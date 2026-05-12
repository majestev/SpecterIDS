#include "capture.h"

#include "config.h"
#include "correlation.h"
#include "pool.h"
#include "queue.h"

#if defined(__has_include)
#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#elif __has_include(<pcap.h>)
#include <pcap.h>
#else
#include <pcap.h>
#endif
#else
#include <pcap.h>
#endif

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define PACKETS_PER_DISPATCH 128

typedef struct {
    packet_header_t header;
    size_t data_len;
    unsigned char data[SPECTERIDS_MAX_PACKET_BYTES];
} raw_packet_t;

typedef struct {
    packet_info_t info;
    raw_packet_t *raw;
} parsed_packet_t;

typedef struct {
    parsed_packet_t *parsed;
    alert_t alerts[SPECTERIDS_MAX_ALERTS_PER_PACKET];
    size_t alert_count;
} log_event_t;

typedef struct {
    const capture_options_t *options;
    detection_engine_t *engine;
    logger_t *logger;
    dashboard_t *dashboard;
    ids_stats_t *stats;
    volatile sig_atomic_t *stop_requested;
    ids_queue_t raw_queue;
    ids_queue_t parsed_queue;
    ids_queue_t log_queue;
    ids_pool_t raw_pool;
    ids_pool_t parsed_pool;
    ids_pool_t log_pool;
    correlation_engine_t correlation;
    bool correlation_initialized;
    int capture_status;
} pipeline_t;

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void publish_event(pipeline_t *pipeline,
                          ids_event_type_t type,
                          const packet_info_t *packet,
                          const alert_t *alert,
                          size_t alert_count,
                          const char *message)
{
    ids_event_t event;
    struct timeval now;

    if (pipeline == NULL || pipeline->options == NULL || pipeline->options->event_bus == NULL) {
        return;
    }

    gettimeofday(&now, NULL);
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.packet = packet;
    event.alert = alert;
    event.alert_count = alert_count;
    event.message = message;
    event.timestamp = now;
    ids_event_bus_publish(pipeline->options->event_bus, &event);
}

static void release_raw(pipeline_t *pipeline, raw_packet_t *raw)
{
    ids_pool_release(&pipeline->raw_pool, raw);
}

static void release_parsed(pipeline_t *pipeline, parsed_packet_t *parsed)
{
    if (parsed == NULL) {
        return;
    }
    if (parsed->raw != NULL) {
        release_raw(pipeline, parsed->raw);
        parsed->raw = NULL;
    }
    ids_pool_release(&pipeline->parsed_pool, parsed);
}

static void release_log_event(pipeline_t *pipeline, log_event_t *event)
{
    if (event == NULL) {
        return;
    }
    release_parsed(pipeline, event->parsed);
    event->parsed = NULL;
    ids_pool_release(&pipeline->log_pool, event);
}

static void update_queue_stats(pipeline_t *pipeline)
{
    uint64_t drops;

    if (pipeline == NULL || pipeline->stats == NULL) {
        return;
    }

    drops = ids_queue_dropped(&pipeline->raw_queue);
    drops += ids_queue_dropped(&pipeline->parsed_queue);
    drops += ids_queue_dropped(&pipeline->log_queue);
    ids_stats_set_queues(pipeline->stats,
                         ids_queue_size(&pipeline->raw_queue),
                         ids_queue_size(&pipeline->parsed_queue),
                         ids_queue_size(&pipeline->log_queue),
                         drops);
}

static int install_bpf_filter(pcap_t *handle,
                              const char *interface_name,
                              const char *filter_expression)
{
    struct bpf_program program;
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (filter_expression == NULL || filter_expression[0] == '\0') {
        return 0;
    }

    memset(errbuf, 0, sizeof(errbuf));
    if (pcap_lookupnet(interface_name, &net, &mask, errbuf) == PCAP_ERROR) {
        net = 0;
        mask = 0;
    }
    (void)net;

    if (pcap_compile(handle, &program, filter_expression, 1, mask) == PCAP_ERROR) {
        fprintf(stderr, "Failed to compile BPF filter '%s': %s\n", filter_expression, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &program) == PCAP_ERROR) {
        fprintf(stderr, "Failed to install BPF filter '%s': %s\n", filter_expression, pcap_geterr(handle));
        pcap_freecode(&program);
        return -1;
    }

    pcap_freecode(&program);
    return 0;
}

static void capture_packet_callback(unsigned char *user,
                                    const struct pcap_pkthdr *header,
                                    const unsigned char *packet)
{
    pipeline_t *pipeline = (pipeline_t *)user;
    raw_packet_t *raw;
    size_t copy_len;

    if (pipeline == NULL || header == NULL || packet == NULL) {
        return;
    }

    raw = ids_pool_try_acquire(&pipeline->raw_pool);
    if (raw == NULL) {
        ids_stats_record_drop(pipeline->stats, 1);
        return;
    }

    copy_len = header->caplen;
    if (copy_len > sizeof(raw->data)) {
        copy_len = sizeof(raw->data);
    }

    raw->header.length = header->len;
    raw->header.captured_length = (uint32_t)copy_len;
    raw->header.timestamp = header->ts;
    raw->data_len = copy_len;
    memcpy(raw->data, packet, copy_len);

    ids_stats_record_capture(pipeline->stats, header->len);
    publish_event(pipeline, IDS_EVENT_PACKET_CAPTURED, NULL, NULL, 0, NULL);

    if (!ids_queue_try_push(&pipeline->raw_queue, raw)) {
        release_raw(pipeline, raw);
        ids_stats_record_drop(pipeline->stats, 1);
    }
}

static void maybe_reload_rules(pipeline_t *pipeline)
{
    app_config_t reloaded_config;
    ids_rules_t rules;
    const char *rules_file;

    if (pipeline == NULL || pipeline->options == NULL ||
        pipeline->options->reload_requested == NULL ||
        !*pipeline->options->reload_requested) {
        return;
    }

    *pipeline->options->reload_requested = 0;
    rules_file = pipeline->options->rules_file;
    if (pipeline->options->config_file != NULL && pipeline->options->config_file[0] != '\0') {
        config_set_defaults(&reloaded_config);
        if (config_load_file(&reloaded_config, pipeline->options->config_file) == 0) {
            detection_set_sensitive_ports(pipeline->engine,
                                          reloaded_config.sensitive_ports,
                                          reloaded_config.sensitive_port_count);
            rules_file = reloaded_config.rules_file;
            logger_log_status(pipeline->logger, "INFO", "config subset reloaded after SIGHUP");
        } else {
            logger_log_status(pipeline->logger, "WARN", "config reload failed; keeping previous runtime config");
        }
    }

    if (rules_file == NULL || rules_file[0] == '\0') {
        logger_log_status(pipeline->logger, "WARN", "SIGHUP received but no rules file is configured");
        return;
    }

    rules_set_defaults(&rules);
    if (rules_load_file(&rules, rules_file) == 0) {
        detection_update_rules(pipeline->engine, &rules);
        logger_log_status(pipeline->logger, "INFO", "rules reloaded after SIGHUP");
        publish_event(pipeline, IDS_EVENT_RELOAD, NULL, NULL, 0, "rules reloaded");
    } else {
        logger_log_status(pipeline->logger, "WARN", "rules reload failed; keeping previous rules");
    }
}

static void *capture_thread_main(void *arg)
{
    pipeline_t *pipeline = (pipeline_t *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int link_type;

    memset(errbuf, 0, sizeof(errbuf));
    handle = pcap_open_live(pipeline->options->interface_name,
                            pipeline->options->snaplen,
                            pipeline->options->promiscuous,
                            pipeline->options->timeout_ms,
                            errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface '%s': %s\n", pipeline->options->interface_name, errbuf);
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }

    link_type = pcap_datalink(handle);
    if (link_type != DLT_EN10MB) {
        fprintf(stderr,
                "Unsupported datalink type %d on '%s'. SpecterIDS currently supports Ethernet (DLT_EN10MB).\n",
                link_type,
                pipeline->options->interface_name);
        pcap_close(handle);
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }

    if (install_bpf_filter(handle,
                           pipeline->options->interface_name,
                           pipeline->options->bpf_filter) != 0) {
        pcap_close(handle);
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }

    if (!pipeline->options->quiet) {
        printf("Capture thread started on %s", pipeline->options->interface_name);
        if (pipeline->options->bpf_filter != NULL && pipeline->options->bpf_filter[0] != '\0') {
            printf(" with BPF '%s'", pipeline->options->bpf_filter);
        }
        printf(". Press Ctrl+C to stop.\n");
    }

    while (!*pipeline->stop_requested) {
        int rc = pcap_dispatch(handle, PACKETS_PER_DISPATCH, capture_packet_callback, (unsigned char *)pipeline);

        if (rc == PCAP_ERROR_BREAK) {
            break;
        }
        if (rc == PCAP_ERROR) {
            fprintf(stderr, "pcap_dispatch failed: %s\n", pcap_geterr(handle));
            pipeline->capture_status = -1;
            break;
        }
        update_queue_stats(pipeline);
        dashboard_render_stats(pipeline->dashboard, pipeline->stats, false);
        maybe_reload_rules(pipeline);
    }

    pcap_close(handle);
    ids_queue_close(&pipeline->raw_queue);
    return NULL;
}

static void *parser_worker_main(void *arg)
{
    pipeline_t *pipeline = (pipeline_t *)arg;
    void *item = NULL;

    while (ids_queue_pop(&pipeline->raw_queue, &item)) {
        raw_packet_t *raw = (raw_packet_t *)item;
        parsed_packet_t *parsed = ids_pool_acquire(&pipeline->parsed_pool);
        char parse_error[128];
        uint64_t started = monotonic_ns();

        if (parsed == NULL) {
            release_raw(pipeline, raw);
            ids_stats_record_drop(pipeline->stats, 1);
            continue;
        }

        if (!parser_parse_packet(&raw->header, raw->data, &parsed->info, parse_error, sizeof(parse_error))) {
            ids_stats_record_parse_error(pipeline->stats);
            release_raw(pipeline, raw);
            ids_pool_release(&pipeline->parsed_pool, parsed);
            continue;
        }

        ids_stats_record_parse_time(pipeline->stats, monotonic_ns() - started);
        parsed->raw = raw;
        ids_stats_record_parse(pipeline->stats, &parsed->info);
        publish_event(pipeline, IDS_EVENT_PACKET_PARSED, &parsed->info, NULL, 0, NULL);
        if (!ids_queue_push(&pipeline->parsed_queue, parsed)) {
            release_parsed(pipeline, parsed);
            ids_stats_record_drop(pipeline->stats, 1);
        }
    }

    return NULL;
}

static void *detection_worker_main(void *arg)
{
    pipeline_t *pipeline = (pipeline_t *)arg;
    void *item = NULL;

    while (ids_queue_pop(&pipeline->parsed_queue, &item)) {
        parsed_packet_t *parsed = (parsed_packet_t *)item;
        log_event_t *event = ids_pool_acquire(&pipeline->log_pool);
        size_t i;
        uint64_t started = monotonic_ns();

        if (event == NULL) {
            release_parsed(pipeline, parsed);
            ids_stats_record_drop(pipeline->stats, 1);
            continue;
        }

        event->parsed = parsed;
        event->alert_count = detection_process_packet(pipeline->engine,
                                                      &parsed->info,
                                                      event->alerts,
                                                      SPECTERIDS_MAX_ALERTS_PER_PACKET);
        if (event->alert_count < SPECTERIDS_MAX_ALERTS_PER_PACKET && pipeline->correlation_initialized) {
            event->alert_count += correlation_process_alerts(&pipeline->correlation,
                                                            event->alerts,
                                                            event->alert_count,
                                                            event->alerts + event->alert_count,
                                                            SPECTERIDS_MAX_ALERTS_PER_PACKET - event->alert_count);
        }
        ids_stats_record_detection_time(pipeline->stats, monotonic_ns() - started);
        publish_event(pipeline, IDS_EVENT_DETECTION_COMPLETE, &parsed->info, NULL, event->alert_count, NULL);
        for (i = 0; i < event->alert_count; i++) {
            ids_stats_record_alert(pipeline->stats, &event->alerts[i]);
            dashboard_record_alert(pipeline->dashboard, &event->alerts[i]);
            publish_event(pipeline, IDS_EVENT_ALERT, &parsed->info, &event->alerts[i], 1, NULL);
        }
        dashboard_record_packet(pipeline->dashboard, &parsed->info);

        if (!ids_queue_push(&pipeline->log_queue, event)) {
            release_log_event(pipeline, event);
            ids_stats_record_drop(pipeline->stats, 1);
        }
        update_queue_stats(pipeline);
    }

    return NULL;
}

static void *logger_thread_main(void *arg)
{
    pipeline_t *pipeline = (pipeline_t *)arg;
    void *item = NULL;

    while (ids_queue_pop(&pipeline->log_queue, &item)) {
        log_event_t *event = (log_event_t *)item;
        raw_packet_t *raw = event->parsed->raw;
        uint64_t started = monotonic_ns();

        (void)logger_log_packet_raw(pipeline->logger,
                                    &event->parsed->info,
                                    &raw->header,
                                    raw->data,
                                    raw->data_len);
        if (event->alert_count > 0) {
            (void)logger_log_alerts(pipeline->logger,
                                    event->alerts,
                                    event->alert_count,
                                    &raw->header,
                                    raw->data,
                                    raw->data_len);
        }
        ids_stats_record_logged(pipeline->stats);
        ids_stats_record_logging_time(pipeline->stats, monotonic_ns() - started);
        publish_event(pipeline, IDS_EVENT_OUTPUT_WRITTEN, &event->parsed->info, NULL, event->alert_count, NULL);
        release_log_event(pipeline, event);
        update_queue_stats(pipeline);
    }

    return NULL;
}

static int pipeline_init(pipeline_t *pipeline,
                         const capture_options_t *options,
                         detection_engine_t *engine,
                         logger_t *logger,
                         dashboard_t *dashboard,
                         ids_stats_t *stats,
                         volatile sig_atomic_t *stop_requested)
{
    size_t queue_size = options->queue_size > 0 ? options->queue_size : SPECTERIDS_DEFAULT_QUEUE_SIZE;

    memset(pipeline, 0, sizeof(*pipeline));
    pipeline->options = options;
    pipeline->engine = engine;
    pipeline->logger = logger;
    pipeline->dashboard = dashboard;
    pipeline->stats = stats;
    pipeline->stop_requested = stop_requested;

    if (ids_queue_init(&pipeline->raw_queue, queue_size) != 0 ||
        ids_queue_init(&pipeline->parsed_queue, queue_size) != 0 ||
        ids_queue_init(&pipeline->log_queue, queue_size) != 0 ||
        ids_pool_init(&pipeline->raw_pool, queue_size, sizeof(raw_packet_t)) != 0 ||
        ids_pool_init(&pipeline->parsed_pool, queue_size, sizeof(parsed_packet_t)) != 0 ||
        ids_pool_init(&pipeline->log_pool, queue_size, sizeof(log_event_t)) != 0) {
        return -1;
    }

    if (correlation_init(&pipeline->correlation, 300) == 0) {
        pipeline->correlation_initialized = true;
    }

    return 0;
}

static void pipeline_destroy(pipeline_t *pipeline)
{
    if (pipeline->correlation_initialized) {
        correlation_destroy(&pipeline->correlation);
    }
    ids_pool_destroy(&pipeline->log_pool);
    ids_pool_destroy(&pipeline->parsed_pool);
    ids_pool_destroy(&pipeline->raw_pool);
    ids_queue_destroy(&pipeline->log_queue);
    ids_queue_destroy(&pipeline->parsed_queue);
    ids_queue_destroy(&pipeline->raw_queue);
}

int capture_run(const capture_options_t *options,
                detection_engine_t *engine,
                logger_t *logger,
                dashboard_t *dashboard,
                ids_stats_t *stats,
                volatile sig_atomic_t *stop_requested)
{
    pipeline_t pipeline;
    pthread_t capture_thread;
    pthread_t logger_thread;
    pthread_t *parser_threads = NULL;
    pthread_t *detection_threads = NULL;
    int parser_workers;
    int detection_workers;
    int parser_created = 0;
    int detection_created = 0;
    bool logger_created = false;
    bool capture_created = false;
    int status = -1;
    int i;

    if (options == NULL || options->interface_name == NULL ||
        engine == NULL || logger == NULL || dashboard == NULL ||
        stats == NULL || stop_requested == NULL) {
        fprintf(stderr, "Invalid capture configuration\n");
        return -1;
    }

    parser_workers = options->parser_workers > 0 ? options->parser_workers : SPECTERIDS_DEFAULT_WORKERS;
    detection_workers = options->detection_workers > 0 ? options->detection_workers : SPECTERIDS_DEFAULT_WORKERS;

    parser_threads = calloc((size_t)parser_workers, sizeof(*parser_threads));
    detection_threads = calloc((size_t)detection_workers, sizeof(*detection_threads));
    if (parser_threads == NULL || detection_threads == NULL) {
        free(parser_threads);
        free(detection_threads);
        return -1;
    }

    if (pipeline_init(&pipeline, options, engine, logger, dashboard, stats, stop_requested) != 0) {
        free(parser_threads);
        free(detection_threads);
        fprintf(stderr, "Failed to initialize capture pipeline\n");
        return -1;
    }

    logger_log_status(logger, "INFO", "threaded pipeline starting");

    if (pthread_create(&logger_thread, NULL, logger_thread_main, &pipeline) != 0) {
        ids_queue_close(&pipeline.raw_queue);
        ids_queue_close(&pipeline.parsed_queue);
        ids_queue_close(&pipeline.log_queue);
        pipeline_destroy(&pipeline);
        free(parser_threads);
        free(detection_threads);
        return -1;
    }
    logger_created = true;

    if (pthread_create(&capture_thread, NULL, capture_thread_main, &pipeline) != 0) {
        ids_queue_close(&pipeline.raw_queue);
        ids_queue_close(&pipeline.parsed_queue);
        ids_queue_close(&pipeline.log_queue);
        if (logger_created) {
            pthread_join(logger_thread, NULL);
        }
        pipeline_destroy(&pipeline);
        free(parser_threads);
        free(detection_threads);
        return -1;
    }
    capture_created = true;

    for (i = 0; i < parser_workers; i++) {
        if (pthread_create(&parser_threads[i], NULL, parser_worker_main, &pipeline) != 0) {
            *stop_requested = 1;
        } else {
            parser_created++;
        }
    }

    for (i = 0; i < detection_workers; i++) {
        if (pthread_create(&detection_threads[i], NULL, detection_worker_main, &pipeline) != 0) {
            *stop_requested = 1;
        } else {
            detection_created++;
        }
    }

    if (capture_created) {
        pthread_join(capture_thread, NULL);
    }
    for (i = 0; i < parser_created; i++) {
        pthread_join(parser_threads[i], NULL);
    }
    ids_queue_close(&pipeline.parsed_queue);

    for (i = 0; i < detection_created; i++) {
        pthread_join(detection_threads[i], NULL);
    }
    ids_queue_close(&pipeline.log_queue);

    pthread_join(logger_thread, NULL);

    update_queue_stats(&pipeline);
    status = pipeline.capture_status;
    logger_log_status(logger, "INFO", "threaded pipeline stopped");

    pipeline_destroy(&pipeline);
    free(parser_threads);
    free(detection_threads);
    return status;
}
