#include "capture.h"

#include "config.h"
#include "correlation.h"
#include "datalink.h"
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
#define PIPELINE_QUEUE_TIMEOUT_MS 250U
#define PIPELINE_POOL_TIMEOUT_MS 250U
#define PIPELINE_HEARTBEAT_SECONDS 5
#define REPLAY_SLEEP_SLICE_NS 100000000ULL /* 100 ms: re-check stop between slices */

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
    int datalink_type;
    int capture_status;
    time_t last_watchdog_warning;
    time_t last_heartbeat_at;
} pipeline_t;

/* ids_monotonic_ns() is provided by common.h */
static uint64_t monotonic_ns(void)
{
    return ids_monotonic_ns();
}

static uint64_t timeval_to_ns(const struct timeval *timestamp)
{
    uint64_t usec;

    /*
     * Timestamps come from a PCAP file (untrusted in offline mode). A corrupt
     * or crafted record can carry negative or out-of-range fields; casting
     * those straight to uint64_t would yield a huge bogus value. Reject
     * negatives and clamp tv_usec below one second.
     */
    if (timestamp == NULL || timestamp->tv_sec < 0 || timestamp->tv_usec < 0) {
        return 0;
    }

    usec = (uint64_t)timestamp->tv_usec;
    if (usec >= 1000000ULL) {
        usec = 999999ULL;
    }

    return ((uint64_t)timestamp->tv_sec * 1000000000ULL) + (usec * 1000ULL);
}

/*
 * Sleep until target_ns (CLOCK_MONOTONIC), waking at least every
 * REPLAY_SLEEP_SLICE_NS to re-check stop_requested. Without the periodic
 * check, a large inter-packet gap in a replayed PCAP — or a crafted future
 * timestamp — would pin the capture thread in nanosleep and make the process
 * ignore SIGINT/SIGTERM until the whole gap elapsed.
 */
static void sleep_until_ns(uint64_t target_ns, volatile sig_atomic_t *stop_requested)
{
    uint64_t now;

    while ((stop_requested == NULL || !*stop_requested) &&
           (now = monotonic_ns()) < target_ns) {
        uint64_t remaining = target_ns - now;
        struct timespec request;

        if (remaining > REPLAY_SLEEP_SLICE_NS) {
            remaining = REPLAY_SLEEP_SLICE_NS;
        }
        request.tv_sec = (time_t)(remaining / 1000000000ULL);
        request.tv_nsec = (long)(remaining % 1000000000ULL);
        if (nanosleep(&request, NULL) != 0 && errno != EINTR) {
            return;
        }
    }
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
    size_t raw_depth;
    size_t parsed_depth;
    size_t log_depth;
    size_t total_depth;
    size_t total_capacity;
    time_t now;

    if (pipeline == NULL || pipeline->stats == NULL) {
        return;
    }

    raw_depth = ids_queue_size(&pipeline->raw_queue);
    parsed_depth = ids_queue_size(&pipeline->parsed_queue);
    log_depth = ids_queue_size(&pipeline->log_queue);
    drops = ids_queue_dropped(&pipeline->raw_queue);
    drops += ids_queue_dropped(&pipeline->parsed_queue);
    drops += ids_queue_dropped(&pipeline->log_queue);
    ids_stats_set_queues(pipeline->stats,
                         raw_depth,
                         parsed_depth,
                         log_depth,
                         drops);
    if (pipeline->options != NULL && pipeline->options->event_bus != NULL) {
        ids_event_bus_snapshot_t event_snapshot;

        ids_event_bus_snapshot(pipeline->options->event_bus, &event_snapshot);
        ids_stats_set_event_bus(pipeline->stats,
                                event_snapshot.published_events,
                                event_snapshot.dispatched_events,
                                event_snapshot.dropped_events,
                                event_snapshot.queue_depth,
                                event_snapshot.queue_capacity);
    }
    ids_stats_set_memory_pool(pipeline->stats,
                              ids_pool_available(&pipeline->raw_pool) +
                                  ids_pool_available(&pipeline->parsed_pool) +
                                  ids_pool_available(&pipeline->log_pool),
                              ids_pool_capacity(&pipeline->raw_pool) +
                                  ids_pool_capacity(&pipeline->parsed_pool) +
                                  ids_pool_capacity(&pipeline->log_pool),
                              ids_pool_failed_acquires(&pipeline->raw_pool) +
                                  ids_pool_failed_acquires(&pipeline->parsed_pool) +
                                  ids_pool_failed_acquires(&pipeline->log_pool),
                              ids_pool_invalid_releases(&pipeline->raw_pool) +
                                  ids_pool_invalid_releases(&pipeline->parsed_pool) +
                                  ids_pool_invalid_releases(&pipeline->log_pool));

    total_depth = raw_depth + parsed_depth + log_depth;
    total_capacity = pipeline->raw_queue.capacity + pipeline->parsed_queue.capacity + pipeline->log_queue.capacity;
    now = time(NULL);
    if (now - pipeline->last_heartbeat_at >= PIPELINE_HEARTBEAT_SECONDS) {
        ids_stats_record_heartbeat(pipeline->stats);
        publish_event(pipeline, IDS_EVENT_HEALTH, NULL, NULL, 0, "pipeline heartbeat");
        pipeline->last_heartbeat_at = now;
    }
    if (total_capacity > 0 &&
        total_depth * 100U >= total_capacity * 90U &&
        now - pipeline->last_watchdog_warning >= 5) {
        if (pipeline->logger != NULL) {
            logger_log_status(pipeline->logger, "WARN", "watchdog: queue pressure above 90%; bounded queues may drop packets");
        }
        pipeline->last_watchdog_warning = now;
    }
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
    if (interface_name == NULL ||
        interface_name[0] == '\0' ||
        pcap_lookupnet(interface_name, &net, &mask, errbuf) == PCAP_ERROR) {
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
    raw->header.datalink_type = pipeline->datalink_type;
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
    bool config_reloaded = false;

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
            config_reloaded = true;
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
        if (config_reloaded) {
            rules.beaconing.min_hits = reloaded_config.beaconing_min_hits;
            rules.beaconing.interval_seconds = reloaded_config.beaconing_interval;
            rules.beaconing.tolerance_seconds = reloaded_config.beaconing_tolerance;
            rules.beaconing.ignore_private = reloaded_config.beaconing_ignore_private;
            if (reloaded_config.beaconing_whitelist[0] != '\0') {
                ids_copy_string(rules.beaconing.whitelist,
                                sizeof(rules.beaconing.whitelist),
                                reloaded_config.beaconing_whitelist);
            }
        }
        detection_update_rules(pipeline->engine, &rules);
        logger_log_status(pipeline->logger, "INFO", "rules reloaded after SIGHUP");
        publish_event(pipeline, IDS_EVENT_RELOAD, NULL, NULL, 0, "rules reloaded");
    } else {
        logger_log_status(pipeline->logger, "WARN", "rules reload failed; keeping previous rules");
    }
}

static int dispatch_offline_packets(pcap_t *handle, pipeline_t *pipeline)
{
    const unsigned char *data = NULL;
    struct pcap_pkthdr *header = NULL;
    uint64_t first_pcap_ns = 0;
    uint64_t first_mono_ns = 0;
    bool have_first_timestamp = false;

    while (!*pipeline->stop_requested) {
        int rc = pcap_next_ex(handle, &header, &data);

        if (rc == 1) {
            if (pipeline->options->pcap_replay) {
                uint64_t packet_ns = timeval_to_ns(&header->ts);

                if (!have_first_timestamp) {
                    first_pcap_ns = packet_ns;
                    first_mono_ns = monotonic_ns();
                    have_first_timestamp = true;
                } else if (packet_ns >= first_pcap_ns) {
                    double speed = pipeline->options->pcap_speed > 0.0 ? pipeline->options->pcap_speed : 1.0;
                    uint64_t delta = packet_ns - first_pcap_ns;
                    uint64_t scaled_delta = (uint64_t)((double)delta / speed);

                    sleep_until_ns(first_mono_ns + scaled_delta, pipeline->stop_requested);
                }
            }

            capture_packet_callback((unsigned char *)pipeline, header, data);
            update_queue_stats(pipeline);
            dashboard_render_stats(pipeline->dashboard, pipeline->stats, false);
            maybe_reload_rules(pipeline);
            continue;
        }

        if (rc == PCAP_ERROR_BREAK) {
            return 0;
        }
        if (rc == 0) {
            continue;
        }

        fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}

static void *capture_thread_main(void *arg)
{
    pipeline_t *pipeline = (pipeline_t *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int link_type;

    memset(errbuf, 0, sizeof(errbuf));
    if (pipeline->options->offline) {
        handle = pcap_open_offline(pipeline->options->pcap_file, errbuf);
    } else {
        handle = pcap_open_live(pipeline->options->interface_name,
                                pipeline->options->snaplen,
                                pipeline->options->promiscuous,
                                pipeline->options->timeout_ms,
                                errbuf);
    }
    if (handle == NULL) {
        if (pipeline->options->offline) {
            fprintf(stderr, "Failed to open PCAP '%s': %s\n", pipeline->options->pcap_file, errbuf);
        } else {
            fprintf(stderr, "Failed to open interface '%s': %s\n", pipeline->options->interface_name, errbuf);
        }
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }

    link_type = pcap_datalink(handle);
    if (!datalink_is_supported(link_type)) {
        fprintf(stderr,
                "Unsupported datalink type %d (%s) on '%s'. Supported: Ethernet, Linux cooked, Linux cooked v2, RAW IP.\n",
                link_type,
                datalink_type_name(link_type),
                pipeline->options->offline ? pipeline->options->pcap_file : pipeline->options->interface_name);
        pcap_close(handle);
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }
    pipeline->datalink_type = link_type;

    if (install_bpf_filter(handle,
                           pipeline->options->offline ? NULL : pipeline->options->interface_name,
                           pipeline->options->bpf_filter) != 0) {
        pcap_close(handle);
        pipeline->capture_status = -1;
        ids_queue_close(&pipeline->raw_queue);
        return NULL;
    }

    if (!pipeline->options->quiet) {
        if (pipeline->options->offline) {
            printf("Offline PCAP replay started from %s", pipeline->options->pcap_file);
            if (pipeline->options->pcap_replay) {
                printf(" at %.2fx", pipeline->options->pcap_speed > 0.0 ? pipeline->options->pcap_speed : 1.0);
            }
        } else {
            printf("Capture thread started on %s", pipeline->options->interface_name);
        }
        printf(" using %s", datalink_type_name(link_type));
        if (pipeline->options->bpf_filter != NULL && pipeline->options->bpf_filter[0] != '\0') {
            printf(" with BPF '%s'", pipeline->options->bpf_filter);
        }
        printf("%s\n", pipeline->options->offline ? "." : ". Press Ctrl+C to stop.");
    }

    if (pipeline->options->offline) {
        if (dispatch_offline_packets(handle, pipeline) != 0) {
            pipeline->capture_status = -1;
        }
    } else {
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
        parsed_packet_t *parsed = ids_pool_acquire_timeout(&pipeline->parsed_pool,
                                                           PIPELINE_POOL_TIMEOUT_MS);
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
        publish_event(pipeline, IDS_EVENT_DATALINK_PARSED, &parsed->info, NULL, 0, NULL);
        publish_event(pipeline, IDS_EVENT_NETWORK_PACKET_PARSED, &parsed->info, NULL, 0, NULL);
        publish_event(pipeline, IDS_EVENT_PACKET_PARSED, &parsed->info, NULL, 0, NULL);
        if (!ids_queue_push_timeout(&pipeline->parsed_queue, parsed, PIPELINE_QUEUE_TIMEOUT_MS)) {
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
        log_event_t *event = ids_pool_acquire_timeout(&pipeline->log_pool,
                                                      PIPELINE_POOL_TIMEOUT_MS);
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
        if (event->alert_count >= SPECTERIDS_MAX_ALERTS_PER_PACKET) {
            ids_stats_record_alert_drop(pipeline->stats, 1);
        }
        if (event->alert_count < SPECTERIDS_MAX_ALERTS_PER_PACKET && pipeline->correlation_initialized) {
            size_t before_correlation = event->alert_count;
            uint64_t correlation_started = monotonic_ns();

            event->alert_count += correlation_process_alerts(&pipeline->correlation,
                                                            event->alerts,
                                                            event->alert_count,
                                                            event->alerts + event->alert_count,
                                                            SPECTERIDS_MAX_ALERTS_PER_PACKET - event->alert_count);
            ids_stats_record_correlation_time(pipeline->stats, monotonic_ns() - correlation_started);
            if (event->alert_count > before_correlation) {
                publish_event(pipeline,
                              IDS_EVENT_CORRELATION,
                              &parsed->info,
                              &event->alerts[before_correlation],
                              event->alert_count - before_correlation,
                              NULL);
            }
        }
        ids_stats_record_detection_time(pipeline->stats, monotonic_ns() - started);
        ids_stats_set_detection_runtime(pipeline->stats,
                                        detection_shard_pressure(pipeline->engine),
                                        (uint64_t)detection_plugin_count(pipeline->engine),
                                        detection_plugin_packets(pipeline->engine),
                                        detection_plugin_alerts(pipeline->engine),
                                        detection_plugin_errors(pipeline->engine),
                                        detection_plugin_latency_ns(pipeline->engine));
        ids_stats_set_detection_state(pipeline->stats,
                                      detection_shard_evictions(pipeline->engine),
                                      detection_source_memory_bytes(pipeline->engine));
        publish_event(pipeline, IDS_EVENT_DETECTION_COMPLETE, &parsed->info, NULL, event->alert_count, NULL);
        for (i = 0; i < event->alert_count; i++) {
            ids_stats_record_alert(pipeline->stats, &event->alerts[i]);
            dashboard_record_alert(pipeline->dashboard, &event->alerts[i]);
            publish_event(pipeline, IDS_EVENT_ALERT, &parsed->info, &event->alerts[i], 1, NULL);
        }
        dashboard_record_packet(pipeline->dashboard, &parsed->info);

        if (!ids_queue_push_timeout(&pipeline->log_queue, event, PIPELINE_QUEUE_TIMEOUT_MS)) {
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
    bool raw_queue_initialized = false;
    bool parsed_queue_initialized = false;
    bool log_queue_initialized = false;
    bool raw_pool_initialized = false;
    bool parsed_pool_initialized = false;
    bool log_pool_initialized = false;

    memset(pipeline, 0, sizeof(*pipeline));
    pipeline->options = options;
    pipeline->engine = engine;
    pipeline->logger = logger;
    pipeline->dashboard = dashboard;
    pipeline->stats = stats;
    pipeline->stop_requested = stop_requested;

    if (ids_queue_init(&pipeline->raw_queue, queue_size) != 0) {
        goto fail;
    }
    raw_queue_initialized = true;
    if (ids_queue_init(&pipeline->parsed_queue, queue_size) != 0) {
        goto fail;
    }
    parsed_queue_initialized = true;
    if (ids_queue_init(&pipeline->log_queue, queue_size) != 0) {
        goto fail;
    }
    log_queue_initialized = true;
    if (ids_pool_init(&pipeline->raw_pool, queue_size, sizeof(raw_packet_t)) != 0) {
        goto fail;
    }
    raw_pool_initialized = true;
    if (ids_pool_init(&pipeline->parsed_pool, queue_size, sizeof(parsed_packet_t)) != 0) {
        goto fail;
    }
    parsed_pool_initialized = true;
    if (ids_pool_init(&pipeline->log_pool, queue_size, sizeof(log_event_t)) != 0) {
        goto fail;
    }
    log_pool_initialized = true;

    {
        int corr_window = (options->correlation_window_seconds > 0)
                            ? options->correlation_window_seconds
                            : 300;
        if (correlation_init(&pipeline->correlation, corr_window) == 0) {
            pipeline->correlation_initialized = true;
        }
    }

    return 0;

fail:
    if (log_pool_initialized) {
        ids_pool_destroy(&pipeline->log_pool);
    }
    if (parsed_pool_initialized) {
        ids_pool_destroy(&pipeline->parsed_pool);
    }
    if (raw_pool_initialized) {
        ids_pool_destroy(&pipeline->raw_pool);
    }
    if (log_queue_initialized) {
        ids_queue_destroy(&pipeline->log_queue);
    }
    if (parsed_queue_initialized) {
        ids_queue_destroy(&pipeline->parsed_queue);
    }
    if (raw_queue_initialized) {
        ids_queue_destroy(&pipeline->raw_queue);
    }
    return -1;
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

    if (options == NULL ||
        ((!options->offline && options->interface_name == NULL) ||
         (options->offline && options->pcap_file == NULL)) ||
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
