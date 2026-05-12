#include "stats.h"

#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>

static double elapsed_seconds_between(const struct timeval *start, const struct timeval *end)
{
    double seconds = (double)(end->tv_sec - start->tv_sec);
    seconds += (double)(end->tv_usec - start->tv_usec) / 1000000.0;
    return seconds > 0.0 ? seconds : 0.001;
}

static void top_counter_add(ids_top_counter_t *items, const char *key, uint64_t delta)
{
    size_t i;
    size_t lowest = 0;

    if (key == NULL || key[0] == '\0') {
        return;
    }

    for (i = 0; i < IDS_STATS_TOP_ITEMS; i++) {
        if (items[i].key[0] == '\0') {
            ids_copy_string(items[i].key, sizeof(items[i].key), key);
            items[i].value = delta;
            return;
        }
        if (strcmp(items[i].key, key) == 0) {
            items[i].value += delta;
            return;
        }
        if (items[i].value < items[lowest].value) {
            lowest = i;
        }
    }

    if (delta > items[lowest].value) {
        ids_copy_string(items[lowest].key, sizeof(items[lowest].key), key);
        items[lowest].value = delta;
    }
}

int ids_stats_init(ids_stats_t *stats)
{
    if (stats == NULL) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    gettimeofday(&stats->started_at, NULL);
    return pthread_mutex_init(&stats->lock, NULL);
}

void ids_stats_destroy(ids_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_destroy(&stats->lock);
}

void ids_stats_record_capture(ids_stats_t *stats, uint32_t bytes)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->captured_packets++;
    stats->bytes_seen += bytes;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_parse(ids_stats_t *stats, const packet_info_t *packet)
{
    char port_key[16];

    if (stats == NULL || packet == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->parsed_packets++;
    if (packet->protocol >= 0 && packet->protocol < PACKET_PROTO_COUNT) {
        stats->protocols[packet->protocol]++;
    }
    top_counter_add(stats->top_sources, packet->src_ip, 1);
    if (packet->dst_port != 0) {
        snprintf(port_key, sizeof(port_key), "%u", packet->dst_port);
        top_counter_add(stats->top_ports, port_key, 1);
    }
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_parse_error(ids_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->parse_errors++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_drop(ids_stats_t *stats, uint64_t count)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->dropped_packets += count;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_logged(ids_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->logged_packets++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_parse_time(ids_stats_t *stats, uint64_t nanoseconds)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->parse_time_ns += nanoseconds;
    stats->parsed_timed_packets++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_detection_time(ids_stats_t *stats, uint64_t nanoseconds)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->detection_time_ns += nanoseconds;
    stats->detected_timed_packets++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_logging_time(ids_stats_t *stats, uint64_t nanoseconds)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->logging_time_ns += nanoseconds;
    stats->logged_timed_events++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_alert(ids_stats_t *stats, const alert_t *alert)
{
    if (stats == NULL || alert == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->alert_count++;
    if (alert->severity >= 0 && alert->severity < IDS_SEVERITY_COUNT) {
        stats->alerts_by_severity[alert->severity]++;
    }
    if (alert->type >= 0 && alert->type < ALERT_TYPE_COUNT) {
        stats->alerts_by_type[alert->type]++;
    }
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_set_queues(ids_stats_t *stats,
                          size_t packet_queue_depth,
                          size_t parsed_queue_depth,
                          size_t log_queue_depth,
                          uint64_t queue_drops)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->packet_queue_depth = packet_queue_depth;
    stats->parsed_queue_depth = parsed_queue_depth;
    stats->log_queue_depth = log_queue_depth;
    stats->queue_drops = queue_drops;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_snapshot(ids_stats_t *stats, ids_stats_snapshot_t *snapshot)
{
    struct timeval now;
    struct rusage usage;
    double uptime;

    if (stats == NULL || snapshot == NULL) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    gettimeofday(&now, NULL);

    pthread_mutex_lock(&stats->lock);
    *snapshot = (ids_stats_snapshot_t){
        .captured_packets = stats->captured_packets,
        .parsed_packets = stats->parsed_packets,
        .parse_errors = stats->parse_errors,
        .dropped_packets = stats->dropped_packets,
        .logged_packets = stats->logged_packets,
        .alert_count = stats->alert_count,
        .bytes_seen = stats->bytes_seen,
        .packet_queue_depth = stats->packet_queue_depth,
        .parsed_queue_depth = stats->parsed_queue_depth,
        .log_queue_depth = stats->log_queue_depth,
        .queue_drops = stats->queue_drops
    };
    if (stats->parsed_timed_packets > 0) {
        snapshot->avg_parse_us = ((double)stats->parse_time_ns / (double)stats->parsed_timed_packets) / 1000.0;
    }
    if (stats->detected_timed_packets > 0) {
        snapshot->avg_detection_us = ((double)stats->detection_time_ns / (double)stats->detected_timed_packets) / 1000.0;
    }
    if (stats->logged_timed_events > 0) {
        snapshot->avg_logging_us = ((double)stats->logging_time_ns / (double)stats->logged_timed_events) / 1000.0;
    }
    memcpy(snapshot->alerts_by_severity, stats->alerts_by_severity, sizeof(snapshot->alerts_by_severity));
    memcpy(snapshot->protocols, stats->protocols, sizeof(snapshot->protocols));
    memcpy(snapshot->alerts_by_type, stats->alerts_by_type, sizeof(snapshot->alerts_by_type));
    memcpy(snapshot->top_sources, stats->top_sources, sizeof(snapshot->top_sources));
    memcpy(snapshot->top_ports, stats->top_ports, sizeof(snapshot->top_ports));
    uptime = elapsed_seconds_between(&stats->started_at, &now);
    pthread_mutex_unlock(&stats->lock);

    snapshot->uptime_seconds = uptime;
    snapshot->packets_per_second = (double)snapshot->parsed_packets / uptime;
    snapshot->mbps = ((double)snapshot->bytes_seen * 8.0) / (uptime * 1000000.0);
    snapshot->alerts_per_minute = ((double)snapshot->alert_count * 60.0) / uptime;
    snapshot->queue_pressure = (double)(snapshot->packet_queue_depth +
                                        snapshot->parsed_queue_depth +
                                        snapshot->log_queue_depth);

    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        snapshot->cpu_seconds = (double)usage.ru_utime.tv_sec + ((double)usage.ru_utime.tv_usec / 1000000.0);
        snapshot->cpu_seconds += (double)usage.ru_stime.tv_sec + ((double)usage.ru_stime.tv_usec / 1000000.0);
        snapshot->memory_kb = usage.ru_maxrss;
    }
}
