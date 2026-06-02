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
    size_t lowest;

    if (key == NULL || key[0] == '\0') {
        return;
    }

    /*
     * Find the true minimum-value slot before scanning for the key.
     * Starting `lowest` at 0 was wrong: if items[0] holds the maximum value,
     * the loop never updates `lowest` and we evict the most-seen entry.
     */
    lowest = 0;
    for (i = 1; i < IDS_STATS_TOP_ITEMS; i++) {
        if (items[i].key[0] == '\0') {
            lowest = i;
            break;
        }
        if (items[i].value < items[lowest].value) {
            lowest = i;
        }
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
    if (packet->ip_version == 4U) {
        stats->ipv4_packets++;
    } else if (packet->ip_version == 6U) {
        stats->ipv6_packets++;
    }
    if (packet->protocol == PACKET_PROTO_ARP) {
        stats->arp_packets++;
    }
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
    stats->malformed_packets++;
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

void ids_stats_record_alert_drop(ids_stats_t *stats, uint64_t count)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->dropped_alerts += count;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_storage_write(ids_stats_t *stats, uint64_t count)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->storage_writes += count;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_storage_error(ids_stats_t *stats, uint64_t count)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->storage_errors += count;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_storage_retry(ids_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->storage_retries++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_storage_time(ids_stats_t *stats, uint64_t nanoseconds)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->storage_time_ns += nanoseconds;
    stats->storage_timed_writes++;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_record_heartbeat(ids_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->heartbeat_total++;
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

void ids_stats_record_correlation_time(ids_stats_t *stats, uint64_t nanoseconds)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->correlation_time_ns += nanoseconds;
    stats->correlated_timed_packets++;
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

void ids_stats_set_detection_shards(ids_stats_t *stats, uint64_t shard_count)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->detection_shards = shard_count;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_set_detection_runtime(ids_stats_t *stats,
                                     double shard_pressure,
                                     uint64_t plugin_count,
                                     uint64_t plugin_packets,
                                     uint64_t plugin_alerts,
                                     uint64_t plugin_errors,
                                     uint64_t plugin_latency_ns)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->shard_pressure = shard_pressure;
    stats->plugin_count = plugin_count;
    stats->plugin_packets = plugin_packets;
    stats->plugin_alerts = plugin_alerts;
    stats->plugin_errors = plugin_errors;
    stats->plugin_latency_ns = plugin_latency_ns;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_set_detection_state(ids_stats_t *stats,
                                   uint64_t shard_evictions,
                                   size_t source_memory_bytes)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->shard_evictions = shard_evictions;
    stats->source_memory_bytes = source_memory_bytes;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_set_event_bus(ids_stats_t *stats,
                             uint64_t published,
                             uint64_t dispatched,
                             uint64_t dropped,
                             size_t queue_depth,
                             size_t queue_capacity)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->event_published = published;
    stats->event_dispatched = dispatched;
    stats->event_dropped = dropped;
    stats->event_queue_depth = queue_depth;
    stats->event_queue_capacity = queue_capacity;
    pthread_mutex_unlock(&stats->lock);
}

void ids_stats_set_memory_pool(ids_stats_t *stats,
                               size_t pool_available,
                               size_t pool_capacity,
                               uint64_t failed_acquires,
                               uint64_t invalid_releases)
{
    if (stats == NULL) {
        return;
    }

    pthread_mutex_lock(&stats->lock);
    stats->pool_available = pool_available;
    stats->pool_capacity = pool_capacity;
    stats->pool_failed_acquires = failed_acquires;
    stats->pool_invalid_releases = invalid_releases;
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
        .dropped_alerts = stats->dropped_alerts,
        .bytes_seen = stats->bytes_seen,
        .ipv4_packets = stats->ipv4_packets,
        .ipv6_packets = stats->ipv6_packets,
        .arp_packets = stats->arp_packets,
        .malformed_packets = stats->malformed_packets,
        .detection_shards = stats->detection_shards,
        .plugin_count = stats->plugin_count,
        .plugin_packets = stats->plugin_packets,
        .plugin_alerts = stats->plugin_alerts,
        .plugin_errors = stats->plugin_errors,
        .storage_writes = stats->storage_writes,
        .storage_errors = stats->storage_errors,
        .storage_retries = stats->storage_retries,
        .heartbeat_total = stats->heartbeat_total,
        .event_published = stats->event_published,
        .event_dispatched = stats->event_dispatched,
        .event_dropped = stats->event_dropped,
        .event_queue_depth = stats->event_queue_depth,
        .event_queue_capacity = stats->event_queue_capacity,
        .packet_queue_depth = stats->packet_queue_depth,
        .parsed_queue_depth = stats->parsed_queue_depth,
        .log_queue_depth = stats->log_queue_depth,
        .queue_drops = stats->queue_drops,
        .shard_pressure = stats->shard_pressure,
        .shard_evictions = stats->shard_evictions,
        .source_memory_bytes = stats->source_memory_bytes,
        .pool_available = stats->pool_available,
        .pool_capacity = stats->pool_capacity,
        .pool_failed_acquires = stats->pool_failed_acquires,
        .pool_invalid_releases = stats->pool_invalid_releases
    };
    if (stats->parsed_timed_packets > 0) {
        snapshot->avg_parse_us = ((double)stats->parse_time_ns / (double)stats->parsed_timed_packets) / 1000.0;
    }
    if (stats->detected_timed_packets > 0) {
        snapshot->avg_detection_us = ((double)stats->detection_time_ns / (double)stats->detected_timed_packets) / 1000.0;
    }
    if (stats->correlated_timed_packets > 0) {
        snapshot->avg_correlation_us = ((double)stats->correlation_time_ns / (double)stats->correlated_timed_packets) / 1000.0;
    }
    if (stats->logged_timed_events > 0) {
        snapshot->avg_logging_us = ((double)stats->logging_time_ns / (double)stats->logged_timed_events) / 1000.0;
    }
    if (stats->storage_timed_writes > 0) {
        snapshot->avg_storage_write_us = ((double)stats->storage_time_ns / (double)stats->storage_timed_writes) / 1000.0;
    }
    if (stats->plugin_packets > 0) {
        snapshot->avg_plugin_latency_us = ((double)stats->plugin_latency_ns / (double)stats->plugin_packets) / 1000.0;
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
    if (snapshot->pool_capacity > 0) {
        snapshot->memory_pool_utilization =
            (double)(snapshot->pool_capacity - snapshot->pool_available) /
            (double)snapshot->pool_capacity;
    }
    if (snapshot->parsed_packets > 0) {
        snapshot->ipv6_ratio = (double)snapshot->ipv6_packets / (double)snapshot->parsed_packets;
    }

    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        snapshot->cpu_seconds = (double)usage.ru_utime.tv_sec + ((double)usage.ru_utime.tv_usec / 1000000.0);
        snapshot->cpu_seconds += (double)usage.ru_stime.tv_sec + ((double)usage.ru_stime.tv_usec / 1000000.0);
        snapshot->memory_kb = usage.ru_maxrss;
    }
}
