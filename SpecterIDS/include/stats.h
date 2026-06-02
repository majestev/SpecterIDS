#ifndef SPECTERIDS_STATS_H
#define SPECTERIDS_STATS_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>

#include "common.h"
#include "detection.h"
#include "parser.h"

#define IDS_STATS_TOP_ITEMS 10

typedef struct {
    char key[64];
    uint64_t value;
} ids_top_counter_t;

typedef struct {
    uint64_t captured_packets;
    uint64_t parsed_packets;
    uint64_t parse_errors;
    uint64_t dropped_packets;
    uint64_t logged_packets;
    uint64_t alert_count;
    uint64_t dropped_alerts;
    uint64_t bytes_seen;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t arp_packets;
    uint64_t malformed_packets;
    uint64_t detection_shards;
    uint64_t plugin_count;
    uint64_t plugin_packets;
    uint64_t plugin_alerts;
    uint64_t plugin_errors;
    uint64_t storage_writes;
    uint64_t storage_errors;
    uint64_t storage_retries;
    uint64_t heartbeat_total;
    uint64_t event_published;
    uint64_t event_dispatched;
    uint64_t event_dropped;
    size_t event_queue_depth;
    size_t event_queue_capacity;
    uint64_t alerts_by_severity[IDS_SEVERITY_COUNT];
    uint64_t protocols[PACKET_PROTO_COUNT];
    uint64_t alerts_by_type[ALERT_TYPE_COUNT];
    ids_top_counter_t top_sources[IDS_STATS_TOP_ITEMS];
    ids_top_counter_t top_ports[IDS_STATS_TOP_ITEMS];
    size_t packet_queue_depth;
    size_t parsed_queue_depth;
    size_t log_queue_depth;
    uint64_t queue_drops;
    double uptime_seconds;
    double packets_per_second;
    double mbps;
    double alerts_per_minute;
    double cpu_seconds;
    double avg_parse_us;
    double avg_detection_us;
    double avg_correlation_us;
    double avg_logging_us;
    double avg_storage_write_us;
    double avg_plugin_latency_us;
    double queue_pressure;
    double shard_pressure;
    double ipv6_ratio;
    uint64_t shard_evictions;
    size_t source_memory_bytes;
    double memory_pool_utilization;
    size_t pool_available;
    size_t pool_capacity;
    uint64_t pool_failed_acquires;
    uint64_t pool_invalid_releases;
    long memory_kb;
} ids_stats_snapshot_t;

typedef struct {
    pthread_mutex_t lock;
    struct timeval started_at;
    uint64_t captured_packets;
    uint64_t parsed_packets;
    uint64_t parse_errors;
    uint64_t dropped_packets;
    uint64_t logged_packets;
    uint64_t alert_count;
    uint64_t dropped_alerts;
    uint64_t bytes_seen;
    uint64_t ipv4_packets;
    uint64_t ipv6_packets;
    uint64_t arp_packets;
    uint64_t malformed_packets;
    uint64_t detection_shards;
    uint64_t plugin_count;
    uint64_t plugin_packets;
    uint64_t plugin_alerts;
    uint64_t plugin_errors;
    uint64_t plugin_latency_ns;
    uint64_t storage_writes;
    uint64_t storage_errors;
    uint64_t storage_retries;
    uint64_t storage_time_ns;
    uint64_t storage_timed_writes;
    uint64_t heartbeat_total;
    uint64_t event_published;
    uint64_t event_dispatched;
    uint64_t event_dropped;
    size_t event_queue_depth;
    size_t event_queue_capacity;
    uint64_t parse_time_ns;
    uint64_t detection_time_ns;
    uint64_t correlation_time_ns;
    uint64_t logging_time_ns;
    uint64_t parsed_timed_packets;
    uint64_t detected_timed_packets;
    uint64_t correlated_timed_packets;
    uint64_t logged_timed_events;
    uint64_t alerts_by_severity[IDS_SEVERITY_COUNT];
    uint64_t protocols[PACKET_PROTO_COUNT];
    uint64_t alerts_by_type[ALERT_TYPE_COUNT];
    ids_top_counter_t top_sources[IDS_STATS_TOP_ITEMS];
    ids_top_counter_t top_ports[IDS_STATS_TOP_ITEMS];
    size_t packet_queue_depth;
    size_t parsed_queue_depth;
    size_t log_queue_depth;
    uint64_t queue_drops;
    double shard_pressure;
    uint64_t shard_evictions;
    size_t source_memory_bytes;
    size_t pool_available;
    size_t pool_capacity;
    uint64_t pool_failed_acquires;
    uint64_t pool_invalid_releases;
} ids_stats_t;

int ids_stats_init(ids_stats_t *stats);
void ids_stats_destroy(ids_stats_t *stats);
void ids_stats_record_capture(ids_stats_t *stats, uint32_t bytes);
void ids_stats_record_parse(ids_stats_t *stats, const packet_info_t *packet);
void ids_stats_record_parse_error(ids_stats_t *stats);
void ids_stats_record_drop(ids_stats_t *stats, uint64_t count);
void ids_stats_record_alert_drop(ids_stats_t *stats, uint64_t count);
void ids_stats_record_storage_write(ids_stats_t *stats, uint64_t count);
void ids_stats_record_storage_error(ids_stats_t *stats, uint64_t count);
void ids_stats_record_storage_retry(ids_stats_t *stats);
void ids_stats_record_storage_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_heartbeat(ids_stats_t *stats);
void ids_stats_record_logged(ids_stats_t *stats);
void ids_stats_record_parse_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_detection_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_correlation_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_logging_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_alert(ids_stats_t *stats, const alert_t *alert);
void ids_stats_set_queues(ids_stats_t *stats,
                          size_t packet_queue_depth,
                          size_t parsed_queue_depth,
                          size_t log_queue_depth,
                          uint64_t queue_drops);
void ids_stats_set_detection_shards(ids_stats_t *stats, uint64_t shard_count);
void ids_stats_set_detection_runtime(ids_stats_t *stats,
                                     double shard_pressure,
                                     uint64_t plugin_count,
                                     uint64_t plugin_packets,
                                     uint64_t plugin_alerts,
                                     uint64_t plugin_errors,
                                     uint64_t plugin_latency_ns);
void ids_stats_set_detection_state(ids_stats_t *stats,
                                   uint64_t shard_evictions,
                                   size_t source_memory_bytes);
void ids_stats_set_event_bus(ids_stats_t *stats,
                             uint64_t published,
                             uint64_t dispatched,
                             uint64_t dropped,
                             size_t queue_depth,
                             size_t queue_capacity);
void ids_stats_set_memory_pool(ids_stats_t *stats,
                               size_t pool_available,
                               size_t pool_capacity,
                               uint64_t failed_acquires,
                               uint64_t invalid_releases);
void ids_stats_snapshot(ids_stats_t *stats, ids_stats_snapshot_t *snapshot);

#endif
