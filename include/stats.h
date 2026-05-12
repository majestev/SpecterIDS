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
    uint64_t bytes_seen;
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
    double avg_logging_us;
    double queue_pressure;
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
    uint64_t bytes_seen;
    uint64_t parse_time_ns;
    uint64_t detection_time_ns;
    uint64_t logging_time_ns;
    uint64_t parsed_timed_packets;
    uint64_t detected_timed_packets;
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
} ids_stats_t;

int ids_stats_init(ids_stats_t *stats);
void ids_stats_destroy(ids_stats_t *stats);
void ids_stats_record_capture(ids_stats_t *stats, uint32_t bytes);
void ids_stats_record_parse(ids_stats_t *stats, const packet_info_t *packet);
void ids_stats_record_parse_error(ids_stats_t *stats);
void ids_stats_record_drop(ids_stats_t *stats, uint64_t count);
void ids_stats_record_logged(ids_stats_t *stats);
void ids_stats_record_parse_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_detection_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_logging_time(ids_stats_t *stats, uint64_t nanoseconds);
void ids_stats_record_alert(ids_stats_t *stats, const alert_t *alert);
void ids_stats_set_queues(ids_stats_t *stats,
                          size_t packet_queue_depth,
                          size_t parsed_queue_depth,
                          size_t log_queue_depth,
                          uint64_t queue_drops);
void ids_stats_snapshot(ids_stats_t *stats, ids_stats_snapshot_t *snapshot);

#endif
