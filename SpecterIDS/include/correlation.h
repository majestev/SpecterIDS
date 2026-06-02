#ifndef SPECTERIDS_CORRELATION_H
#define SPECTERIDS_CORRELATION_H

#include <stddef.h>
#include <pthread.h>

#include "detection.h"

/* Hash table size: power of 2, 2× max_sources for ≤50% load factor */
#define CORR_HASH_BUCKETS 8192U

typedef struct correlation_source {
    char source_ip[SPECTERIDS_IP_STR_LEN];
    time_t scan_seen_at;
    time_t brute_seen_at;
    time_t beacon_seen_at;
    time_t last_alert_at;
    time_t last_decay_at;
    int attack_score;
    struct correlation_source *next; /* collision chain within same bucket */
} correlation_source_t;

typedef struct {
    correlation_source_t *buckets[CORR_HASH_BUCKETS]; /* hash table, O(1) avg */
    pthread_mutex_t lock;
    int window_seconds;
    size_t source_count;
    size_t max_sources;
} correlation_engine_t;

int correlation_init(correlation_engine_t *engine, int window_seconds);
void correlation_destroy(correlation_engine_t *engine);
size_t correlation_process_alerts(correlation_engine_t *engine,
                                  const alert_t *input_alerts,
                                  size_t input_count,
                                  alert_t *output_alerts,
                                  size_t max_output_alerts);

#endif
