#ifndef SPECTERIDS_CORRELATION_H
#define SPECTERIDS_CORRELATION_H

#include <stddef.h>
#include <pthread.h>

#include "detection.h"

typedef struct correlation_source {
    char source_ip[SPECTERIDS_IP_STR_LEN];
    time_t scan_seen_at;
    time_t brute_seen_at;
    time_t beacon_seen_at;
    time_t last_alert_at;
    int attack_score;
    struct correlation_source *next;
} correlation_source_t;

typedef struct {
    correlation_source_t *sources;
    pthread_mutex_t lock;
    int window_seconds;
} correlation_engine_t;

int correlation_init(correlation_engine_t *engine, int window_seconds);
void correlation_destroy(correlation_engine_t *engine);
size_t correlation_process_alerts(correlation_engine_t *engine,
                                  const alert_t *input_alerts,
                                  size_t input_count,
                                  alert_t *output_alerts,
                                  size_t max_output_alerts);

#endif
