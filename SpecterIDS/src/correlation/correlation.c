#include "correlation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CORRELATION_MAX_SOURCES    4096U
#define CORR_DECAY_INTERVAL_SEC    60
#define CORR_DECAY_RATE            10
#define CORR_SCORE_MAX             100

/* Delegates to the shared ids_fnv1a_str() in common.h */
static uint64_t hash_corr_ip(const char *ip)
{
    return ids_fnv1a_str(ip);
}

/*
 * O(1) average lookup via hash table with separate chaining.
 * Previous implementation was O(n) linked-list scan — worst case 4096
 * strcmp calls per alert under a busy alert storm.
 */
static correlation_source_t *get_source(correlation_engine_t *engine, const char *source_ip)
{
    uint64_t hash = hash_corr_ip(source_ip);
    size_t bucket = hash % CORR_HASH_BUCKETS;
    correlation_source_t *current = engine->buckets[bucket];

    while (current != NULL) {
        if (strcmp(current->source_ip, source_ip) == 0) {
            return current;
        }
        current = current->next;
    }

    if (engine->source_count >= engine->max_sources) {
        return NULL;
    }

    current = calloc(1, sizeof(*current));
    if (current == NULL) {
        return NULL;
    }

    ids_copy_string(current->source_ip, sizeof(current->source_ip), source_ip);
    current->next = engine->buckets[bucket];
    engine->buckets[bucket] = current;
    engine->source_count++;
    return current;
}

int correlation_init(correlation_engine_t *engine, int window_seconds)
{
    if (engine == NULL) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));
    engine->window_seconds = window_seconds > 0 ? window_seconds : 300;
    engine->max_sources = CORRELATION_MAX_SOURCES;
    return pthread_mutex_init(&engine->lock, NULL);
}

void correlation_destroy(correlation_engine_t *engine)
{
    size_t i;

    if (engine == NULL) {
        return;
    }

    /* Walk all buckets and free every chain node */
    for (i = 0; i < CORR_HASH_BUCKETS; i++) {
        correlation_source_t *current = engine->buckets[i];

        while (current != NULL) {
            correlation_source_t *next = current->next;
            free(current);
            current = next;
        }
        engine->buckets[i] = NULL;
    }

    pthread_mutex_destroy(&engine->lock);
    memset(engine, 0, sizeof(*engine));
}

static bool within_window(time_t now, time_t then, int window)
{
    return then != 0 && now >= then && now - then <= window;
}

static void decay_source_score(correlation_source_t *source, time_t now)
{
    time_t elapsed;
    int decay;

    if (source->last_decay_at == 0) {
        source->last_decay_at = now;
        return;
    }

    elapsed = now - source->last_decay_at;
    if (elapsed < CORR_DECAY_INTERVAL_SEC) {
        return;
    }

    decay = (int)(elapsed / CORR_DECAY_INTERVAL_SEC) * CORR_DECAY_RATE;
    source->attack_score = source->attack_score > decay ? source->attack_score - decay : 0;
    source->last_decay_at = now;
}

static void build_correlation_alert(const alert_t *base, correlation_source_t *source, alert_t *out)
{
    *out = *base;
    out->type = ALERT_TYPE_THREAT_CORRELATION;
    out->severity = IDS_SEVERITY_CRITICAL;
    out->risk_score = source->attack_score;
    out->confidence_score = source->attack_score;
    snprintf(out->reason,
             sizeof(out->reason),
             "Temporal correlation: scan/bruteforce/beacon pattern observed with confidence score %d",
             source->attack_score);
}

size_t correlation_process_alerts(correlation_engine_t *engine,
                                  const alert_t *input_alerts,
                                  size_t input_count,
                                  alert_t *output_alerts,
                                  size_t max_output_alerts)
{
    size_t output_count = 0;
    size_t i;

    if (engine == NULL || input_alerts == NULL || output_alerts == NULL || max_output_alerts == 0) {
        return 0;
    }

    pthread_mutex_lock(&engine->lock);
    for (i = 0; i < input_count && output_count < max_output_alerts; i++) {
        const alert_t *alert = &input_alerts[i];
        correlation_source_t *source = get_source(engine, alert->source_ip);
        time_t now = alert->timestamp.tv_sec;

        if (source == NULL) {
            continue;
        }
        decay_source_score(source, now);

        if (alert->type == ALERT_TYPE_PORT_SCAN || alert->type == ALERT_TYPE_SLOW_SCAN) {
            source->scan_seen_at = now;
            source->attack_score += 25;
        } else if (alert->type == ALERT_TYPE_SSH_BRUTE_FORCE ||
                   alert->type == ALERT_TYPE_SENSITIVE_PORT ||
                   alert->type == ALERT_TYPE_CONNECTION_EXCESS) {
            source->brute_seen_at = now;
            source->attack_score += 25;
        } else if (alert->type == ALERT_TYPE_BEACONING) {
            source->beacon_seen_at = now;
            source->attack_score += 35;
        } else {
            source->attack_score += 5;
        }

        if (source->attack_score > CORR_SCORE_MAX) {
            source->attack_score = CORR_SCORE_MAX;
        }

        if (within_window(now, source->scan_seen_at, engine->window_seconds) &&
            within_window(now, source->brute_seen_at, engine->window_seconds) &&
            within_window(now, source->beacon_seen_at, engine->window_seconds) &&
            (!within_window(now, source->last_alert_at, engine->window_seconds))) {
            build_correlation_alert(alert, source, &output_alerts[output_count++]);
            source->last_alert_at = now;
        }
    }
    pthread_mutex_unlock(&engine->lock);

    return output_count;
}
