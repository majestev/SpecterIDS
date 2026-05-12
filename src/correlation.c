#include "correlation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static correlation_source_t *get_source(correlation_engine_t *engine, const char *source_ip)
{
    correlation_source_t *current = engine->sources;

    while (current != NULL) {
        if (strcmp(current->source_ip, source_ip) == 0) {
            return current;
        }
        current = current->next;
    }

    current = calloc(1, sizeof(*current));
    if (current == NULL) {
        return NULL;
    }

    ids_copy_string(current->source_ip, sizeof(current->source_ip), source_ip);
    current->next = engine->sources;
    engine->sources = current;
    return current;
}

int correlation_init(correlation_engine_t *engine, int window_seconds)
{
    if (engine == NULL) {
        return -1;
    }

    memset(engine, 0, sizeof(*engine));
    engine->window_seconds = window_seconds > 0 ? window_seconds : 300;
    return pthread_mutex_init(&engine->lock, NULL);
}

void correlation_destroy(correlation_engine_t *engine)
{
    correlation_source_t *current;

    if (engine == NULL) {
        return;
    }

    current = engine->sources;
    while (current != NULL) {
        correlation_source_t *next = current->next;
        free(current);
        current = next;
    }
    pthread_mutex_destroy(&engine->lock);
    memset(engine, 0, sizeof(*engine));
}

static bool within_window(time_t now, time_t then, int window)
{
    return then != 0 && now >= then && now - then <= window;
}

static void build_correlation_alert(const alert_t *base, correlation_source_t *source, alert_t *out)
{
    *out = *base;
    out->type = ALERT_TYPE_THREAT_CORRELATION;
    out->severity = IDS_SEVERITY_CRITICAL;
    out->risk_score = source->attack_score;
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

        if (source->attack_score > 100) {
            source->attack_score = 100;
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
