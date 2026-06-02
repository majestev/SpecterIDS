#include "detection.h"
#include "plugin_api.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKED_SOURCES  2048U
#define SOURCE_BUCKETS       4096U
#define MAX_PORT_EVENTS      256U
#define MAX_TIMED_EVENTS     256U
#define MAX_BEACON_EVENTS    256U
#define MAX_DYNAMIC_PLUGINS  32U

/* ARP hash table: power-of-2, 2× MAX_ARP_BINDINGS → ≤50% load factor */
#define ARP_HASH_SIZE        8192U

/* Risk scoring points per severity level */
#define RISK_LOW_POINTS      5
#define RISK_MEDIUM_POINTS   15
#define RISK_HIGH_POINTS     30
#define RISK_CRITICAL_POINTS 50

/* Risk score lifecycle constants */
#define RISK_SCORE_MAX          200
#define RISK_DECAY_PER_MINUTE   5
#define RISK_DECAY_INTERVAL_SEC 60

/* Dynamic severity escalation thresholds */
#define RISK_THRESH_CRITICAL    120
#define RISK_THRESH_HIGH        80
#define RISK_THRESH_MEDIUM      50

typedef struct {
    time_t timestamp;
    uint16_t destination_port;
} port_event_t;

typedef struct {
    time_t timestamp;
    uint32_t bytes;
} byte_event_t;

typedef struct {
    time_t timestamp;
    char destination_ip[SPECTERIDS_IP_STR_LEN];
    uint16_t destination_port;
    packet_protocol_t protocol;
} beacon_event_t;

typedef struct source_state {
    char source_ip[SPECTERIDS_IP_STR_LEN];
    port_event_t port_events[MAX_PORT_EVENTS];
    size_t port_event_count;
    time_t ssh_events[MAX_TIMED_EVENTS];
    size_t ssh_event_count;
    time_t syn_events[MAX_TIMED_EVENTS];
    size_t syn_event_count;
    time_t icmp_events[MAX_TIMED_EVENTS];
    size_t icmp_event_count;
    time_t udp_events[MAX_TIMED_EVENTS];
    size_t udp_event_count;
    time_t dns_events[MAX_TIMED_EVENTS];
    size_t dns_event_count;
    time_t all_packet_events[MAX_TIMED_EVENTS];
    size_t all_packet_event_count;
    time_t connection_events[MAX_TIMED_EVENTS];
    size_t connection_event_count;
    time_t http_events[MAX_TIMED_EVENTS];
    size_t http_event_count;
    port_event_t slow_port_events[MAX_PORT_EVENTS];
    size_t slow_port_event_count;
    byte_event_t byte_events[MAX_TIMED_EVENTS];
    size_t byte_event_count;
    beacon_event_t beacon_events[MAX_BEACON_EVENTS];
    size_t beacon_event_count;
    time_t last_alert_at[ALERT_TYPE_COUNT];
    int risk_score;
    time_t last_risk_decay_at;
    time_t last_packet_at; /* updated every packet; used for LRU eviction */
    struct source_state *next;
} source_state_t;

typedef struct {
    char ip[SPECTERIDS_IP_STR_LEN];
    char mac[SPECTERIDS_MAC_STR_LEN];
    time_t last_seen;
    bool occupied; /* open-addressing sentinel: slot is in use */
} arp_binding_t;

typedef struct {
    source_state_t *buckets[SOURCE_BUCKETS];
    size_t source_count;
    arp_binding_t arp_table[ARP_HASH_SIZE]; /* open-addressing hash, O(1) avg */
    size_t arp_table_used;
    uint64_t eviction_count; /* LRU evictions since shard init */
    pthread_mutex_t lock;
} detection_shard_t;

typedef struct {
    char path[SPECTERIDS_PATH_LEN];
    char name[SPECTERIDS_PLUGIN_NAME_LEN];
    void *handle;
    const specterids_plugin_descriptor_t *descriptor;
    void *state;
    uint64_t packets;
    uint64_t alerts;
    uint64_t errors;
    uint64_t latency_ns;
    pthread_mutex_t lock;
} dynamic_plugin_t;

struct detection_engine {
    ids_rules_t rules;
    uint16_t sensitive_ports[SPECTERIDS_MAX_SENSITIVE_PORTS];
    size_t sensitive_port_count;
    detection_shard_t *shards;
    size_t shard_count;
    dynamic_plugin_t plugins[MAX_DYNAMIC_PLUGINS];
    size_t plugin_count;
    uint64_t plugin_packets;
    uint64_t plugin_alerts;
    uint64_t plugin_errors;
    uint64_t plugin_latency_ns;
    pthread_mutex_t rules_lock;
    pthread_mutex_t plugin_lock;
};

static uint64_t hash_source_ip(const char *source_ip);

static source_state_t *find_source(detection_shard_t *shard, const char *source_ip)
{
    size_t bucket;
    source_state_t *current;

    if (shard == NULL || source_ip == NULL) {
        return NULL;
    }

    bucket = (size_t)(hash_source_ip(source_ip) % SOURCE_BUCKETS);
    current = shard->buckets[bucket];

    while (current != NULL) {
        if (strcmp(current->source_ip, source_ip) == 0) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

/*
 * Evict the least-recently-used source from the shard.
 * Returns a zeroed, detached node ready for reuse as a new source,
 * or NULL if the shard is empty. O(n) over the bucket array — only
 * called when a shard is full, which is rare in steady state.
 */
static source_state_t *evict_lru_source(detection_shard_t *shard)
{
    source_state_t *lru_node = NULL;
    source_state_t **lru_prev = NULL;
    size_t bucket;

    for (bucket = 0; bucket < SOURCE_BUCKETS; bucket++) {
        source_state_t **prev = &shard->buckets[bucket];
        source_state_t *current = shard->buckets[bucket];

        while (current != NULL) {
            if (lru_node == NULL || current->last_packet_at < lru_node->last_packet_at) {
                lru_node = current;
                lru_prev = prev;
            }
            prev = &current->next;
            current = current->next;
        }
    }

    if (lru_node == NULL) {
        return NULL;
    }

    *lru_prev = lru_node->next;
    lru_node->next = NULL;
    shard->source_count--;
    shard->eviction_count++;
    memset(lru_node, 0, sizeof(*lru_node));
    return lru_node;
}

static source_state_t *get_or_create_source(detection_shard_t *shard, const char *source_ip)
{
    source_state_t *state = find_source(shard, source_ip);
    size_t bucket;

    if (state != NULL) {
        return state;
    }

    if (shard->source_count >= MAX_TRACKED_SOURCES) {
        /*
         * Shard is full. Evict the LRU entry and reuse its allocation
         * rather than dropping the packet silently (previous behaviour).
         */
        state = evict_lru_source(shard);
        if (state == NULL) {
            return NULL;
        }
    } else {
        state = calloc(1, sizeof(*state));
        if (state == NULL) {
            return NULL;
        }
    }

    ids_copy_string(state->source_ip, sizeof(state->source_ip), source_ip);
    bucket = (size_t)(hash_source_ip(source_ip) % SOURCE_BUCKETS);
    state->next = shard->buckets[bucket];
    shard->buckets[bucket] = state;
    shard->source_count++;

    return state;
}

static void prune_time_events(time_t *events, size_t *count, time_t now, int window_seconds)
{
    size_t read_index;
    size_t write_index = 0;
    time_t cutoff = now - window_seconds;

    for (read_index = 0; read_index < *count; read_index++) {
        if (events[read_index] >= cutoff) {
            events[write_index++] = events[read_index];
        }
    }

    *count = write_index;
}

static size_t add_time_event(time_t *events,
                             size_t *count,
                             size_t max_events,
                             time_t now,
                             int window_seconds)
{
    prune_time_events(events, count, now, window_seconds);

    if (*count >= max_events) {
        memmove(events, events + 1, (max_events - 1) * sizeof(events[0]));
        *count = max_events - 1;
    }

    events[*count] = now;
    (*count)++;

    return *count;
}

static uint64_t add_byte_event(byte_event_t *events,
                               size_t *count,
                               size_t max_events,
                               time_t now,
                               int window_seconds,
                               uint32_t bytes)
{
    size_t read_index;
    size_t write_index = 0;
    time_t cutoff = now - window_seconds;
    uint64_t total = 0;

    for (read_index = 0; read_index < *count; read_index++) {
        if (events[read_index].timestamp >= cutoff) {
            events[write_index++] = events[read_index];
            total += events[read_index].bytes;
        }
    }
    *count = write_index;

    /*
     * After the compaction loop, `total` is the sum of all surviving
     * (in-window) entries. If the ring is still full we must evict events[0]
     * (the oldest surviving entry) to make room. Subtract its bytes from
     * `total` before shifting it out — it was already included in total above.
     */
    if (*count >= max_events) {
        total -= events[0].bytes;
        memmove(events, events + 1, (max_events - 1) * sizeof(events[0]));
        *count = max_events - 1;
    }

    events[*count].timestamp = now;
    events[*count].bytes = bytes;
    (*count)++;
    total += bytes;

    return total;
}

static void prune_port_events(port_event_t *events, size_t *count, time_t now, int window_seconds)
{
    size_t read_index;
    size_t write_index = 0;
    time_t cutoff = now - window_seconds;

    for (read_index = 0; read_index < *count; read_index++) {
        if (events[read_index].timestamp >= cutoff) {
            events[write_index++] = events[read_index];
        }
    }

    *count = write_index;
}

static size_t count_unique_ports(const port_event_t *events, size_t count)
{
    uint8_t seen[8192]; /* 65536-bit bitset, one bit per port number */
    size_t unique_count = 0;
    size_t i;

    memset(seen, 0, sizeof(seen));
    for (i = 0; i < count; i++) {
        uint16_t port = events[i].destination_port;
        uint8_t bit = (uint8_t)(1U << (port & 7U));
        uint8_t *byte = &seen[port >> 3U];

        if (!(*byte & bit)) {
            *byte |= bit;
            unique_count++;
        }
    }

    return unique_count;
}

/* Shared implementation for add_port_event and add_slow_port_event */
static size_t add_port_event_to(port_event_t *events,
                                size_t *count,
                                uint16_t destination_port,
                                time_t now,
                                int window_seconds)
{
    prune_port_events(events, count, now, window_seconds);

    if (*count >= MAX_PORT_EVENTS) {
        memmove(events, events + 1, (MAX_PORT_EVENTS - 1) * sizeof(events[0]));
        *count = MAX_PORT_EVENTS - 1;
    }

    events[*count].timestamp = now;
    events[*count].destination_port = destination_port;
    (*count)++;

    return count_unique_ports(events, *count);
}

static size_t add_port_event(source_state_t *state,
                             uint16_t destination_port,
                             time_t now,
                             int window_seconds)
{
    return add_port_event_to(state->port_events,
                             &state->port_event_count,
                             destination_port,
                             now,
                             window_seconds);
}

static size_t add_slow_port_event(source_state_t *state,
                                  uint16_t destination_port,
                                  time_t now,
                                  int window_seconds)
{
    return add_port_event_to(state->slow_port_events,
                             &state->slow_port_event_count,
                             destination_port,
                             now,
                             window_seconds);
}

static int severity_points(ids_severity_t severity)
{
    switch (severity) {
    case IDS_SEVERITY_LOW:
        return RISK_LOW_POINTS;
    case IDS_SEVERITY_MEDIUM:
        return RISK_MEDIUM_POINTS;
    case IDS_SEVERITY_HIGH:
        return RISK_HIGH_POINTS;
    case IDS_SEVERITY_CRITICAL:
        return RISK_CRITICAL_POINTS;
    case IDS_SEVERITY_COUNT:
    default:
        return RISK_LOW_POINTS;
    }
}

static void decay_risk(source_state_t *state, time_t now)
{
    time_t elapsed;
    int decay;

    if (state->last_risk_decay_at == 0) {
        state->last_risk_decay_at = now;
        return;
    }

    elapsed = now - state->last_risk_decay_at;
    if (elapsed < RISK_DECAY_INTERVAL_SEC) {
        return;
    }

    {
        /* Compute in time_t width before capping to avoid signed overflow when
           elapsed is large (e.g. source state kept alive for days, or a clock
           jump resets last_risk_decay_at to 0). */
        time_t intervals = elapsed / RISK_DECAY_INTERVAL_SEC;
        time_t decay_wide = intervals * (time_t)RISK_DECAY_PER_MINUTE;

        decay = (decay_wide >= (time_t)RISK_SCORE_MAX) ? RISK_SCORE_MAX : (int)decay_wide;
    }
    state->risk_score = state->risk_score > decay ? state->risk_score - decay : 0;
    state->last_risk_decay_at = now;
}

static ids_severity_t dynamic_severity(ids_severity_t base, int risk_score)
{
    if (risk_score >= RISK_THRESH_CRITICAL) {
        return IDS_SEVERITY_CRITICAL;
    }
    if (risk_score >= RISK_THRESH_HIGH && base < IDS_SEVERITY_HIGH) {
        return IDS_SEVERITY_HIGH;
    }
    if (risk_score >= RISK_THRESH_MEDIUM && base < IDS_SEVERITY_MEDIUM) {
        return IDS_SEVERITY_MEDIUM;
    }
    return base;
}

static bool should_emit_alert(source_state_t *state,
                              alert_type_t type,
                              time_t now,
                              int suppression_seconds)
{
    time_t previous = state->last_alert_at[type];
    int effective_suppression = suppression_seconds > 0 ? suppression_seconds : 1;

    if (previous != 0 && (now - previous) < effective_suppression) {
        return false;
    }

    state->last_alert_at[type] = now;
    return true;
}

static void build_alert(alert_t *alert,
                        alert_type_t type,
                        ids_severity_t severity,
                        const packet_info_t *packet,
                        const char *reason,
                        int risk_score)
{
    int confidence_score = risk_score;

    memset(alert, 0, sizeof(*alert));
    alert->type = type;
    alert->severity = severity;
    ids_copy_string(alert->source_ip, sizeof(alert->source_ip), packet->src_ip);
    ids_copy_string(alert->destination_ip, sizeof(alert->destination_ip), packet->dst_ip);
    ids_copy_string(alert->reason, sizeof(alert->reason), reason);
    snprintf(alert->correlation_id,
             sizeof(alert->correlation_id),
             "%ld-%u-%u",
             (long)packet->timestamp.tv_sec,
             packet->src_port,
             packet->dst_port);
    alert->risk_score = risk_score;
    if (confidence_score < severity_points(severity)) {
        confidence_score = severity_points(severity);
    }
    if (confidence_score < 0) {
        confidence_score = 0;
    }
    if (confidence_score > 100) {
        confidence_score = 100;
    }
    alert->confidence_score = confidence_score;
    alert->timestamp = packet->timestamp;
}

static bool emit_alert(source_state_t *state,
                       alert_t *alerts,
                       size_t *alert_count,
                       size_t max_alerts,
                       alert_type_t type,
                       ids_severity_t severity,
                       const packet_info_t *packet,
                       const char *reason)
{
    ids_severity_t final_severity;

    if (*alert_count >= max_alerts) {
        return false;
    }

    state->risk_score += severity_points(severity);
    if (state->risk_score > RISK_SCORE_MAX) {
        state->risk_score = RISK_SCORE_MAX;
    }
    final_severity = dynamic_severity(severity, state->risk_score);
    build_alert(&alerts[*alert_count], type, final_severity, packet, reason, state->risk_score);
    (*alert_count)++;
    return true;
}

static bool is_connection_candidate(const packet_info_t *packet)
{
    if (packet->protocol == PACKET_PROTO_TCP) {
        return packet->tcp_syn && !packet->tcp_ack;
    }

    return packet->protocol == PACKET_PROTO_UDP;
}

static void prune_beacon_events(source_state_t *state, time_t now, int interval_seconds, int min_hits)
{
    size_t read_index;
    size_t write_index = 0;
    int window_seconds = interval_seconds * (min_hits + 2);
    time_t cutoff = now - window_seconds;

    if (window_seconds < interval_seconds) {
        cutoff = now - interval_seconds;
    }

    for (read_index = 0; read_index < state->beacon_event_count; read_index++) {
        if (state->beacon_events[read_index].timestamp >= cutoff) {
            state->beacon_events[write_index++] = state->beacon_events[read_index];
        }
    }

    state->beacon_event_count = write_index;
}

static void add_beacon_event(source_state_t *state, const packet_info_t *packet, const rule_config_t *rule)
{
    prune_beacon_events(state, packet->timestamp.tv_sec, rule->interval_seconds, rule->min_hits);

    if (state->beacon_event_count >= MAX_BEACON_EVENTS) {
        memmove(state->beacon_events,
                state->beacon_events + 1,
                (MAX_BEACON_EVENTS - 1) * sizeof(state->beacon_events[0]));
        state->beacon_event_count = MAX_BEACON_EVENTS - 1;
    }

    state->beacon_events[state->beacon_event_count].timestamp = packet->timestamp.tv_sec;
    ids_copy_string(state->beacon_events[state->beacon_event_count].destination_ip,
                    sizeof(state->beacon_events[state->beacon_event_count].destination_ip),
                    packet->dst_ip);
    state->beacon_events[state->beacon_event_count].destination_port = packet->dst_port;
    state->beacon_events[state->beacon_event_count].protocol = packet->protocol;
    state->beacon_event_count++;
}

static bool beacon_tuple_matches(const beacon_event_t *event, const packet_info_t *packet)
{
    return event->protocol == packet->protocol &&
           event->destination_port == packet->dst_port &&
           strcmp(event->destination_ip, packet->dst_ip) == 0;
}

static bool ip_in_csv(const char *csv, const char *ip)
{
    char copy[SPECTERIDS_LIST_LEN];
    char *saveptr = NULL;
    char *token;

    if (csv == NULL || csv[0] == '\0' || ip == NULL || ip[0] == '\0' ||
        strlen(csv) >= sizeof(copy)) {
        return false;
    }

    ids_copy_string(copy, sizeof(copy), csv);
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        char *trimmed = ids_trim(token);
        if (trimmed != NULL && strcmp(trimmed, ip) == 0) {
            return true;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return false;
}

static bool is_private_or_local_ip(const char *ip)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (ip == NULL || ip[0] == '\0') {
        return false;
    }

    if (inet_pton(AF_INET, ip, &v4) == 1) {
        uint32_t host = ntohl(v4.s_addr);

        return (host >> 24U) == 10U ||
               (host >> 20U) == 0xAC1U ||
               (host >> 16U) == 0xC0A8U ||
               (host >> 24U) == 127U ||
               (host >> 16U) == 0xA9FEU;
    }

    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        return v6.s6_addr[0] == 0xFCU ||
               v6.s6_addr[0] == 0xFDU ||
               (v6.s6_addr[0] == 0xFEU && (v6.s6_addr[1] & 0xC0U) == 0x80U) ||
               IN6_IS_ADDR_LOOPBACK(&v6);
    }

    return false;
}

static size_t count_regular_beacon_hits(const source_state_t *state,
                                        const packet_info_t *packet,
                                        const rule_config_t *rule,
                                        double *average_interval)
{
    time_t reversed[MAX_BEACON_EVENTS];
    size_t reversed_count = 0;
    size_t i;
    size_t regular_hits = 1;
    double total_delta = 0.0;
    size_t delta_count = 0;

    if (state->beacon_event_count == 0) {
        return 0;
    }

    for (i = state->beacon_event_count; i > 0; i--) {
        const beacon_event_t *event = &state->beacon_events[i - 1];
        if (beacon_tuple_matches(event, packet)) {
            reversed[reversed_count++] = event->timestamp;
            if (reversed_count >= (size_t)rule->min_hits) {
                break;
            }
        }
    }

    if (reversed_count < (size_t)rule->min_hits) {
        return reversed_count;
    }

    for (i = 1; i < reversed_count; i++) {
        time_t delta = reversed[i - 1] - reversed[i];
        if (delta < 0) {
            delta = -delta;
        }
        if (delta >= rule->interval_seconds - rule->tolerance_seconds &&
            delta <= rule->interval_seconds + rule->tolerance_seconds) {
            regular_hits++;
            total_delta += (double)delta;
            delta_count++;
        } else {
            break;
        }
    }

    if (average_interval != NULL && delta_count > 0) {
        *average_interval = total_delta / (double)delta_count;
    }
    return regular_hits;
}

static uint64_t hash_source_ip(const char *source_ip)
{
    return ids_fnv1a_str(source_ip);
}

static detection_shard_t *select_shard(detection_engine_t *engine, const char *source_ip)
{
    uint64_t hash;

    if (engine == NULL || engine->shards == NULL || engine->shard_count == 0) {
        return NULL;
    }

    hash = hash_source_ip(source_ip);
    return &engine->shards[hash % engine->shard_count];
}

detection_engine_t *detection_create_with_shards(const ids_rules_t *rules, size_t shard_count)
{
    detection_engine_t *engine = calloc(1, sizeof(*engine));
    size_t i;

    if (engine == NULL) {
        return NULL;
    }

    if (shard_count == 0) {
        shard_count = 1;
    }
    if (shard_count > 256U) {
        shard_count = 256U;
    }

    if (rules != NULL) {
        engine->rules = *rules;
    } else {
        rules_set_defaults(&engine->rules);
    }
    engine->sensitive_ports[0] = 22;
    engine->sensitive_ports[1] = 23;
    engine->sensitive_ports[2] = 3389;
    engine->sensitive_ports[3] = 445;
    engine->sensitive_port_count = 4;
    engine->shard_count = shard_count;
    engine->shards = calloc(shard_count, sizeof(engine->shards[0]));
    if (engine->shards == NULL) {
        free(engine);
        return NULL;
    }

    if (pthread_mutex_init(&engine->rules_lock, NULL) != 0) {
        free(engine->shards);
        free(engine);
        return NULL;
    }
    if (pthread_mutex_init(&engine->plugin_lock, NULL) != 0) {
        pthread_mutex_destroy(&engine->rules_lock);
        free(engine->shards);
        free(engine);
        return NULL;
    }

    for (i = 0; i < shard_count; i++) {
        if (pthread_mutex_init(&engine->shards[i].lock, NULL) != 0) {
            while (i > 0) {
                i--;
                pthread_mutex_destroy(&engine->shards[i].lock);
            }
            pthread_mutex_destroy(&engine->plugin_lock);
            pthread_mutex_destroy(&engine->rules_lock);
            free(engine->shards);
            free(engine);
            return NULL;
        }
    }

    return engine;
}

detection_engine_t *detection_create(const ids_rules_t *rules)
{
    return detection_create_with_shards(rules, 16U);
}

void detection_set_sensitive_ports(detection_engine_t *engine,
                                   const uint16_t *ports,
                                   size_t count)
{
    size_t i;

    if (engine == NULL || ports == NULL || count == 0) {
        return;
    }

    if (count > SPECTERIDS_MAX_SENSITIVE_PORTS) {
        count = SPECTERIDS_MAX_SENSITIVE_PORTS;
    }

    pthread_mutex_lock(&engine->rules_lock);
    for (i = 0; i < count; i++) {
        engine->sensitive_ports[i] = ports[i];
    }
    engine->sensitive_port_count = count;
    pthread_mutex_unlock(&engine->rules_lock);
}

void detection_update_rules(detection_engine_t *engine, const ids_rules_t *rules)
{
    if (engine == NULL || rules == NULL) {
        return;
    }

    pthread_mutex_lock(&engine->rules_lock);
    engine->rules = *rules;
    pthread_mutex_unlock(&engine->rules_lock);
}

static void set_plugin_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s", message != NULL ? message : "plugin error");
    }
}

static bool has_shared_object_suffix(const char *path)
{
    size_t len;

    if (path == NULL) {
        return false;
    }

    len = strlen(path);
    return len > 3U && strcmp(path + len - 3U, ".so") == 0;
}

int detection_load_plugin(detection_engine_t *engine, const char *path, char *error, size_t error_size)
{
    specterids_plugin_descriptor_fn descriptor_fn;
    const specterids_plugin_descriptor_t *descriptor;
    dynamic_plugin_t *plugin;
    void *handle;
    void *state = NULL;

    if (engine == NULL || path == NULL || path[0] == '\0') {
        set_plugin_error(error, error_size, "invalid plugin argument");
        return -1;
    }
    if (strlen(path) >= SPECTERIDS_PATH_LEN) {
        set_plugin_error(error, error_size, "plugin path is too long");
        return -1;
    }
    if (!has_shared_object_suffix(path)) {
        set_plugin_error(error, error_size, "plugin path must end with .so");
        return -1;
    }

    /*
     * Pre-check without the lock: dlopen must run outside any lock (it may
     * call arbitrary init code). We re-check under the lock before inserting.
     * Do NOT drop the lock between "check" and "insert" — the second lock
     * acquisition at the insertion point is authoritative.
     */
    pthread_mutex_lock(&engine->plugin_lock);
    if (engine->plugin_count >= MAX_DYNAMIC_PLUGINS) {
        pthread_mutex_unlock(&engine->plugin_lock);
        set_plugin_error(error, error_size, "too many plugins loaded");
        return -1;
    }
    pthread_mutex_unlock(&engine->plugin_lock);

    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        set_plugin_error(error, error_size, dlerror());
        return -1;
    }

    {
        void *symbol;

        dlerror();
        symbol = dlsym(handle, SPECTERIDS_PLUGIN_ENTRYPOINT);
        if (symbol == NULL) {
            set_plugin_error(error, error_size, "plugin descriptor symbol not found");
            dlclose(handle);
            return -1;
        }
        memcpy(&descriptor_fn, &symbol, sizeof(descriptor_fn));
    }
    if (descriptor_fn == NULL) {
        set_plugin_error(error, error_size, "plugin descriptor symbol not found");
        dlclose(handle);
        return -1;
    }

    descriptor = descriptor_fn();
    if (descriptor == NULL ||
        descriptor->abi_version != SPECTERIDS_PLUGIN_ABI_VERSION ||
        descriptor->min_core_abi > SPECTERIDS_PLUGIN_ABI_VERSION ||
        descriptor->name == NULL ||
        descriptor->name[0] == '\0' ||
        descriptor->capabilities == 0U ||
        (descriptor->capabilities & ~SPECTERIDS_PLUGIN_CAP_MASK) != 0U ||
        ((descriptor->capabilities & SPECTERIDS_PLUGIN_CAP_PACKET) != 0U &&
         descriptor->packet_handler == NULL) ||
        ((descriptor->capabilities & SPECTERIDS_PLUGIN_CAP_ALERT) != 0U &&
         descriptor->alert_handler == NULL)) {
        set_plugin_error(error, error_size, "plugin ABI validation failed");
        dlclose(handle);
        return -1;
    }

    if (descriptor->init != NULL && descriptor->init(&state) != 0) {
        set_plugin_error(error, error_size, "plugin init hook failed");
        dlclose(handle);
        return -1;
    }
    if (descriptor->start != NULL && descriptor->start(state) != 0) {
        if (descriptor->unload != NULL) {
            descriptor->unload(state);
        }
        set_plugin_error(error, error_size, "plugin start hook failed");
        dlclose(handle);
        return -1;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    if (engine->plugin_count >= MAX_DYNAMIC_PLUGINS) {
        pthread_mutex_unlock(&engine->plugin_lock);
        if (descriptor->stop != NULL) {
            descriptor->stop(state);
        }
        if (descriptor->unload != NULL) {
            descriptor->unload(state);
        }
        set_plugin_error(error, error_size, "too many plugins loaded");
        dlclose(handle);
        return -1;
    }

    plugin = &engine->plugins[engine->plugin_count++];
    memset(plugin, 0, sizeof(*plugin));
    ids_copy_string(plugin->path, sizeof(plugin->path), path);
    ids_copy_string(plugin->name, sizeof(plugin->name), descriptor->name);
    plugin->handle = handle;
    plugin->descriptor = descriptor;
    plugin->state = state;
    if (pthread_mutex_init(&plugin->lock, NULL) != 0) {
        engine->plugin_count--;
        pthread_mutex_unlock(&engine->plugin_lock);
        if (descriptor->stop != NULL) {
            descriptor->stop(state);
        }
        if (descriptor->unload != NULL) {
            descriptor->unload(state);
        }
        dlclose(handle);
        set_plugin_error(error, error_size, "plugin mutex initialization failed");
        return -1;
    }
    pthread_mutex_unlock(&engine->plugin_lock);
    return 0;
}

int detection_load_plugins_from_csv(detection_engine_t *engine, const char *paths)
{
    char copy[SPECTERIDS_LIST_LEN];
    char *saveptr = NULL;
    char *token;
    int loaded = 0;
    int failures = 0;

    if (engine == NULL || paths == NULL || paths[0] == '\0') {
        return 0;
    }
    if (strlen(paths) >= sizeof(copy)) {
        return -1;
    }

    ids_copy_string(copy, sizeof(copy), paths);
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        char *path = ids_trim(token);
        char error[160];

        if (path != NULL && path[0] != '\0') {
            if (detection_load_plugin(engine, path, error, sizeof(error)) == 0) {
                loaded++;
            } else {
                fprintf(stderr, "Warning: failed to load plugin '%s': %s\n", path, error);
                failures++;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return failures > 0 ? -1 : loaded;
}

int detection_load_plugins_from_dir(detection_engine_t *engine, const char *dir_path)
{
    DIR *dir;
    struct dirent *entry;
    int loaded = 0;

    if (engine == NULL || dir_path == NULL || dir_path[0] == '\0') {
        return 0;
    }

    dir = opendir(dir_path);
    if (dir == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char full_path[SPECTERIDS_PATH_LEN];
        char error[160];
        int written;

        if (!has_shared_object_suffix(entry->d_name)) {
            continue;
        }

        written = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        if (written <= 0 || (size_t)written >= sizeof(full_path)) {
            continue;
        }
        if (detection_load_plugin(engine, full_path, error, sizeof(error)) == 0) {
            loaded++;
        } else {
            fprintf(stderr, "Warning: failed to load plugin '%s': %s\n", full_path, error);
        }
    }

    closedir(dir);
    return loaded;
}

size_t detection_plugin_count(detection_engine_t *engine)
{
    size_t count;

    if (engine == NULL) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    count = engine->plugin_count;
    pthread_mutex_unlock(&engine->plugin_lock);
    return count;
}

uint64_t detection_plugin_packets(detection_engine_t *engine)
{
    uint64_t packets;

    if (engine == NULL) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    packets = engine->plugin_packets;
    pthread_mutex_unlock(&engine->plugin_lock);
    return packets;
}

uint64_t detection_plugin_alerts(detection_engine_t *engine)
{
    uint64_t alerts;

    if (engine == NULL) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    alerts = engine->plugin_alerts;
    pthread_mutex_unlock(&engine->plugin_lock);
    return alerts;
}

uint64_t detection_plugin_errors(detection_engine_t *engine)
{
    uint64_t errors;

    if (engine == NULL) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    errors = engine->plugin_errors;
    pthread_mutex_unlock(&engine->plugin_lock);
    return errors;
}

uint64_t detection_plugin_latency_ns(detection_engine_t *engine)
{
    uint64_t latency_ns;

    if (engine == NULL) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    latency_ns = engine->plugin_latency_ns;
    pthread_mutex_unlock(&engine->plugin_lock);
    return latency_ns;
}

double detection_shard_pressure(detection_engine_t *engine)
{
    size_t i;
    size_t max_sources = 0;
    size_t total_sources = 0;

    if (engine == NULL || engine->shards == NULL || engine->shard_count == 0) {
        return 0.0;
    }

    for (i = 0; i < engine->shard_count; i++) {
        size_t source_count;

        pthread_mutex_lock(&engine->shards[i].lock);
        source_count = engine->shards[i].source_count;
        pthread_mutex_unlock(&engine->shards[i].lock);
        total_sources += source_count;
        if (source_count > max_sources) {
            max_sources = source_count;
        }
    }

    if (total_sources == 0) {
        return 0.0;
    }
    return (double)max_sources / ((double)total_sources / (double)engine->shard_count);
}

uint64_t detection_shard_evictions(detection_engine_t *engine)
{
    size_t i;
    uint64_t total = 0;

    if (engine == NULL || engine->shards == NULL || engine->shard_count == 0) {
        return 0;
    }

    for (i = 0; i < engine->shard_count; i++) {
        pthread_mutex_lock(&engine->shards[i].lock);
        total += engine->shards[i].eviction_count;
        pthread_mutex_unlock(&engine->shards[i].lock);
    }

    return total;
}

size_t detection_source_memory_bytes(detection_engine_t *engine)
{
    size_t i;
    size_t total_sources = 0;

    if (engine == NULL || engine->shards == NULL || engine->shard_count == 0) {
        return 0;
    }

    for (i = 0; i < engine->shard_count; i++) {
        pthread_mutex_lock(&engine->shards[i].lock);
        total_sources += engine->shards[i].source_count;
        pthread_mutex_unlock(&engine->shards[i].lock);
    }

    return total_sources * sizeof(source_state_t);
}

void detection_destroy(detection_engine_t *engine)
{
    size_t i;

    if (engine == NULL) {
        return;
    }

    for (i = 0; i < engine->plugin_count; i++) {
        if (engine->plugins[i].descriptor != NULL) {
            if (engine->plugins[i].descriptor->stop != NULL) {
                engine->plugins[i].descriptor->stop(engine->plugins[i].state);
            }
            if (engine->plugins[i].descriptor->unload != NULL) {
                engine->plugins[i].descriptor->unload(engine->plugins[i].state);
            }
        }
        if (engine->plugins[i].handle != NULL) {
            dlclose(engine->plugins[i].handle);
        }
        pthread_mutex_destroy(&engine->plugins[i].lock);
    }

    for (i = 0; i < engine->shard_count; i++) {
        size_t bucket;

        for (bucket = 0; bucket < SOURCE_BUCKETS; bucket++) {
            source_state_t *current = engine->shards[i].buckets[bucket];

            while (current != NULL) {
                source_state_t *next = current->next;
                free(current);
                current = next;
            }
        }
        pthread_mutex_destroy(&engine->shards[i].lock);
    }

    pthread_mutex_destroy(&engine->plugin_lock);
    pthread_mutex_destroy(&engine->rules_lock);
    free(engine->shards);
    free(engine);
}

static void detect_port_scan(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t unique_ports;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->port_scan.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    unique_ports = add_port_event(state,
                                  packet->dst_port,
                                  packet->timestamp.tv_sec,
                                  rules->port_scan.window_seconds);

    if (unique_ports <= (size_t)rules->port_scan.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_PORT_SCAN,
                           packet->timestamp.tv_sec,
                           rules->port_scan.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accessed more than %d ports in %d seconds",
             rules->port_scan.threshold,
             rules->port_scan.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_PORT_SCAN,
                     rules->port_scan.severity,
                     packet,
                     reason);
}

static void detect_ssh_bruteforce(const ids_rule_set_t *rules,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    size_t attempts;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->ssh_bruteforce.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack ||
        packet->dst_port != (uint16_t)rules->ssh_bruteforce.port) {
        return;
    }

    attempts = add_time_event(state->ssh_events,
                              &state->ssh_event_count,
                              MAX_TIMED_EVENTS,
                              packet->timestamp.tv_sec,
                              rules->ssh_bruteforce.window_seconds);

    if (attempts <= (size_t)rules->ssh_bruteforce.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SSH_BRUTE_FORCE,
                           packet->timestamp.tv_sec,
                           rules->ssh_bruteforce.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source opened more than %d TCP connections to port %d in %d seconds",
             rules->ssh_bruteforce.threshold,
             rules->ssh_bruteforce.port,
             rules->ssh_bruteforce.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_SSH_BRUTE_FORCE,
                     rules->ssh_bruteforce.severity,
                     packet,
                     reason);
}

static void detect_syn_flood(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t syn_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->syn_flood.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    syn_count = add_time_event(state->syn_events,
                               &state->syn_event_count,
                               MAX_TIMED_EVENTS,
                               packet->timestamp.tv_sec,
                               rules->syn_flood.window_seconds);

    if (syn_count <= (size_t)rules->syn_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SYN_FLOOD,
                           packet->timestamp.tv_sec,
                           rules->syn_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d TCP SYN packets in %d seconds",
             rules->syn_flood.threshold,
             rules->syn_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_SYN_FLOOD,
                     rules->syn_flood.severity,
                     packet,
                     reason);
}

static void detect_icmp_flood(const ids_rule_set_t *rules,
                              source_state_t *state,
                              const packet_info_t *packet,
                              alert_t *alerts,
                              size_t *alert_count,
                              size_t max_alerts)
{
    size_t icmp_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->icmp_flood.enabled ||
        (packet->protocol != PACKET_PROTO_ICMP && packet->protocol != PACKET_PROTO_ICMPV6)) {
        return;
    }

    icmp_count = add_time_event(state->icmp_events,
                                &state->icmp_event_count,
                                MAX_TIMED_EVENTS,
                                packet->timestamp.tv_sec,
                                rules->icmp_flood.window_seconds);

    if (icmp_count <= (size_t)rules->icmp_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_ICMP_FLOOD,
                           packet->timestamp.tv_sec,
                           rules->icmp_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d ICMP packets in %d seconds",
             rules->icmp_flood.threshold,
             rules->icmp_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_ICMP_FLOOD,
                     rules->icmp_flood.severity,
                     packet,
                     reason);
}

static void detect_udp_flood(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t udp_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->udp_flood.enabled || packet->protocol != PACKET_PROTO_UDP) {
        return;
    }

    udp_count = add_time_event(state->udp_events,
                               &state->udp_event_count,
                               MAX_TIMED_EVENTS,
                               packet->timestamp.tv_sec,
                               rules->udp_flood.window_seconds);

    if (udp_count <= (size_t)rules->udp_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_UDP_FLOOD,
                           packet->timestamp.tv_sec,
                           rules->udp_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d UDP packets in %d seconds",
             rules->udp_flood.threshold,
             rules->udp_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_UDP_FLOOD,
                     rules->udp_flood.severity,
                     packet,
                     reason);
}

static void detect_beaconing(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t hits;
    char reason[SPECTERIDS_REASON_LEN];

    double average_interval = 0.0;

    if (!rules->beaconing.enabled || !is_connection_candidate(packet)) {
        return;
    }

    if (rules->beaconing.ignore_private && is_private_or_local_ip(packet->dst_ip)) {
        return;
    }

    if (ip_in_csv(rules->beaconing.whitelist, packet->dst_ip)) {
        return;
    }

    add_beacon_event(state, packet, &rules->beaconing);
    hits = count_regular_beacon_hits(state, packet, &rules->beaconing, &average_interval);

    if (hits < (size_t)rules->beaconing.min_hits ||
        !should_emit_alert(state,
                           ALERT_TYPE_BEACONING,
                           packet->timestamp.tv_sec,
                           rules->beaconing.interval_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source repeated src->dst at average %.1f second intervals (%zu occurrences, tolerance %d seconds)",
             average_interval,
             hits,
             rules->beaconing.tolerance_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_BEACONING,
                     rules->beaconing.severity,
                     packet,
                     reason);
}

/*
 * ARP binding hash table — open addressing with linear probing.
 * ARP_HASH_SIZE is a power of 2 so (hash & mask) replaces modulo.
 * Hard cap at ARP_HASH_SIZE/2 slots (50% load factor) keeps probe sequences short.
 */
static arp_binding_t *arp_find(detection_shard_t *shard, const char *ip)
{
    uint64_t hash = hash_source_ip(ip);
    size_t slot = hash & (ARP_HASH_SIZE - 1U);
    size_t i;

    for (i = 0; i < ARP_HASH_SIZE; i++) {
        size_t s = (slot + i) & (ARP_HASH_SIZE - 1U);

        if (!shard->arp_table[s].occupied) {
            return NULL;
        }
        if (strcmp(shard->arp_table[s].ip, ip) == 0) {
            return &shard->arp_table[s];
        }
    }

    return NULL;
}

static arp_binding_t *arp_insert(detection_shard_t *shard, const char *ip, const char *mac, time_t ts)
{
    uint64_t hash = hash_source_ip(ip);
    size_t slot = hash & (ARP_HASH_SIZE - 1U);
    size_t i;

    if (shard->arp_table_used >= ARP_HASH_SIZE / 2U) {
        return NULL;
    }

    for (i = 0; i < ARP_HASH_SIZE; i++) {
        size_t s = (slot + i) & (ARP_HASH_SIZE - 1U);

        if (!shard->arp_table[s].occupied) {
            ids_copy_string(shard->arp_table[s].ip, sizeof(shard->arp_table[s].ip), ip);
            ids_copy_string(shard->arp_table[s].mac, sizeof(shard->arp_table[s].mac), mac);
            shard->arp_table[s].last_seen = ts;
            shard->arp_table[s].occupied = true;
            shard->arp_table_used++;
            return &shard->arp_table[s];
        }
    }

    return NULL;
}

static bool port_in_list(const uint16_t *ports, size_t count, uint16_t port)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (ports[i] == port) {
            return true;
        }
    }

    return false;
}

static void detect_arp_spoofing(detection_shard_t *shard,
                                const ids_rule_set_t *rules,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    arp_binding_t *binding;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->arp_spoofing.enabled || packet->protocol != PACKET_PROTO_ARP ||
        packet->arp_sender_ip[0] == '\0' || packet->arp_sender_mac[0] == '\0') {
        return;
    }

    binding = arp_find(shard, packet->arp_sender_ip);
    if (binding != NULL) {
        if (strcmp(binding->mac, packet->arp_sender_mac) != 0 &&
            should_emit_alert(state, ALERT_TYPE_ARP_SPOOFING, packet->timestamp.tv_sec, 60)) {
            snprintf(reason,
                     sizeof(reason),
                     "ARP sender IP %s changed MAC from %s to %s",
                     packet->arp_sender_ip,
                     binding->mac,
                     packet->arp_sender_mac);
            ids_copy_string(binding->mac, sizeof(binding->mac), packet->arp_sender_mac);
            binding->last_seen = packet->timestamp.tv_sec;
            (void)emit_alert(state,
                             alerts,
                             alert_count,
                             max_alerts,
                             ALERT_TYPE_ARP_SPOOFING,
                             rules->arp_spoofing.severity,
                             packet,
                             reason);
        }
        binding->last_seen = packet->timestamp.tv_sec;
        return;
    }

    (void)arp_insert(shard, packet->arp_sender_ip, packet->arp_sender_mac, packet->timestamp.tv_sec);
}

static void detect_dns_flood(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->dns_flood.enabled || !packet->dns) {
        return;
    }

    count = add_time_event(state->dns_events,
                           &state->dns_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           rules->dns_flood.window_seconds);
    if (count <= (size_t)rules->dns_flood.threshold ||
        !should_emit_alert(state, ALERT_TYPE_DNS_FLOOD, packet->timestamp.tv_sec, rules->dns_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d DNS packets in %d seconds",
             rules->dns_flood.threshold,
             rules->dns_flood.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_DNS_FLOOD, rules->dns_flood.severity, packet, reason);
}

static void detect_http_flood(const ids_rule_set_t *rules,
                              source_state_t *state,
                              const packet_info_t *packet,
                              alert_t *alerts,
                              size_t *alert_count,
                              size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->http_flood.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !port_in_list(rules->http_flood.ports, rules->http_flood.port_count, packet->dst_port)) {
        return;
    }

    count = add_time_event(state->http_events,
                           &state->http_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           rules->http_flood.window_seconds);
    if (count <= (size_t)rules->http_flood.threshold ||
        !should_emit_alert(state, ALERT_TYPE_HTTP_FLOOD, packet->timestamp.tv_sec, rules->http_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d HTTP-family packets in %d seconds",
             rules->http_flood.threshold,
             rules->http_flood.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_HTTP_FLOOD, rules->http_flood.severity, packet, reason);
}

static void detect_rate_anomaly(const ids_rule_set_t *rules,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->rate_anomaly.enabled) {
        return;
    }

    count = add_time_event(state->all_packet_events,
                           &state->all_packet_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           rules->rate_anomaly.window_seconds);
    if (count <= (size_t)rules->rate_anomaly.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_RATE_ANOMALY,
                           packet->timestamp.tv_sec,
                           rules->rate_anomaly.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source exceeded %d packets in %d seconds",
             rules->rate_anomaly.threshold,
             rules->rate_anomaly.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_RATE_ANOMALY, rules->rate_anomaly.severity, packet, reason);
}

static void detect_slow_scan(const ids_rule_set_t *rules,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t unique_ports;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->slow_scan.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    unique_ports = add_slow_port_event(state,
                                       packet->dst_port,
                                       packet->timestamp.tv_sec,
                                       rules->slow_scan.window_seconds);
    if (unique_ports <= (size_t)rules->slow_scan.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SLOW_SCAN,
                           packet->timestamp.tv_sec,
                           rules->slow_scan.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source touched more than %d ports slowly over %d seconds",
             rules->slow_scan.threshold,
             rules->slow_scan.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_SLOW_SCAN, rules->slow_scan.severity, packet, reason);
}

static void detect_sensitive_port(const ids_rule_set_t *rules,
                                  const uint16_t *sensitive_ports,
                                  size_t sensitive_port_count,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->sensitive_port.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack ||
        !(port_in_list(sensitive_ports, sensitive_port_count, packet->dst_port) ||
          port_in_list(rules->sensitive_port.ports, rules->sensitive_port.port_count, packet->dst_port)) ||
        !should_emit_alert(state,
                           ALERT_TYPE_SENSITIVE_PORT,
                           packet->timestamp.tv_sec,
                           rules->sensitive_port.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accessed sensitive TCP port %u",
             packet->dst_port);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_SENSITIVE_PORT, rules->sensitive_port.severity, packet, reason);
}

static void detect_connection_excess(const ids_rule_set_t *rules,
                                     source_state_t *state,
                                     const packet_info_t *packet,
                                     alert_t *alerts,
                                     size_t *alert_count,
                                     size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->connection_excess.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    count = add_time_event(state->connection_events,
                           &state->connection_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           rules->connection_excess.window_seconds);
    if (count <= (size_t)rules->connection_excess.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_CONNECTION_EXCESS,
                           packet->timestamp.tv_sec,
                           rules->connection_excess.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source opened more than %d TCP connection attempts in %d seconds",
             rules->connection_excess.threshold,
             rules->connection_excess.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_CONNECTION_EXCESS, rules->connection_excess.severity, packet, reason);
}

static void detect_large_payload(const ids_rule_set_t *rules,
                                 source_state_t *state,
                                 const packet_info_t *packet,
                                 alert_t *alerts,
                                 size_t *alert_count,
                                 size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->large_payload.enabled ||
        packet->payload_length <= (uint32_t)rules->large_payload.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_LARGE_PAYLOAD,
                           packet->timestamp.tv_sec,
                           rules->large_payload.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent payload larger than %d bytes (%u bytes observed)",
             rules->large_payload.threshold,
             packet->payload_length);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_LARGE_PAYLOAD, rules->large_payload.severity, packet, reason);
}

static void detect_volume_anomaly(const ids_rule_set_t *rules,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    uint64_t bytes;
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->volume_anomaly.enabled) {
        return;
    }

    bytes = add_byte_event(state->byte_events,
                           &state->byte_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           rules->volume_anomaly.window_seconds,
                           packet->length);
    if (bytes <= (uint64_t)rules->volume_anomaly.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_VOLUME_ANOMALY,
                           packet->timestamp.tv_sec,
                           rules->volume_anomaly.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source transferred more than %d bytes in %d seconds",
             rules->volume_anomaly.threshold,
             rules->volume_anomaly.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_VOLUME_ANOMALY, rules->volume_anomaly.severity, packet, reason);
}

static void detect_heuristic_risk(const ids_rule_set_t *rules,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!rules->heuristic_risk.enabled ||
        state->risk_score < rules->heuristic_risk.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_HEURISTIC_RISK,
                           packet->timestamp.tv_sec,
                           rules->heuristic_risk.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accumulated risk score %d",
             state->risk_score);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_HEURISTIC_RISK, rules->heuristic_risk.severity, packet, reason);
}

typedef struct {
    detection_shard_t *shard;
    const ids_rule_set_t *rules;
    const uint16_t *sensitive_ports;
    size_t sensitive_port_count;
} detection_context_t;

typedef void (*detection_stage_fn)(const detection_context_t *context,
                                   source_state_t *state,
                                   const packet_info_t *packet,
                                   alert_t *alerts,
                                   size_t *alert_count,
                                   size_t max_alerts);

typedef struct {
    const char *name;
    alert_type_t primary_alert;
    detection_stage_fn process;
} detection_stage_module_t;

static void module_rate_anomaly(const detection_context_t *context,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    detect_rate_anomaly(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_arp_spoofing(const detection_context_t *context,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    detect_arp_spoofing(context->shard, context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_port_scan(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_port_scan(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_slow_scan(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_slow_scan(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_sensitive_port(const detection_context_t *context,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    detect_sensitive_port(context->rules,
                          context->sensitive_ports,
                          context->sensitive_port_count,
                          state,
                          packet,
                          alerts,
                          alert_count,
                          max_alerts);
}

static void module_connection_excess(const detection_context_t *context,
                                     source_state_t *state,
                                     const packet_info_t *packet,
                                     alert_t *alerts,
                                     size_t *alert_count,
                                     size_t max_alerts)
{
    detect_connection_excess(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_ssh_bruteforce(const detection_context_t *context,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    detect_ssh_bruteforce(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_syn_flood(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_syn_flood(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_icmp_flood(const detection_context_t *context,
                              source_state_t *state,
                              const packet_info_t *packet,
                              alert_t *alerts,
                              size_t *alert_count,
                              size_t max_alerts)
{
    detect_icmp_flood(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_udp_flood(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_udp_flood(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_dns_flood(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_dns_flood(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_http_flood(const detection_context_t *context,
                              source_state_t *state,
                              const packet_info_t *packet,
                              alert_t *alerts,
                              size_t *alert_count,
                              size_t max_alerts)
{
    detect_http_flood(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_large_payload(const detection_context_t *context,
                                 source_state_t *state,
                                 const packet_info_t *packet,
                                 alert_t *alerts,
                                 size_t *alert_count,
                                 size_t max_alerts)
{
    detect_large_payload(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_volume_anomaly(const detection_context_t *context,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    detect_volume_anomaly(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_beaconing(const detection_context_t *context,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    detect_beaconing(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static void module_heuristic_risk(const detection_context_t *context,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    detect_heuristic_risk(context->rules, state, packet, alerts, alert_count, max_alerts);
}

static const detection_stage_module_t DETECTION_MODULES[] = {
    {"rate_anomaly", ALERT_TYPE_RATE_ANOMALY, module_rate_anomaly},
    {"arp_spoofing", ALERT_TYPE_ARP_SPOOFING, module_arp_spoofing},
    {"port_scan", ALERT_TYPE_PORT_SCAN, module_port_scan},
    {"slow_scan", ALERT_TYPE_SLOW_SCAN, module_slow_scan},
    {"sensitive_port", ALERT_TYPE_SENSITIVE_PORT, module_sensitive_port},
    {"connection_excess", ALERT_TYPE_CONNECTION_EXCESS, module_connection_excess},
    {"ssh_bruteforce", ALERT_TYPE_SSH_BRUTE_FORCE, module_ssh_bruteforce},
    {"syn_flood", ALERT_TYPE_SYN_FLOOD, module_syn_flood},
    {"icmp_flood", ALERT_TYPE_ICMP_FLOOD, module_icmp_flood},
    {"udp_flood", ALERT_TYPE_UDP_FLOOD, module_udp_flood},
    {"dns_flood", ALERT_TYPE_DNS_FLOOD, module_dns_flood},
    {"http_flood", ALERT_TYPE_HTTP_FLOOD, module_http_flood},
    {"large_payload", ALERT_TYPE_LARGE_PAYLOAD, module_large_payload},
    {"volume_anomaly", ALERT_TYPE_VOLUME_ANOMALY, module_volume_anomaly},
    {"beaconing", ALERT_TYPE_BEACONING, module_beaconing},
    {"heuristic_risk", ALERT_TYPE_HEURISTIC_RISK, module_heuristic_risk}
};

size_t detection_builtin_module_count(void)
{
    return sizeof(DETECTION_MODULES) / sizeof(DETECTION_MODULES[0]);
}

const char *detection_builtin_module_name(size_t index)
{
    if (index >= detection_builtin_module_count()) {
        return NULL;
    }
    return DETECTION_MODULES[index].name;
}

static size_t process_dynamic_plugins(detection_engine_t *engine,
                                      const packet_info_t *packet,
                                      alert_t *alerts,
                                      size_t max_alerts)
{
    size_t alert_count = 0;
    size_t plugin_count;
    size_t i;

    if (engine == NULL || packet == NULL || alerts == NULL || max_alerts == 0) {
        return 0;
    }

    pthread_mutex_lock(&engine->plugin_lock);
    plugin_count = engine->plugin_count;
    pthread_mutex_unlock(&engine->plugin_lock);

    for (i = 0; i < plugin_count && alert_count < max_alerts; i++) {
        dynamic_plugin_t *plugin = &engine->plugins[i];
        size_t remaining = max_alerts - alert_count;
        uint64_t started_ns = 0;
        uint64_t latency_delta_ns = 0;
        uint64_t error_delta = 0;
        size_t produced = 0;

        pthread_mutex_lock(&plugin->lock);
        if ((plugin->descriptor->capabilities & SPECTERIDS_PLUGIN_CAP_PACKET) != 0U &&
            plugin->descriptor->packet_handler != NULL) {
            struct timespec ts;

            if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
                started_ns = ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
            }
            produced = plugin->descriptor->packet_handler(plugin->state,
                                                          packet,
                                                          alerts + alert_count,
                                                          remaining);
            if (started_ns != 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
                    uint64_t finished_ns =
                        ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
                    if (finished_ns >= started_ns) {
                        latency_delta_ns = finished_ns - started_ns;
                    }
                }
            }
        }

        if (produced > remaining) {
            produced = remaining;
            error_delta++;
        }
        plugin->packets++;
        plugin->alerts += produced;
        plugin->errors += error_delta;
        plugin->latency_ns += latency_delta_ns;
        if ((plugin->descriptor->capabilities & SPECTERIDS_PLUGIN_CAP_ALERT) != 0U &&
            plugin->descriptor->alert_handler != NULL) {
            size_t alert_index;

            for (alert_index = 0; alert_index < produced; alert_index++) {
                plugin->descriptor->alert_handler(plugin->state, &alerts[alert_count + alert_index]);
            }
        }
        pthread_mutex_unlock(&plugin->lock);

        pthread_mutex_lock(&engine->plugin_lock);
        engine->plugin_packets++;
        engine->plugin_alerts += produced;
        engine->plugin_errors += error_delta;
        engine->plugin_latency_ns += latency_delta_ns;
        pthread_mutex_unlock(&engine->plugin_lock);
        alert_count += produced;
    }
    return alert_count;
}

size_t detection_process_packet(detection_engine_t *engine,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t max_alerts)
{
    detection_shard_t *shard;
    source_state_t *state;
    ids_rule_set_t rules;
    uint16_t sensitive_ports[SPECTERIDS_MAX_SENSITIVE_PORTS];
    size_t sensitive_port_count;
    detection_context_t context;
    size_t alert_count = 0;
    size_t i;

    if (engine == NULL || packet == NULL || alerts == NULL || max_alerts == 0) {
        return 0;
    }

    pthread_mutex_lock(&engine->rules_lock);
    (void)rules_select_for_destination(&engine->rules, packet->dst_ip, &rules, NULL, 0);
    sensitive_port_count = engine->sensitive_port_count;
    if (sensitive_port_count > SPECTERIDS_MAX_SENSITIVE_PORTS) {
        sensitive_port_count = SPECTERIDS_MAX_SENSITIVE_PORTS;
    }
    memcpy(sensitive_ports, engine->sensitive_ports, sensitive_port_count * sizeof(sensitive_ports[0]));
    pthread_mutex_unlock(&engine->rules_lock);

    shard = select_shard(engine, packet->src_ip);
    if (shard == NULL) {
        return 0;
    }

    pthread_mutex_lock(&shard->lock);
    state = get_or_create_source(shard, packet->src_ip);
    if (state == NULL) {
        pthread_mutex_unlock(&shard->lock);
        return 0;
    }

    decay_risk(state, packet->timestamp.tv_sec);
    state->last_packet_at = packet->timestamp.tv_sec;
    context = (detection_context_t){
        .shard = shard,
        .rules = &rules,
        .sensitive_ports = sensitive_ports,
        .sensitive_port_count = sensitive_port_count
    };
    for (i = 0; i < detection_builtin_module_count(); i++) {
        DETECTION_MODULES[i].process(&context, state, packet, alerts, &alert_count, max_alerts);
        if (alert_count >= max_alerts) {
            break;
        }
    }

    pthread_mutex_unlock(&shard->lock);
    if (alert_count < max_alerts) {
        alert_count += process_dynamic_plugins(engine,
                                               packet,
                                               alerts + alert_count,
                                               max_alerts - alert_count);
    }
    return alert_count;
}

const char *detection_alert_type_name(alert_type_t type)
{
    switch (type) {
    case ALERT_TYPE_PORT_SCAN:
        return "PORT_SCAN";
    case ALERT_TYPE_SSH_BRUTE_FORCE:
        return "SSH_BRUTE_FORCE";
    case ALERT_TYPE_SYN_FLOOD:
        return "SYN_FLOOD";
    case ALERT_TYPE_ICMP_FLOOD:
        return "ICMP_FLOOD";
    case ALERT_TYPE_UDP_FLOOD:
        return "UDP_FLOOD";
    case ALERT_TYPE_BEACONING:
        return "BEACONING";
    case ALERT_TYPE_ARP_SPOOFING:
        return "ARP_SPOOFING";
    case ALERT_TYPE_DNS_FLOOD:
        return "DNS_FLOOD";
    case ALERT_TYPE_HTTP_FLOOD:
        return "HTTP_FLOOD";
    case ALERT_TYPE_RATE_ANOMALY:
        return "RATE_ANOMALY";
    case ALERT_TYPE_SLOW_SCAN:
        return "SLOW_SCAN";
    case ALERT_TYPE_SENSITIVE_PORT:
        return "SENSITIVE_PORT";
    case ALERT_TYPE_CONNECTION_EXCESS:
        return "CONNECTION_EXCESS";
    case ALERT_TYPE_LARGE_PAYLOAD:
        return "LARGE_PAYLOAD";
    case ALERT_TYPE_VOLUME_ANOMALY:
        return "VOLUME_ANOMALY";
    case ALERT_TYPE_HEURISTIC_RISK:
        return "HEURISTIC_RISK";
    case ALERT_TYPE_THREAT_CORRELATION:
        return "THREAT_CORRELATION";
    case ALERT_TYPE_COUNT:
    default:
        return "UNKNOWN";
    }
}

const char *detection_severity_name(ids_severity_t severity)
{
    return ids_severity_name(severity);
}
