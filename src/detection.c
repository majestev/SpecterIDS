#include "detection.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TRACKED_SOURCES 2048U
#define MAX_PORT_EVENTS 512U
#define MAX_TIMED_EVENTS 1024U
#define MAX_BEACON_EVENTS 512U
#define MAX_ARP_BINDINGS 4096U
#define RISK_LOW_POINTS 5
#define RISK_MEDIUM_POINTS 15
#define RISK_HIGH_POINTS 30
#define RISK_CRITICAL_POINTS 50

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
    port_event_t slow_port_events[MAX_PORT_EVENTS];
    size_t slow_port_event_count;
    byte_event_t byte_events[MAX_TIMED_EVENTS];
    size_t byte_event_count;
    beacon_event_t beacon_events[MAX_BEACON_EVENTS];
    size_t beacon_event_count;
    time_t last_alert_at[ALERT_TYPE_COUNT];
    int risk_score;
    time_t last_risk_decay_at;
    struct source_state *next;
} source_state_t;

typedef struct {
    char ip[SPECTERIDS_IP_STR_LEN];
    char mac[SPECTERIDS_MAC_STR_LEN];
    time_t last_seen;
} arp_binding_t;

struct detection_engine {
    ids_rules_t rules;
    source_state_t *sources;
    size_t source_count;
    arp_binding_t arp_bindings[MAX_ARP_BINDINGS];
    size_t arp_binding_count;
    uint16_t sensitive_ports[SPECTERIDS_MAX_SENSITIVE_PORTS];
    size_t sensitive_port_count;
    pthread_mutex_t lock;
};

static source_state_t *find_source(detection_engine_t *engine, const char *source_ip)
{
    source_state_t *current = engine->sources;

    while (current != NULL) {
        if (strcmp(current->source_ip, source_ip) == 0) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

static source_state_t *get_or_create_source(detection_engine_t *engine, const char *source_ip)
{
    source_state_t *state = find_source(engine, source_ip);

    if (state != NULL) {
        return state;
    }

    if (engine->source_count >= MAX_TRACKED_SOURCES) {
        return NULL;
    }

    state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return NULL;
    }

    ids_copy_string(state->source_ip, sizeof(state->source_ip), source_ip);
    state->next = engine->sources;
    engine->sources = state;
    engine->source_count++;

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
    size_t unique_count = 0;
    size_t i;

    for (i = 0; i < count; i++) {
        bool seen = false;
        size_t j;

        for (j = 0; j < i; j++) {
            if (events[j].destination_port == events[i].destination_port) {
                seen = true;
                break;
            }
        }

        if (!seen) {
            unique_count++;
        }
    }

    return unique_count;
}

static size_t add_port_event(source_state_t *state,
                             uint16_t destination_port,
                             time_t now,
                             int window_seconds)
{
    prune_port_events(state->port_events, &state->port_event_count, now, window_seconds);

    if (state->port_event_count >= MAX_PORT_EVENTS) {
        memmove(state->port_events,
                state->port_events + 1,
                (MAX_PORT_EVENTS - 1) * sizeof(state->port_events[0]));
        state->port_event_count = MAX_PORT_EVENTS - 1;
    }

    state->port_events[state->port_event_count].timestamp = now;
    state->port_events[state->port_event_count].destination_port = destination_port;
    state->port_event_count++;

    return count_unique_ports(state->port_events, state->port_event_count);
}

static size_t add_slow_port_event(source_state_t *state,
                                  uint16_t destination_port,
                                  time_t now,
                                  int window_seconds)
{
    prune_port_events(state->slow_port_events, &state->slow_port_event_count, now, window_seconds);

    if (state->slow_port_event_count >= MAX_PORT_EVENTS) {
        memmove(state->slow_port_events,
                state->slow_port_events + 1,
                (MAX_PORT_EVENTS - 1) * sizeof(state->slow_port_events[0]));
        state->slow_port_event_count = MAX_PORT_EVENTS - 1;
    }

    state->slow_port_events[state->slow_port_event_count].timestamp = now;
    state->slow_port_events[state->slow_port_event_count].destination_port = destination_port;
    state->slow_port_event_count++;

    return count_unique_ports(state->slow_port_events, state->slow_port_event_count);
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
    if (elapsed < 60) {
        return;
    }

    decay = (int)(elapsed / 60) * 5;
    state->risk_score = state->risk_score > decay ? state->risk_score - decay : 0;
    state->last_risk_decay_at = now;
}

static ids_severity_t dynamic_severity(ids_severity_t base, int risk_score)
{
    if (risk_score >= 120) {
        return IDS_SEVERITY_CRITICAL;
    }
    if (risk_score >= 80 && base < IDS_SEVERITY_HIGH) {
        return IDS_SEVERITY_HIGH;
    }
    if (risk_score >= 50 && base < IDS_SEVERITY_MEDIUM) {
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
    if (state->risk_score > 200) {
        state->risk_score = 200;
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

static size_t count_regular_beacon_hits(const source_state_t *state,
                                        const packet_info_t *packet,
                                        const rule_config_t *rule)
{
    time_t reversed[MAX_BEACON_EVENTS];
    size_t reversed_count = 0;
    size_t i;
    size_t regular_hits = 1;

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
        } else {
            break;
        }
    }

    return regular_hits;
}

detection_engine_t *detection_create(const ids_rules_t *rules)
{
    detection_engine_t *engine = calloc(1, sizeof(*engine));

    if (engine == NULL) {
        return NULL;
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

    if (pthread_mutex_init(&engine->lock, NULL) != 0) {
        free(engine);
        return NULL;
    }

    return engine;
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

    pthread_mutex_lock(&engine->lock);
    for (i = 0; i < count; i++) {
        engine->sensitive_ports[i] = ports[i];
    }
    engine->sensitive_port_count = count;
    pthread_mutex_unlock(&engine->lock);
}

void detection_update_rules(detection_engine_t *engine, const ids_rules_t *rules)
{
    if (engine == NULL || rules == NULL) {
        return;
    }

    pthread_mutex_lock(&engine->lock);
    engine->rules = *rules;
    pthread_mutex_unlock(&engine->lock);
}

void detection_destroy(detection_engine_t *engine)
{
    source_state_t *current;

    if (engine == NULL) {
        return;
    }

    current = engine->sources;
    while (current != NULL) {
        source_state_t *next = current->next;
        free(current);
        current = next;
    }

    pthread_mutex_destroy(&engine->lock);
    free(engine);
}

static void detect_port_scan(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t unique_ports;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.port_scan.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    unique_ports = add_port_event(state,
                                  packet->dst_port,
                                  packet->timestamp.tv_sec,
                                  engine->rules.port_scan.window_seconds);

    if (unique_ports <= (size_t)engine->rules.port_scan.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_PORT_SCAN,
                           packet->timestamp.tv_sec,
                           engine->rules.port_scan.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accessed more than %d ports in %d seconds",
             engine->rules.port_scan.threshold,
             engine->rules.port_scan.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_PORT_SCAN,
                     engine->rules.port_scan.severity,
                     packet,
                     reason);
}

static void detect_ssh_bruteforce(detection_engine_t *engine,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    size_t attempts;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.ssh_bruteforce.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack ||
        packet->dst_port != (uint16_t)engine->rules.ssh_bruteforce.port) {
        return;
    }

    attempts = add_time_event(state->ssh_events,
                              &state->ssh_event_count,
                              MAX_TIMED_EVENTS,
                              packet->timestamp.tv_sec,
                              engine->rules.ssh_bruteforce.window_seconds);

    if (attempts <= (size_t)engine->rules.ssh_bruteforce.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SSH_BRUTE_FORCE,
                           packet->timestamp.tv_sec,
                           engine->rules.ssh_bruteforce.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source opened more than %d TCP connections to port %d in %d seconds",
             engine->rules.ssh_bruteforce.threshold,
             engine->rules.ssh_bruteforce.port,
             engine->rules.ssh_bruteforce.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_SSH_BRUTE_FORCE,
                     engine->rules.ssh_bruteforce.severity,
                     packet,
                     reason);
}

static void detect_syn_flood(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t syn_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.syn_flood.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    syn_count = add_time_event(state->syn_events,
                               &state->syn_event_count,
                               MAX_TIMED_EVENTS,
                               packet->timestamp.tv_sec,
                               engine->rules.syn_flood.window_seconds);

    if (syn_count <= (size_t)engine->rules.syn_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SYN_FLOOD,
                           packet->timestamp.tv_sec,
                           engine->rules.syn_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d TCP SYN packets in %d seconds",
             engine->rules.syn_flood.threshold,
             engine->rules.syn_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_SYN_FLOOD,
                     engine->rules.syn_flood.severity,
                     packet,
                     reason);
}

static void detect_icmp_flood(detection_engine_t *engine,
                              source_state_t *state,
                              const packet_info_t *packet,
                              alert_t *alerts,
                              size_t *alert_count,
                              size_t max_alerts)
{
    size_t icmp_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.icmp_flood.enabled || packet->protocol != PACKET_PROTO_ICMP) {
        return;
    }

    icmp_count = add_time_event(state->icmp_events,
                                &state->icmp_event_count,
                                MAX_TIMED_EVENTS,
                                packet->timestamp.tv_sec,
                                engine->rules.icmp_flood.window_seconds);

    if (icmp_count <= (size_t)engine->rules.icmp_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_ICMP_FLOOD,
                           packet->timestamp.tv_sec,
                           engine->rules.icmp_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d ICMP packets in %d seconds",
             engine->rules.icmp_flood.threshold,
             engine->rules.icmp_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_ICMP_FLOOD,
                     engine->rules.icmp_flood.severity,
                     packet,
                     reason);
}

static void detect_udp_flood(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t udp_count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.udp_flood.enabled || packet->protocol != PACKET_PROTO_UDP) {
        return;
    }

    udp_count = add_time_event(state->udp_events,
                               &state->udp_event_count,
                               MAX_TIMED_EVENTS,
                               packet->timestamp.tv_sec,
                               engine->rules.udp_flood.window_seconds);

    if (udp_count <= (size_t)engine->rules.udp_flood.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_UDP_FLOOD,
                           packet->timestamp.tv_sec,
                           engine->rules.udp_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d UDP packets in %d seconds",
             engine->rules.udp_flood.threshold,
             engine->rules.udp_flood.window_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_UDP_FLOOD,
                     engine->rules.udp_flood.severity,
                     packet,
                     reason);
}

static void detect_beaconing(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t hits;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.beaconing.enabled || !is_connection_candidate(packet)) {
        return;
    }

    add_beacon_event(state, packet, &engine->rules.beaconing);
    hits = count_regular_beacon_hits(state, packet, &engine->rules.beaconing);

    if (hits < (size_t)engine->rules.beaconing.min_hits ||
        !should_emit_alert(state,
                           ALERT_TYPE_BEACONING,
                           packet->timestamp.tv_sec,
                           engine->rules.beaconing.interval_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source contacted the same destination at about %d second intervals (%d hits, tolerance %d seconds)",
             engine->rules.beaconing.interval_seconds,
             engine->rules.beaconing.min_hits,
             engine->rules.beaconing.tolerance_seconds);
    (void)emit_alert(state,
                     alerts,
                     alert_count,
                     max_alerts,
                     ALERT_TYPE_BEACONING,
                     engine->rules.beaconing.severity,
                     packet,
                     reason);
}

static bool is_sensitive_port(const detection_engine_t *engine, uint16_t port)
{
    size_t i;

    for (i = 0; i < engine->sensitive_port_count; i++) {
        if (engine->sensitive_ports[i] == port) {
            return true;
        }
    }

    return false;
}

static void detect_arp_spoofing(detection_engine_t *engine,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    size_t i;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.arp_spoofing.enabled || packet->protocol != PACKET_PROTO_ARP ||
        packet->arp_sender_ip[0] == '\0' || packet->arp_sender_mac[0] == '\0') {
        return;
    }

    for (i = 0; i < engine->arp_binding_count; i++) {
        if (strcmp(engine->arp_bindings[i].ip, packet->arp_sender_ip) == 0) {
            if (strcmp(engine->arp_bindings[i].mac, packet->arp_sender_mac) != 0 &&
                should_emit_alert(state,
                                  ALERT_TYPE_ARP_SPOOFING,
                                  packet->timestamp.tv_sec,
                                  60)) {
                snprintf(reason,
                         sizeof(reason),
                         "ARP sender IP %s changed MAC from %s to %s",
                         packet->arp_sender_ip,
                         engine->arp_bindings[i].mac,
                         packet->arp_sender_mac);
                ids_copy_string(engine->arp_bindings[i].mac,
                                sizeof(engine->arp_bindings[i].mac),
                                packet->arp_sender_mac);
                engine->arp_bindings[i].last_seen = packet->timestamp.tv_sec;
                (void)emit_alert(state,
                                 alerts,
                                 alert_count,
                                 max_alerts,
                                 ALERT_TYPE_ARP_SPOOFING,
                                 engine->rules.arp_spoofing.severity,
                                 packet,
                                 reason);
            }
            engine->arp_bindings[i].last_seen = packet->timestamp.tv_sec;
            return;
        }
    }

    if (engine->arp_binding_count < MAX_ARP_BINDINGS) {
        ids_copy_string(engine->arp_bindings[engine->arp_binding_count].ip,
                        sizeof(engine->arp_bindings[engine->arp_binding_count].ip),
                        packet->arp_sender_ip);
        ids_copy_string(engine->arp_bindings[engine->arp_binding_count].mac,
                        sizeof(engine->arp_bindings[engine->arp_binding_count].mac),
                        packet->arp_sender_mac);
        engine->arp_bindings[engine->arp_binding_count].last_seen = packet->timestamp.tv_sec;
        engine->arp_binding_count++;
    }
}

static void detect_dns_flood(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.dns_flood.enabled || !packet->dns) {
        return;
    }

    count = add_time_event(state->dns_events,
                           &state->dns_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           engine->rules.dns_flood.window_seconds);
    if (count <= (size_t)engine->rules.dns_flood.threshold ||
        !should_emit_alert(state, ALERT_TYPE_DNS_FLOOD, packet->timestamp.tv_sec, engine->rules.dns_flood.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent more than %d DNS packets in %d seconds",
             engine->rules.dns_flood.threshold,
             engine->rules.dns_flood.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_DNS_FLOOD, engine->rules.dns_flood.severity, packet, reason);
}

static void detect_rate_anomaly(detection_engine_t *engine,
                                source_state_t *state,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t *alert_count,
                                size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.rate_anomaly.enabled) {
        return;
    }

    count = add_time_event(state->all_packet_events,
                           &state->all_packet_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           engine->rules.rate_anomaly.window_seconds);
    if (count <= (size_t)engine->rules.rate_anomaly.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_RATE_ANOMALY,
                           packet->timestamp.tv_sec,
                           engine->rules.rate_anomaly.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source exceeded %d packets in %d seconds",
             engine->rules.rate_anomaly.threshold,
             engine->rules.rate_anomaly.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_RATE_ANOMALY, engine->rules.rate_anomaly.severity, packet, reason);
}

static void detect_slow_scan(detection_engine_t *engine,
                             source_state_t *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t *alert_count,
                             size_t max_alerts)
{
    size_t unique_ports;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.slow_scan.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    unique_ports = add_slow_port_event(state,
                                       packet->dst_port,
                                       packet->timestamp.tv_sec,
                                       engine->rules.slow_scan.window_seconds);
    if (unique_ports <= (size_t)engine->rules.slow_scan.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_SLOW_SCAN,
                           packet->timestamp.tv_sec,
                           engine->rules.slow_scan.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source touched more than %d ports slowly over %d seconds",
             engine->rules.slow_scan.threshold,
             engine->rules.slow_scan.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_SLOW_SCAN, engine->rules.slow_scan.severity, packet, reason);
}

static void detect_sensitive_port(detection_engine_t *engine,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.sensitive_port.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack ||
        !is_sensitive_port(engine, packet->dst_port) ||
        !should_emit_alert(state,
                           ALERT_TYPE_SENSITIVE_PORT,
                           packet->timestamp.tv_sec,
                           engine->rules.sensitive_port.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accessed sensitive TCP port %u",
             packet->dst_port);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_SENSITIVE_PORT, engine->rules.sensitive_port.severity, packet, reason);
}

static void detect_connection_excess(detection_engine_t *engine,
                                     source_state_t *state,
                                     const packet_info_t *packet,
                                     alert_t *alerts,
                                     size_t *alert_count,
                                     size_t max_alerts)
{
    size_t count;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.connection_excess.enabled ||
        packet->protocol != PACKET_PROTO_TCP ||
        !packet->tcp_syn ||
        packet->tcp_ack) {
        return;
    }

    count = add_time_event(state->connection_events,
                           &state->connection_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           engine->rules.connection_excess.window_seconds);
    if (count <= (size_t)engine->rules.connection_excess.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_CONNECTION_EXCESS,
                           packet->timestamp.tv_sec,
                           engine->rules.connection_excess.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source opened more than %d TCP connection attempts in %d seconds",
             engine->rules.connection_excess.threshold,
             engine->rules.connection_excess.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_CONNECTION_EXCESS, engine->rules.connection_excess.severity, packet, reason);
}

static void detect_large_payload(detection_engine_t *engine,
                                 source_state_t *state,
                                 const packet_info_t *packet,
                                 alert_t *alerts,
                                 size_t *alert_count,
                                 size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.large_payload.enabled ||
        packet->payload_length <= (uint32_t)engine->rules.large_payload.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_LARGE_PAYLOAD,
                           packet->timestamp.tv_sec,
                           engine->rules.large_payload.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source sent payload larger than %d bytes (%u bytes observed)",
             engine->rules.large_payload.threshold,
             packet->payload_length);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_LARGE_PAYLOAD, engine->rules.large_payload.severity, packet, reason);
}

static void detect_volume_anomaly(detection_engine_t *engine,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    uint64_t bytes;
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.volume_anomaly.enabled) {
        return;
    }

    bytes = add_byte_event(state->byte_events,
                           &state->byte_event_count,
                           MAX_TIMED_EVENTS,
                           packet->timestamp.tv_sec,
                           engine->rules.volume_anomaly.window_seconds,
                           packet->length);
    if (bytes <= (uint64_t)engine->rules.volume_anomaly.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_VOLUME_ANOMALY,
                           packet->timestamp.tv_sec,
                           engine->rules.volume_anomaly.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source transferred more than %d bytes in %d seconds",
             engine->rules.volume_anomaly.threshold,
             engine->rules.volume_anomaly.window_seconds);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_VOLUME_ANOMALY, engine->rules.volume_anomaly.severity, packet, reason);
}

static void detect_heuristic_risk(detection_engine_t *engine,
                                  source_state_t *state,
                                  const packet_info_t *packet,
                                  alert_t *alerts,
                                  size_t *alert_count,
                                  size_t max_alerts)
{
    char reason[SPECTERIDS_REASON_LEN];

    if (!engine->rules.heuristic_risk.enabled ||
        state->risk_score < engine->rules.heuristic_risk.threshold ||
        !should_emit_alert(state,
                           ALERT_TYPE_HEURISTIC_RISK,
                           packet->timestamp.tv_sec,
                           engine->rules.heuristic_risk.window_seconds)) {
        return;
    }

    snprintf(reason,
             sizeof(reason),
             "Source accumulated risk score %d",
             state->risk_score);
    (void)emit_alert(state, alerts, alert_count, max_alerts, ALERT_TYPE_HEURISTIC_RISK, engine->rules.heuristic_risk.severity, packet, reason);
}

size_t detection_process_packet(detection_engine_t *engine,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t max_alerts)
{
    source_state_t *state;
    size_t alert_count = 0;

    if (engine == NULL || packet == NULL || alerts == NULL || max_alerts == 0) {
        return 0;
    }

    pthread_mutex_lock(&engine->lock);
    state = get_or_create_source(engine, packet->src_ip);
    if (state == NULL) {
        pthread_mutex_unlock(&engine->lock);
        return 0;
    }

    decay_risk(state, packet->timestamp.tv_sec);
    detect_rate_anomaly(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_arp_spoofing(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_port_scan(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_slow_scan(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_sensitive_port(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_connection_excess(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_ssh_bruteforce(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_syn_flood(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_icmp_flood(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_udp_flood(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_dns_flood(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_large_payload(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_volume_anomaly(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_beaconing(engine, state, packet, alerts, &alert_count, max_alerts);
    detect_heuristic_risk(engine, state, packet, alerts, &alert_count, max_alerts);

    pthread_mutex_unlock(&engine->lock);
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
