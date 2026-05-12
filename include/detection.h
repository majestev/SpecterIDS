#ifndef SPECTERIDS_DETECTION_H
#define SPECTERIDS_DETECTION_H

#include <stddef.h>
#include <sys/time.h>

#include "parser.h"
#include "rules.h"

typedef enum {
    ALERT_TYPE_PORT_SCAN = 0,
    ALERT_TYPE_SSH_BRUTE_FORCE,
    ALERT_TYPE_SYN_FLOOD,
    ALERT_TYPE_ICMP_FLOOD,
    ALERT_TYPE_UDP_FLOOD,
    ALERT_TYPE_BEACONING,
    ALERT_TYPE_ARP_SPOOFING,
    ALERT_TYPE_DNS_FLOOD,
    ALERT_TYPE_RATE_ANOMALY,
    ALERT_TYPE_SLOW_SCAN,
    ALERT_TYPE_SENSITIVE_PORT,
    ALERT_TYPE_CONNECTION_EXCESS,
    ALERT_TYPE_LARGE_PAYLOAD,
    ALERT_TYPE_VOLUME_ANOMALY,
    ALERT_TYPE_HEURISTIC_RISK,
    ALERT_TYPE_THREAT_CORRELATION,
    ALERT_TYPE_COUNT
} alert_type_t;

typedef struct {
    alert_type_t type;
    ids_severity_t severity;
    char source_ip[SPECTERIDS_IP_STR_LEN];
    char destination_ip[SPECTERIDS_IP_STR_LEN];
    char reason[SPECTERIDS_REASON_LEN];
    char correlation_id[SPECTERIDS_CORRELATION_ID_LEN];
    int risk_score;
    struct timeval timestamp;
} alert_t;

typedef struct detection_engine detection_engine_t;

detection_engine_t *detection_create(const ids_rules_t *rules);
void detection_destroy(detection_engine_t *engine);
void detection_set_sensitive_ports(detection_engine_t *engine,
                                   const uint16_t *ports,
                                   size_t count);
void detection_update_rules(detection_engine_t *engine, const ids_rules_t *rules);

size_t detection_process_packet(detection_engine_t *engine,
                                const packet_info_t *packet,
                                alert_t *alerts,
                                size_t max_alerts);

const char *detection_alert_type_name(alert_type_t type);
const char *detection_severity_name(ids_severity_t severity);

#endif
