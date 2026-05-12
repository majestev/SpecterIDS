#ifndef SPECTERIDS_RULES_H
#define SPECTERIDS_RULES_H

#include <stdbool.h>
#include <stddef.h>

#include "common.h"

typedef struct {
    bool enabled;
    int threshold;
    int window_seconds;
    int port;
    int min_hits;
    int interval_seconds;
    int tolerance_seconds;
    ids_severity_t severity;
} rule_config_t;

typedef struct {
    rule_config_t port_scan;
    rule_config_t ssh_bruteforce;
    rule_config_t syn_flood;
    rule_config_t icmp_flood;
    rule_config_t udp_flood;
    rule_config_t beaconing;
    rule_config_t arp_spoofing;
    rule_config_t dns_flood;
    rule_config_t rate_anomaly;
    rule_config_t slow_scan;
    rule_config_t sensitive_port;
    rule_config_t connection_excess;
    rule_config_t large_payload;
    rule_config_t volume_anomaly;
    rule_config_t heuristic_risk;
} ids_rules_t;

void rules_set_defaults(ids_rules_t *rules);
int rules_load_file(ids_rules_t *rules, const char *path);
void rules_describe(const ids_rules_t *rules);

#endif
