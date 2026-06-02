#ifndef SPECTERIDS_RULES_H
#define SPECTERIDS_RULES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

#define SPECTERIDS_MAX_RULE_GROUPS 16
#define SPECTERIDS_MAX_RULE_TARGETS 32
#define SPECTERIDS_RULE_NAME_LEN 64

typedef struct {
    bool enabled;
    int threshold;
    int window_seconds;
    int port;
    uint16_t ports[SPECTERIDS_MAX_SENSITIVE_PORTS];
    size_t port_count;
    int min_hits;
    int interval_seconds;
    int tolerance_seconds;
    bool ignore_private;
    char whitelist[SPECTERIDS_LIST_LEN];
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
    rule_config_t http_flood;
    rule_config_t rate_anomaly;
    rule_config_t slow_scan;
    rule_config_t sensitive_port;
    rule_config_t connection_excess;
    rule_config_t large_payload;
    rule_config_t volume_anomaly;
    rule_config_t heuristic_risk;
} ids_rule_set_t;

typedef struct {
    bool active;
    char name[SPECTERIDS_RULE_NAME_LEN];
    char targets[SPECTERIDS_MAX_RULE_TARGETS][SPECTERIDS_IP_STR_LEN];
    size_t target_count;
    ids_rule_set_t rules;
} ids_rule_group_t;

typedef struct {
    rule_config_t port_scan;
    rule_config_t ssh_bruteforce;
    rule_config_t syn_flood;
    rule_config_t icmp_flood;
    rule_config_t udp_flood;
    rule_config_t beaconing;
    rule_config_t arp_spoofing;
    rule_config_t dns_flood;
    rule_config_t http_flood;
    rule_config_t rate_anomaly;
    rule_config_t slow_scan;
    rule_config_t sensitive_port;
    rule_config_t connection_excess;
    rule_config_t large_payload;
    rule_config_t volume_anomaly;
    rule_config_t heuristic_risk;
    ids_rule_group_t groups[SPECTERIDS_MAX_RULE_GROUPS];
    size_t group_count;
} ids_rules_t;

void rules_set_defaults(ids_rules_t *rules);
int rules_load_file(ids_rules_t *rules, const char *path);
void rules_describe(const ids_rules_t *rules);
void rules_copy_default_set(const ids_rules_t *rules, ids_rule_set_t *out);
bool rules_select_for_destination(const ids_rules_t *rules,
                                  const char *destination_ip,
                                  ids_rule_set_t *out,
                                  char *group_name,
                                  size_t group_name_size);

#endif
