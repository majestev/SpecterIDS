#include "rules.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RULE_LINE_LEN 512

typedef struct {
    const char *name;
    rule_config_t *rule;
} rule_lookup_t;

static void set_rule_defaults(ids_rule_set_t *rules)
{
    if (rules == NULL) {
        return;
    }

    memset(rules, 0, sizeof(*rules));

    rules->port_scan.enabled = true;
    rules->port_scan.threshold = 20;
    rules->port_scan.window_seconds = 10;
    rules->port_scan.severity = IDS_SEVERITY_HIGH;

    rules->ssh_bruteforce.enabled = true;
    rules->ssh_bruteforce.port = 22;
    rules->ssh_bruteforce.threshold = 10;
    rules->ssh_bruteforce.window_seconds = 60;
    rules->ssh_bruteforce.severity = IDS_SEVERITY_HIGH;

    rules->syn_flood.enabled = true;
    rules->syn_flood.threshold = 100;
    rules->syn_flood.window_seconds = 5;
    rules->syn_flood.severity = IDS_SEVERITY_CRITICAL;

    rules->icmp_flood.enabled = true;
    rules->icmp_flood.threshold = 100;
    rules->icmp_flood.window_seconds = 5;
    rules->icmp_flood.severity = IDS_SEVERITY_MEDIUM;

    rules->udp_flood.enabled = true;
    rules->udp_flood.threshold = 200;
    rules->udp_flood.window_seconds = 10;
    rules->udp_flood.severity = IDS_SEVERITY_MEDIUM;

    rules->beaconing.enabled = true;
    rules->beaconing.min_hits = 8;
    rules->beaconing.interval_seconds = 30;
    rules->beaconing.tolerance_seconds = 3;
    rules->beaconing.ignore_private = true;
    rules->beaconing.severity = IDS_SEVERITY_LOW;

    rules->arp_spoofing.enabled = true;
    rules->arp_spoofing.severity = IDS_SEVERITY_HIGH;

    rules->dns_flood.enabled = true;
    rules->dns_flood.threshold = 150;
    rules->dns_flood.window_seconds = 10;
    rules->dns_flood.severity = IDS_SEVERITY_MEDIUM;

    rules->http_flood.enabled = true;
    rules->http_flood.ports[0] = 80;
    rules->http_flood.ports[1] = 443;
    rules->http_flood.port_count = 2;
    rules->http_flood.threshold = 300;
    rules->http_flood.window_seconds = 10;
    rules->http_flood.severity = IDS_SEVERITY_HIGH;

    rules->rate_anomaly.enabled = true;
    rules->rate_anomaly.threshold = 500;
    rules->rate_anomaly.window_seconds = 10;
    rules->rate_anomaly.severity = IDS_SEVERITY_MEDIUM;

    rules->slow_scan.enabled = true;
    rules->slow_scan.threshold = 15;
    rules->slow_scan.window_seconds = 300;
    rules->slow_scan.severity = IDS_SEVERITY_MEDIUM;

    rules->sensitive_port.enabled = true;
    rules->sensitive_port.window_seconds = 60;
    rules->sensitive_port.threshold = 1;
    rules->sensitive_port.severity = IDS_SEVERITY_MEDIUM;

    rules->connection_excess.enabled = true;
    rules->connection_excess.threshold = 200;
    rules->connection_excess.window_seconds = 60;
    rules->connection_excess.severity = IDS_SEVERITY_HIGH;

    rules->large_payload.enabled = true;
    rules->large_payload.threshold = 1400;
    rules->large_payload.window_seconds = 60;
    rules->large_payload.severity = IDS_SEVERITY_MEDIUM;

    rules->volume_anomaly.enabled = true;
    rules->volume_anomaly.threshold = 10000000;
    rules->volume_anomaly.window_seconds = 60;
    rules->volume_anomaly.severity = IDS_SEVERITY_HIGH;

    rules->heuristic_risk.enabled = true;
    rules->heuristic_risk.threshold = 80;
    rules->heuristic_risk.window_seconds = 300;
    rules->heuristic_risk.severity = IDS_SEVERITY_HIGH;
}

static void apply_rule_set(ids_rules_t *rules, const ids_rule_set_t *set)
{
    /* ids_rules_t begins with the same 16 fields as ids_rule_set_t */
    memcpy(rules, set, sizeof(*set));
}

void rules_copy_default_set(const ids_rules_t *rules, ids_rule_set_t *out)
{
    if (rules == NULL || out == NULL) {
        return;
    }

    /* ids_rules_t begins with the same 16 fields as ids_rule_set_t */
    memcpy(out, rules, sizeof(*out));
}

void rules_set_defaults(ids_rules_t *rules)
{
    ids_rule_set_t defaults;

    if (rules == NULL) {
        return;
    }

    memset(rules, 0, sizeof(*rules));
    set_rule_defaults(&defaults);
    apply_rule_set(rules, &defaults);
}

static rule_config_t *find_rule_in_set(ids_rule_set_t *rules, const char *name)
{
    rule_lookup_t lookup[] = {
        {"PORT_SCAN", &rules->port_scan},
        {"SSH_BRUTE_FORCE", &rules->ssh_bruteforce},
        {"SYN_FLOOD", &rules->syn_flood},
        {"ICMP_FLOOD", &rules->icmp_flood},
        {"UDP_FLOOD", &rules->udp_flood},
        {"BEACONING", &rules->beaconing},
        {"ARP_SPOOFING", &rules->arp_spoofing},
        {"DNS_FLOOD", &rules->dns_flood},
        {"HTTP_FLOOD", &rules->http_flood},
        {"RATE_ANOMALY", &rules->rate_anomaly},
        {"SLOW_SCAN", &rules->slow_scan},
        {"SENSITIVE_PORT", &rules->sensitive_port},
        {"SENSITIVE_PORTS", &rules->sensitive_port},
        {"CONNECTION_EXCESS", &rules->connection_excess},
        {"LARGE_PAYLOAD", &rules->large_payload},
        {"VOLUME_ANOMALY", &rules->volume_anomaly},
        {"HEURISTIC_RISK", &rules->heuristic_risk}
    };
    size_t i;

    if (rules == NULL || name == NULL) {
        return NULL;
    }

    for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); i++) {
        if (strcmp(name, lookup[i].name) == 0) {
            return lookup[i].rule;
        }
    }

    return NULL;
}

static rule_config_t *find_rule(ids_rules_t *rules, const char *name)
{
    rule_lookup_t lookup[] = {
        {"PORT_SCAN", &rules->port_scan},
        {"SSH_BRUTE_FORCE", &rules->ssh_bruteforce},
        {"SYN_FLOOD", &rules->syn_flood},
        {"ICMP_FLOOD", &rules->icmp_flood},
        {"UDP_FLOOD", &rules->udp_flood},
        {"BEACONING", &rules->beaconing},
        {"ARP_SPOOFING", &rules->arp_spoofing},
        {"DNS_FLOOD", &rules->dns_flood},
        {"HTTP_FLOOD", &rules->http_flood},
        {"RATE_ANOMALY", &rules->rate_anomaly},
        {"SLOW_SCAN", &rules->slow_scan},
        {"SENSITIVE_PORT", &rules->sensitive_port},
        {"SENSITIVE_PORTS", &rules->sensitive_port},
        {"CONNECTION_EXCESS", &rules->connection_excess},
        {"LARGE_PAYLOAD", &rules->large_payload},
        {"VOLUME_ANOMALY", &rules->volume_anomaly},
        {"HEURISTIC_RISK", &rules->heuristic_risk}
    };
    size_t i;

    if (rules == NULL || name == NULL) {
        return NULL;
    }

    for (i = 0; i < sizeof(lookup) / sizeof(lookup[0]); i++) {
        if (strcmp(name, lookup[i].name) == 0) {
            return lookup[i].rule;
        }
    }

    return NULL;
}

static void warn_rule_line(const char *path,
                           unsigned long line_number,
                           const char *message)
{
    fprintf(stderr, "Warning: %s:%lu: %s\n", path, line_number, message);
}

static bool parse_positive_int(const char *value, int min, int max, int *out)
{
    char *endptr = NULL;
    long parsed;

    if (value == NULL || out == NULL) {
        return false;
    }

    errno = 0;
    parsed = strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || ids_trim(endptr)[0] != '\0') {
        return false;
    }
    if (parsed < min || parsed > max) {
        return false;
    }

    *out = (int)parsed;
    return true;
}

static bool parse_ports(rule_config_t *rule,
                        const char *value,
                        const char *path,
                        unsigned long line_number)
{
    char copy[SPECTERIDS_LIST_LEN];
    char *saveptr = NULL;
    char *token;
    size_t count = 0;

    if (strlen(value) >= sizeof(copy)) {
        warn_rule_line(path, line_number, "ports value too long ignored");
        return false;
    }

    ids_copy_string(copy, sizeof(copy), value);
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL && count < SPECTERIDS_MAX_SENSITIVE_PORTS) {
        int port;
        char *trimmed = ids_trim(token);

        if (trimmed != NULL && parse_positive_int(trimmed, 1, 65535, &port)) {
            rule->ports[count++] = (uint16_t)port;
        } else {
            warn_rule_line(path, line_number, "invalid port in ports list ignored");
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (count == 0) {
        return false;
    }

    rule->port_count = count;
    return true;
}

static bool apply_rule_option(rule_config_t *rule,
                              const char *key,
                              const char *value,
                              const char *path,
                              unsigned long line_number)
{
    int int_value;
    bool bool_value;
    ids_severity_t severity;

    if (strcmp(key, "threshold") == 0) {
        if (!parse_positive_int(value, 1, INT_MAX, &int_value)) {
            warn_rule_line(path, line_number, "invalid threshold ignored");
            return false;
        }
        rule->threshold = int_value;
        return true;
    }

    if (strcmp(key, "window") == 0) {
        if (!parse_positive_int(value, 1, 86400, &int_value)) {
            warn_rule_line(path, line_number, "invalid window ignored");
            return false;
        }
        rule->window_seconds = int_value;
        return true;
    }

    if (strcmp(key, "port") == 0) {
        if (!parse_positive_int(value, 1, 65535, &int_value)) {
            warn_rule_line(path, line_number, "invalid port ignored");
            return false;
        }
        rule->port = int_value;
        return true;
    }

    if (strcmp(key, "ports") == 0) {
        return parse_ports(rule, value, path, line_number);
    }

    if (strcmp(key, "min_hits") == 0) {
        if (!parse_positive_int(value, 2, 1000000, &int_value)) {
            warn_rule_line(path, line_number, "invalid min_hits ignored");
            return false;
        }
        rule->min_hits = int_value;
        return true;
    }

    if (strcmp(key, "interval") == 0) {
        if (!parse_positive_int(value, 1, 86400, &int_value)) {
            warn_rule_line(path, line_number, "invalid interval ignored");
            return false;
        }
        rule->interval_seconds = int_value;
        return true;
    }

    if (strcmp(key, "tolerance") == 0) {
        if (!parse_positive_int(value, 0, 86400, &int_value)) {
            warn_rule_line(path, line_number, "invalid tolerance ignored");
            return false;
        }
        rule->tolerance_seconds = int_value;
        return true;
    }

    if (strcmp(key, "ignore_private") == 0) {
        if (!ids_parse_bool(value, &bool_value)) {
            warn_rule_line(path, line_number, "invalid ignore_private value ignored");
            return false;
        }
        rule->ignore_private = bool_value;
        return true;
    }

    if (strcmp(key, "whitelist") == 0) {
        if (strlen(value) >= sizeof(rule->whitelist)) {
            warn_rule_line(path, line_number, "whitelist value too long ignored");
            return false;
        }
        ids_copy_string(rule->whitelist, sizeof(rule->whitelist), value);
        return true;
    }

    if (strcmp(key, "enabled") == 0) {
        if (!ids_parse_bool(value, &bool_value)) {
            warn_rule_line(path, line_number, "invalid enabled value ignored");
            return false;
        }
        rule->enabled = bool_value;
        return true;
    }

    if (strcmp(key, "severity") == 0) {
        if (!ids_parse_severity(value, &severity)) {
            warn_rule_line(path, line_number, "invalid severity ignored");
            return false;
        }
        rule->severity = severity;
        return true;
    }

    warn_rule_line(path, line_number, "unknown rule option ignored");
    return false;
}

static void strip_inline_comment(char *line)
{
    char *comment = strchr(line, '#');

    if (comment != NULL) {
        *comment = '\0';
    }
}

static ids_rule_group_t *find_or_create_group(ids_rules_t *rules,
                                              const char *name,
                                              const char *path,
                                              unsigned long line_number)
{
    ids_rule_set_t defaults;
    size_t i;

    if (rules == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }

    for (i = 0; i < rules->group_count; i++) {
        if (strcmp(rules->groups[i].name, name) == 0) {
            return &rules->groups[i];
        }
    }

    if (rules->group_count >= SPECTERIDS_MAX_RULE_GROUPS) {
        warn_rule_line(path, line_number, "too many rule groups; group ignored");
        return NULL;
    }

    rules_copy_default_set(rules, &defaults);
    i = rules->group_count++;
    memset(&rules->groups[i], 0, sizeof(rules->groups[i]));
    rules->groups[i].active = true;
    ids_copy_string(rules->groups[i].name, sizeof(rules->groups[i].name), name);
    rules->groups[i].rules = defaults;
    return &rules->groups[i];
}

static bool parse_group_header(char *line, char *name, size_t name_size)
{
    char *start;
    char *end;
    char *trimmed;

    if (line == NULL || name == NULL || name_size == 0 || line[0] != '[') {
        return false;
    }

    end = strchr(line, ']');
    if (end == NULL) {
        return false;
    }
    *end = '\0';
    start = ids_trim(line + 1U);
    if (strncmp(start, "group", 5U) != 0) {
        return false;
    }
    trimmed = ids_trim(start + 5U);
    if (trimmed == NULL || trimmed[0] == '\0' || strlen(trimmed) >= name_size) {
        return false;
    }
    ids_copy_string(name, name_size, trimmed);
    return true;
}

static bool is_valid_rule_target(const char *target);

static void parse_group_targets(ids_rule_group_t *group,
                                const char *value,
                                const char *path,
                                unsigned long line_number)
{
    char copy[SPECTERIDS_LIST_LEN];
    char *saveptr = NULL;
    char *token;
    size_t count = 0;

    if (group == NULL || value == NULL) {
        return;
    }

    if (strlen(value) >= sizeof(copy)) {
        warn_rule_line(path, line_number, "targets value too long ignored");
        return;
    }

    ids_copy_string(copy, sizeof(copy), value);
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL && count < SPECTERIDS_MAX_RULE_TARGETS) {
        char *target = ids_trim(token);

        if (target != NULL &&
            target[0] != '\0' &&
            strlen(target) < SPECTERIDS_IP_STR_LEN &&
            is_valid_rule_target(target)) {
            ids_copy_string(group->targets[count++], sizeof(group->targets[0]), target);
        } else {
            warn_rule_line(path, line_number, "invalid target ignored");
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    group->target_count = count;
}

static bool is_valid_rule_target(const char *target)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (target == NULL || target[0] == '\0') {
        return false;
    }

    return inet_pton(AF_INET, target, &v4) == 1 ||
           inet_pton(AF_INET6, target, &v6) == 1;
}

int rules_load_file(ids_rules_t *rules, const char *path)
{
    FILE *fp;
    char line[RULE_LINE_LEN];
    unsigned long line_number = 0;
    ids_rule_group_t *current_group = NULL;

    if (rules == NULL || path == NULL || path[0] == '\0') {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open rules file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *cursor;
        char *rule_name;
        char *token;
        char group_name[SPECTERIDS_RULE_NAME_LEN];
        rule_config_t *rule;
        ids_rule_set_t *target_set = NULL;
        char *saveptr = NULL;

        line_number++;
        strip_inline_comment(line);
        cursor = ids_trim(line);
        if (cursor == NULL || cursor[0] == '\0') {
            continue;
        }

        if (parse_group_header(cursor, group_name, sizeof(group_name))) {
            if (strcmp(group_name, "default") == 0) {
                current_group = NULL;
            } else {
                current_group = find_or_create_group(rules, group_name, path, line_number);
            }
            continue;
        }

        if (current_group != NULL && strncmp(cursor, "targets=", 8U) == 0) {
            parse_group_targets(current_group, ids_trim(cursor + 8U), path, line_number);
            continue;
        }

        rule_name = strtok_r(cursor, " \t\r\n", &saveptr);
        if (rule_name == NULL) {
            continue;
        }

        if (current_group != NULL) {
            target_set = &current_group->rules;
            rule = find_rule_in_set(target_set, rule_name);
        } else {
            rule = find_rule(rules, rule_name);
        }

        if (rule == NULL) {
            warn_rule_line(path, line_number, "unknown rule ignored");
            continue;
        }

        token = strtok_r(NULL, " \t\r\n", &saveptr);
        if (token == NULL) {
            warn_rule_line(path, line_number, "rule has no options");
            continue;
        }

        while (token != NULL) {
            char *separator = strchr(token, '=');
            char *key;
            char *value;

            if (separator == NULL) {
                warn_rule_line(path, line_number, "option without key=value syntax ignored");
                token = strtok_r(NULL, " \t\r\n", &saveptr);
                continue;
            }

            *separator = '\0';
            key = ids_trim(token);
            value = ids_trim(separator + 1);
            if (key == NULL || value == NULL || key[0] == '\0' || value[0] == '\0') {
                warn_rule_line(path, line_number, "empty key or value ignored");
            } else {
                (void)apply_rule_option(rule, key, value, path, line_number);
            }

            token = strtok_r(NULL, " \t\r\n", &saveptr);
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "Failed while reading rules file '%s'\n", path);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

bool rules_select_for_destination(const ids_rules_t *rules,
                                  const char *destination_ip,
                                  ids_rule_set_t *out,
                                  char *group_name,
                                  size_t group_name_size)
{
    size_t i;
    size_t j;

    if (rules == NULL || out == NULL) {
        return false;
    }

    for (i = 0; i < rules->group_count; i++) {
        const ids_rule_group_t *group = &rules->groups[i];

        if (!group->active) {
            continue;
        }

        for (j = 0; j < group->target_count; j++) {
            if (destination_ip != NULL && strcmp(group->targets[j], destination_ip) == 0) {
                *out = group->rules;
                if (group_name != NULL && group_name_size > 0) {
                    ids_copy_string(group_name, group_name_size, group->name);
                }
                return true;
            }
        }
    }

    rules_copy_default_set(rules, out);
    if (group_name != NULL && group_name_size > 0) {
        ids_copy_string(group_name, group_name_size, "default");
    }
    return false;
}

static void describe_rule(const char *name, const rule_config_t *rule)
{
    if (rule == NULL) {
        return;
    }

    printf("  %s: enabled=%s threshold=%d window=%ds port=%d min_hits=%d interval=%ds tolerance=%ds severity=%s\n",
           name,
           rule->enabled ? "true" : "false",
           rule->threshold,
           rule->window_seconds,
           rule->port,
           rule->min_hits,
           rule->interval_seconds,
           rule->tolerance_seconds,
           ids_severity_name(rule->severity));
}

void rules_describe(const ids_rules_t *rules)
{
    size_t i;

    if (rules == NULL) {
        return;
    }

    printf("Rules:\n");
    describe_rule("PORT_SCAN", &rules->port_scan);
    describe_rule("SSH_BRUTE_FORCE", &rules->ssh_bruteforce);
    describe_rule("SYN_FLOOD", &rules->syn_flood);
    describe_rule("ICMP_FLOOD", &rules->icmp_flood);
    describe_rule("UDP_FLOOD", &rules->udp_flood);
    describe_rule("BEACONING", &rules->beaconing);
    describe_rule("DNS_FLOOD", &rules->dns_flood);
    describe_rule("HTTP_FLOOD", &rules->http_flood);
    describe_rule("SLOW_SCAN", &rules->slow_scan);
    describe_rule("SENSITIVE_PORTS", &rules->sensitive_port);
    printf("  groups: %zu\n", rules->group_count);
    for (i = 0; i < rules->group_count; i++) {
        printf("    [%s] targets=%zu\n", rules->groups[i].name, rules->groups[i].target_count);
    }
}
