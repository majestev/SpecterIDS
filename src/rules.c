#include "rules.h"

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

void rules_set_defaults(ids_rules_t *rules)
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
    rules->beaconing.severity = IDS_SEVERITY_MEDIUM;

    rules->arp_spoofing.enabled = true;
    rules->arp_spoofing.severity = IDS_SEVERITY_HIGH;

    rules->dns_flood.enabled = true;
    rules->dns_flood.threshold = 150;
    rules->dns_flood.window_seconds = 10;
    rules->dns_flood.severity = IDS_SEVERITY_MEDIUM;

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
        {"RATE_ANOMALY", &rules->rate_anomaly},
        {"SLOW_SCAN", &rules->slow_scan},
        {"SENSITIVE_PORT", &rules->sensitive_port},
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
        if (!parse_positive_int(value, 1, 1000000, &int_value)) {
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

int rules_load_file(ids_rules_t *rules, const char *path)
{
    FILE *fp;
    char line[RULE_LINE_LEN];
    unsigned long line_number = 0;

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
        rule_config_t *rule;

        line_number++;
        strip_inline_comment(line);
        cursor = ids_trim(line);
        if (cursor == NULL || cursor[0] == '\0') {
            continue;
        }

        rule_name = strtok(cursor, " \t\r\n");
        if (rule_name == NULL) {
            continue;
        }

        rule = find_rule(rules, rule_name);
        if (rule == NULL) {
            warn_rule_line(path, line_number, "unknown rule ignored");
            continue;
        }

        token = strtok(NULL, " \t\r\n");
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
                token = strtok(NULL, " \t\r\n");
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

            token = strtok(NULL, " \t\r\n");
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

void rules_describe(const ids_rules_t *rules)
{
    if (rules == NULL) {
        return;
    }

    printf("Rules:\n");
    printf("  PORT_SCAN: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->port_scan.enabled ? "true" : "false",
           rules->port_scan.threshold,
           rules->port_scan.window_seconds,
           ids_severity_name(rules->port_scan.severity));
    printf("  SSH_BRUTE_FORCE: enabled=%s port=%d threshold=%d window=%ds severity=%s\n",
           rules->ssh_bruteforce.enabled ? "true" : "false",
           rules->ssh_bruteforce.port,
           rules->ssh_bruteforce.threshold,
           rules->ssh_bruteforce.window_seconds,
           ids_severity_name(rules->ssh_bruteforce.severity));
    printf("  SYN_FLOOD: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->syn_flood.enabled ? "true" : "false",
           rules->syn_flood.threshold,
           rules->syn_flood.window_seconds,
           ids_severity_name(rules->syn_flood.severity));
    printf("  ICMP_FLOOD: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->icmp_flood.enabled ? "true" : "false",
           rules->icmp_flood.threshold,
           rules->icmp_flood.window_seconds,
           ids_severity_name(rules->icmp_flood.severity));
    printf("  UDP_FLOOD: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->udp_flood.enabled ? "true" : "false",
           rules->udp_flood.threshold,
           rules->udp_flood.window_seconds,
           ids_severity_name(rules->udp_flood.severity));
    printf("  BEACONING: enabled=%s min_hits=%d interval=%ds tolerance=%ds severity=%s\n",
           rules->beaconing.enabled ? "true" : "false",
           rules->beaconing.min_hits,
           rules->beaconing.interval_seconds,
           rules->beaconing.tolerance_seconds,
           ids_severity_name(rules->beaconing.severity));
    printf("  ARP_SPOOFING: enabled=%s severity=%s\n",
           rules->arp_spoofing.enabled ? "true" : "false",
           ids_severity_name(rules->arp_spoofing.severity));
    printf("  DNS_FLOOD: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->dns_flood.enabled ? "true" : "false",
           rules->dns_flood.threshold,
           rules->dns_flood.window_seconds,
           ids_severity_name(rules->dns_flood.severity));
    printf("  RATE_ANOMALY: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->rate_anomaly.enabled ? "true" : "false",
           rules->rate_anomaly.threshold,
           rules->rate_anomaly.window_seconds,
           ids_severity_name(rules->rate_anomaly.severity));
    printf("  SLOW_SCAN: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->slow_scan.enabled ? "true" : "false",
           rules->slow_scan.threshold,
           rules->slow_scan.window_seconds,
           ids_severity_name(rules->slow_scan.severity));
    printf("  SENSITIVE_PORT: enabled=%s severity=%s\n",
           rules->sensitive_port.enabled ? "true" : "false",
           ids_severity_name(rules->sensitive_port.severity));
    printf("  CONNECTION_EXCESS: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->connection_excess.enabled ? "true" : "false",
           rules->connection_excess.threshold,
           rules->connection_excess.window_seconds,
           ids_severity_name(rules->connection_excess.severity));
    printf("  LARGE_PAYLOAD: enabled=%s threshold=%d bytes severity=%s\n",
           rules->large_payload.enabled ? "true" : "false",
           rules->large_payload.threshold,
           ids_severity_name(rules->large_payload.severity));
    printf("  VOLUME_ANOMALY: enabled=%s threshold=%d bytes window=%ds severity=%s\n",
           rules->volume_anomaly.enabled ? "true" : "false",
           rules->volume_anomaly.threshold,
           rules->volume_anomaly.window_seconds,
           ids_severity_name(rules->volume_anomaly.severity));
    printf("  HEURISTIC_RISK: enabled=%s threshold=%d window=%ds severity=%s\n",
           rules->heuristic_risk.enabled ? "true" : "false",
           rules->heuristic_risk.threshold,
           rules->heuristic_risk.window_seconds,
           ids_severity_name(rules->heuristic_risk.severity));
}
