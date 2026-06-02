#include "rules.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");
    assert(fp != NULL);
    assert(fputs(content, fp) >= 0);
    assert(fclose(fp) == 0);
}

static void test_valid_rules(void)
{
    ids_rules_t rules;
    const char *path = "tests/rules_valid.tmp";

    rules_set_defaults(&rules);
    write_file(path,
               "# valid rules\n"
               "PORT_SCAN threshold=3 window=7 severity=CRITICAL enabled=true\n"
               "SSH_BRUTE_FORCE port=2222 threshold=4 window=9 severity=LOW enabled=false\n"
               "BEACONING min_hits=4 interval=15 tolerance=2 severity=MEDIUM enabled=true\n");

    assert(rules_load_file(&rules, path) == 0);
    assert(rules.port_scan.threshold == 3);
    assert(rules.port_scan.window_seconds == 7);
    assert(rules.port_scan.severity == IDS_SEVERITY_CRITICAL);
    assert(rules.ssh_bruteforce.port == 2222);
    assert(rules.ssh_bruteforce.enabled == false);
    assert(rules.beaconing.min_hits == 4);
    assert(rules.beaconing.interval_seconds == 15);
    assert(rules.beaconing.tolerance_seconds == 2);
    remove(path);
}

static void test_invalid_rules_are_safe(void)
{
    ids_rules_t rules;
    const char *path = "tests/rules_invalid.tmp";

    rules_set_defaults(&rules);
    write_file(path,
               "PORT_SCAN threshold=-1 window=abc severity=LOUD enabled=maybe\n"
               "UNKNOWN_RULE threshold=1\n"
               "SYN_FLOOD threshold=5 window=2 severity=HIGH enabled=true\n");

    assert(rules_load_file(&rules, path) == 0);
    assert(rules.port_scan.threshold == 20);
    assert(rules.port_scan.window_seconds == 10);
    assert(rules.port_scan.severity == IDS_SEVERITY_HIGH);
    assert(rules.port_scan.enabled == true);
    assert(rules.syn_flood.threshold == 5);
    assert(rules.syn_flood.window_seconds == 2);
    remove(path);
}

static void test_rule_groups(void)
{
    ids_rules_t rules;
    ids_rule_set_t selected;
    char group_name[SPECTERIDS_RULE_NAME_LEN];
    const char *path = "tests/rules_groups.tmp";

    rules_set_defaults(&rules);
    write_file(path,
               "[group default]\n"
               "PORT_SCAN threshold=5 window=10 severity=HIGH enabled=true\n"
               "[group web_servers]\n"
               "targets=192.0.2.10,2001:db8::10,not-an-ip\n"
               "PORT_SCAN threshold=50 window=20 severity=MEDIUM enabled=true\n"
               "HTTP_FLOOD ports=80,443 threshold=300 window=10 severity=HIGH enabled=true\n"
               "BAD_RULE threshold=1\n"
               "[group lab_sensitive]\n"
               "targets=10.0.0.5\n"
               "SENSITIVE_PORTS ports=22,3389,5432 threshold=5 window=60 severity=CRITICAL enabled=true\n");

    assert(rules_load_file(&rules, path) == 0);

    assert(!rules_select_for_destination(&rules, "198.51.100.20", &selected, group_name, sizeof(group_name)));
    assert(strcmp(group_name, "default") == 0);
    assert(selected.port_scan.threshold == 5);

    assert(rules_select_for_destination(&rules, "192.0.2.10", &selected, group_name, sizeof(group_name)));
    assert(strcmp(group_name, "web_servers") == 0);
    assert(rules.groups[0].target_count == 2);
    assert(selected.port_scan.threshold == 50);
    assert(selected.port_scan.severity == IDS_SEVERITY_MEDIUM);
    assert(selected.http_flood.port_count == 2);
    assert(selected.http_flood.ports[0] == 80);

    assert(rules_select_for_destination(&rules, "2001:db8::10", &selected, group_name, sizeof(group_name)));
    assert(strcmp(group_name, "web_servers") == 0);

    assert(rules_select_for_destination(&rules, "10.0.0.5", &selected, group_name, sizeof(group_name)));
    assert(strcmp(group_name, "lab_sensitive") == 0);
    assert(selected.sensitive_port.severity == IDS_SEVERITY_CRITICAL);
    assert(selected.sensitive_port.port_count == 3);
    remove(path);
}

int main(void)
{
    test_valid_rules();
    test_invalid_rules_are_safe();
    test_rule_groups();
    puts("test_rules: ok");
    return 0;
}
