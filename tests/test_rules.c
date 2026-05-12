#include "rules.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

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

int main(void)
{
    test_valid_rules();
    test_invalid_rules_are_safe();
    puts("test_rules: ok");
    return 0;
}
