#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void write_file(const char *path, const char *content)
{
    FILE *fp = fopen(path, "w");

    assert(fp != NULL);
    assert(fputs(content, fp) >= 0);
    assert(fclose(fp) == 0);
}

static void test_config_valid_values(void)
{
    app_config_t config;
    const char *path = "tests/config_valid.tmp";

    config_set_defaults(&config);
    write_file(path,
               "interface=lo\n"
               "pcap_file=samples/example.pcap\n"
               "json_logs=true\n"
               "dashboard=true\n"
               "workers=3\n"
               "detection_shards=8\n"
               "queue_size=256\n"
               "metrics_enabled=true\n"
               "metrics_port=19090\n"
               "sqlite_enabled=true\n"
               "sqlite_path=data/test-config.db\n"
               "pcap_replay=true\n"
               "pcap_speed=5x\n"
               "benchmark_mode=true\n"
               "plugins_enabled=true\n"
               "plugin_dir=plugins\n"
               "plugin=plugins/libspecter_portscan.so\n"
               "sensitive_ports=22,443,3389\n");

    assert(config_load_file(&config, path) == 0);
    assert(strcmp(config.interface_name, "lo") == 0);
    assert(config.offline_mode);
    assert(strcmp(config.pcap_file, "samples/example.pcap") == 0);
    assert(config.json_logs);
    assert(config.dashboard);
    assert(config.parser_workers == 3);
    assert(config.detection_workers == 3);
    assert(config.detection_shards == 8);
    assert(config.queue_size == 256);
    assert(config.metrics_enabled);
    assert(config.metrics_port == 19090);
    assert(config.sqlite_enabled);
    assert(strcmp(config.sqlite_path, "data/test-config.db") == 0);
    assert(config.pcap_replay);
    assert(config.pcap_speed > 4.99 && config.pcap_speed < 5.01);
    assert(config.benchmark_mode);
    assert(config.plugins_enabled);
    assert(strcmp(config.plugin_dir, "plugins") == 0);
    assert(strcmp(config.plugin_paths, "plugins/libspecter_portscan.so") == 0);
    assert(config.sensitive_port_count == 3);
    assert(config.sensitive_ports[1] == 443);
    remove(path);
}

static void test_config_invalid_values_keep_defaults(void)
{
    app_config_t config;
    const char *path = "tests/config_invalid.tmp";

    config_set_defaults(&config);
    write_file(path,
               "queue_size=1\n"
               "detection_shards=999\n"
               "metrics_port=80\n"
               "json_logs=maybe\n"
               "sensitive_ports=0,22,bad\n"
               "unknown_option=value\n");

    assert(config_load_file(&config, path) == 0);
    assert(config.queue_size == SPECTERIDS_DEFAULT_QUEUE_SIZE);
    assert(config.detection_shards == 16);
    assert(config.metrics_port == 9090);
    assert(!config.json_logs);
    assert(config.sensitive_port_count == 1);
    assert(config.sensitive_ports[0] == 22);
    remove(path);
}

int main(void)
{
    test_config_valid_values();
    test_config_invalid_values_keep_defaults();
    puts("test_config: ok");
    return 0;
}
