#ifndef SPECTERIDS_CONFIG_H
#define SPECTERIDS_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

typedef struct {
    char interface_name[SPECTERIDS_IFACE_LEN];
    char log_dir[SPECTERIDS_PATH_LEN];
    char rules_file[SPECTERIDS_PATH_LEN];
    char bpf_filter[SPECTERIDS_BPF_LEN];
    char output_mode[SPECTERIDS_MODE_LEN];
    char dashboard_mode[SPECTERIDS_MODE_LEN];
    char log_level[SPECTERIDS_LOG_LEVEL_LEN];
    char whitelist[SPECTERIDS_LIST_LEN];
    char blacklist[SPECTERIDS_LIST_LEN];
    char capture_dir[SPECTERIDS_PATH_LEN];
    char reports_dir[SPECTERIDS_PATH_LEN];
    uint16_t sensitive_ports[SPECTERIDS_MAX_SENSITIVE_PORTS];
    size_t sensitive_port_count;
    int parser_workers;
    int detection_workers;
    int queue_size;
    int memory_limit_mb;
    int rotation_size_mb;
    int dashboard_refresh_ms;
    int suspicious_context_packets;
    int snaplen;
    int metrics_port;
    bool json_logs;
    bool dashboard;
    bool verbose;
    bool quiet;
    bool compress_logs;
    bool pcap_export;
    bool metrics_enabled;
} app_config_t;

void config_set_defaults(app_config_t *config);
int config_load_file(app_config_t *config, const char *path);
void config_print_effective(const app_config_t *config);

#endif
