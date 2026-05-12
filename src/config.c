#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_LINE_LEN 512

void config_set_defaults(app_config_t *config)
{
    if (config == NULL) {
        return;
    }

    memset(config, 0, sizeof(*config));
    ids_copy_string(config->log_dir, sizeof(config->log_dir), "logs");
    ids_copy_string(config->rules_file, sizeof(config->rules_file), "rules/default.rules");
    ids_copy_string(config->bpf_filter, sizeof(config->bpf_filter), "ip");
    ids_copy_string(config->output_mode, sizeof(config->output_mode), "text");
    ids_copy_string(config->dashboard_mode, sizeof(config->dashboard_mode), "detailed");
    ids_copy_string(config->log_level, sizeof(config->log_level), "INFO");
    ids_copy_string(config->capture_dir, sizeof(config->capture_dir), "captures");
    ids_copy_string(config->reports_dir, sizeof(config->reports_dir), "reports");
    config->parser_workers = SPECTERIDS_DEFAULT_WORKERS;
    config->detection_workers = SPECTERIDS_DEFAULT_WORKERS;
    config->queue_size = SPECTERIDS_DEFAULT_QUEUE_SIZE;
    config->memory_limit_mb = 256;
    config->rotation_size_mb = 32;
    config->dashboard_refresh_ms = 1000;
    config->suspicious_context_packets = 8;
    config->snaplen = SPECTERIDS_MAX_PACKET_BYTES;
    config->metrics_port = 9090;
    config->json_logs = false;
    config->pcap_export = false;
    config->metrics_enabled = false;
    config->sensitive_ports[0] = 22;
    config->sensitive_ports[1] = 23;
    config->sensitive_ports[2] = 3389;
    config->sensitive_ports[3] = 445;
    config->sensitive_port_count = 4;
}

static void warn_config_line(const char *path,
                             unsigned long line_number,
                             const char *message)
{
    fprintf(stderr, "Warning: %s:%lu: %s\n", path, line_number, message);
}

static void strip_inline_comment(char *line)
{
    char *comment = strchr(line, '#');

    if (comment != NULL) {
        *comment = '\0';
    }
}

static void set_string_option(char *dst,
                              size_t dst_size,
                              const char *value,
                              const char *path,
                              unsigned long line_number)
{
    if (value[0] == '\0') {
        warn_config_line(path, line_number, "empty value ignored");
        return;
    }

    if (strlen(value) >= dst_size) {
        warn_config_line(path, line_number, "value is too long and was ignored");
        return;
    }

    ids_copy_string(dst, dst_size, value);
}

static bool parse_int_range(const char *value, int min, int max, int *out)
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

static void set_int_option(int *dst,
                           const char *value,
                           int min,
                           int max,
                           const char *path,
                           unsigned long line_number,
                           const char *name)
{
    int parsed;

    if (!parse_int_range(value, min, max, &parsed)) {
        char warning[128];
        snprintf(warning, sizeof(warning), "invalid range for %s ignored", name);
        warn_config_line(path, line_number, warning);
        return;
    }

    *dst = parsed;
}

static void set_bool_option(bool *dst,
                            const char *value,
                            const char *path,
                            unsigned long line_number,
                            const char *name)
{
    bool parsed;

    if (!ids_parse_bool(value, &parsed)) {
        char warning[128];
        snprintf(warning, sizeof(warning), "invalid boolean for %s", name);
        warn_config_line(path, line_number, warning);
        return;
    }

    *dst = parsed;
}

static void parse_sensitive_ports(app_config_t *config,
                                  const char *value,
                                  const char *path,
                                  unsigned long line_number)
{
    char copy[SPECTERIDS_LIST_LEN];
    char *token;
    size_t count = 0;

    if (strlen(value) >= sizeof(copy)) {
        warn_config_line(path, line_number, "sensitive_ports value too long");
        return;
    }

    ids_copy_string(copy, sizeof(copy), value);
    token = strtok(copy, ",");
    while (token != NULL && count < SPECTERIDS_MAX_SENSITIVE_PORTS) {
        int port;
        char *trimmed = ids_trim(token);

        if (trimmed != NULL && parse_int_range(trimmed, 1, 65535, &port)) {
            config->sensitive_ports[count++] = (uint16_t)port;
        } else {
            warn_config_line(path, line_number, "invalid sensitive port ignored");
        }

        token = strtok(NULL, ",");
    }

    if (count > 0) {
        config->sensitive_port_count = count;
    }
}

int config_load_file(app_config_t *config, const char *path)
{
    FILE *fp;
    char line[CONFIG_LINE_LEN];
    unsigned long line_number = 0;

    if (config == NULL || path == NULL || path[0] == '\0') {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open config file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *key;
        char *value;
        char *separator;
        bool bool_value;

        line_number++;
        strip_inline_comment(line);
        key = ids_trim(line);
        if (key == NULL || key[0] == '\0') {
            continue;
        }

        separator = strchr(key, '=');
        if (separator == NULL) {
            warn_config_line(path, line_number, "expected key=value syntax");
            continue;
        }

        *separator = '\0';
        value = ids_trim(separator + 1);
        key = ids_trim(key);
        if (key == NULL || value == NULL || key[0] == '\0') {
            warn_config_line(path, line_number, "empty key ignored");
            continue;
        }

        if (strcmp(key, "interface") == 0) {
            set_string_option(config->interface_name, sizeof(config->interface_name), value, path, line_number);
        } else if (strcmp(key, "log_dir") == 0) {
            set_string_option(config->log_dir, sizeof(config->log_dir), value, path, line_number);
        } else if (strcmp(key, "rules_file") == 0) {
            set_string_option(config->rules_file, sizeof(config->rules_file), value, path, line_number);
        } else if (strcmp(key, "bpf_filter") == 0) {
            set_string_option(config->bpf_filter, sizeof(config->bpf_filter), value, path, line_number);
        } else if (strcmp(key, "output_mode") == 0) {
            set_string_option(config->output_mode, sizeof(config->output_mode), value, path, line_number);
        } else if (strcmp(key, "dashboard_mode") == 0) {
            set_string_option(config->dashboard_mode, sizeof(config->dashboard_mode), value, path, line_number);
        } else if (strcmp(key, "log_level") == 0) {
            set_string_option(config->log_level, sizeof(config->log_level), value, path, line_number);
        } else if (strcmp(key, "whitelist") == 0) {
            set_string_option(config->whitelist, sizeof(config->whitelist), value, path, line_number);
        } else if (strcmp(key, "blacklist") == 0) {
            set_string_option(config->blacklist, sizeof(config->blacklist), value, path, line_number);
        } else if (strcmp(key, "capture_dir") == 0) {
            set_string_option(config->capture_dir, sizeof(config->capture_dir), value, path, line_number);
        } else if (strcmp(key, "reports_dir") == 0) {
            set_string_option(config->reports_dir, sizeof(config->reports_dir), value, path, line_number);
        } else if (strcmp(key, "sensitive_ports") == 0) {
            parse_sensitive_ports(config, value, path, line_number);
        } else if (strcmp(key, "workers") == 0) {
            int workers = config->parser_workers;
            set_int_option(&workers, value, 1, 32, path, line_number, "workers");
            config->parser_workers = workers;
            config->detection_workers = workers;
        } else if (strcmp(key, "parser_workers") == 0) {
            set_int_option(&config->parser_workers, value, 1, 32, path, line_number, "parser_workers");
        } else if (strcmp(key, "detection_workers") == 0) {
            set_int_option(&config->detection_workers, value, 1, 32, path, line_number, "detection_workers");
        } else if (strcmp(key, "queue_size") == 0) {
            set_int_option(&config->queue_size, value, 64, 65536, path, line_number, "queue_size");
        } else if (strcmp(key, "memory_limits") == 0 || strcmp(key, "memory_limit_mb") == 0) {
            set_int_option(&config->memory_limit_mb, value, 32, 4096, path, line_number, "memory_limit_mb");
        } else if (strcmp(key, "rotation_size") == 0 || strcmp(key, "rotation_size_mb") == 0) {
            set_int_option(&config->rotation_size_mb, value, 1, 4096, path, line_number, "rotation_size_mb");
        } else if (strcmp(key, "dashboard_refresh_ms") == 0) {
            set_int_option(&config->dashboard_refresh_ms, value, 100, 60000, path, line_number, "dashboard_refresh_ms");
        } else if (strcmp(key, "suspicious_context_packets") == 0) {
            set_int_option(&config->suspicious_context_packets, value, 0, 64, path, line_number, "suspicious_context_packets");
        } else if (strcmp(key, "snaplen") == 0) {
            set_int_option(&config->snaplen, value, 256, SPECTERIDS_MAX_PACKET_BYTES, path, line_number, "snaplen");
        } else if (strcmp(key, "metrics_port") == 0) {
            set_int_option(&config->metrics_port, value, 1024, 65535, path, line_number, "metrics_port");
        } else if (strcmp(key, "json_logs") == 0) {
            set_bool_option(&config->json_logs, value, path, line_number, "json_logs");
        } else if (strcmp(key, "dashboard") == 0) {
            set_bool_option(&config->dashboard, value, path, line_number, "dashboard");
        } else if (strcmp(key, "compress_logs") == 0) {
            set_bool_option(&config->compress_logs, value, path, line_number, "compress_logs");
        } else if (strcmp(key, "pcap_export") == 0) {
            set_bool_option(&config->pcap_export, value, path, line_number, "pcap_export");
        } else if (strcmp(key, "metrics_enabled") == 0) {
            set_bool_option(&config->metrics_enabled, value, path, line_number, "metrics_enabled");
        } else if (strcmp(key, "verbose") == 0) {
            if (ids_parse_bool(value, &bool_value)) {
                config->verbose = bool_value;
                if (bool_value) {
                    config->quiet = false;
                }
            } else {
                warn_config_line(path, line_number, "invalid boolean for verbose");
            }
        } else if (strcmp(key, "quiet") == 0) {
            if (ids_parse_bool(value, &bool_value)) {
                config->quiet = bool_value;
                if (bool_value) {
                    config->verbose = false;
                }
            } else {
                warn_config_line(path, line_number, "invalid boolean for quiet");
            }
        } else {
            warn_config_line(path, line_number, "unknown option ignored");
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "Failed while reading config file '%s'\n", path);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

void config_print_effective(const app_config_t *config)
{
    if (config == NULL) {
        return;
    }

    printf("Effective configuration:\n");
    printf("  interface: %s\n", config->interface_name[0] != '\0' ? config->interface_name : "(not set)");
    printf("  log_dir: %s\n", config->log_dir);
    printf("  rules_file: %s\n", config->rules_file);
    printf("  json_logs: %s\n", config->json_logs ? "true" : "false");
    printf("  dashboard: %s\n", config->dashboard ? "true" : "false");
    printf("  verbose: %s\n", config->verbose ? "true" : "false");
    printf("  quiet: %s\n", config->quiet ? "true" : "false");
    printf("  bpf_filter: %s\n", config->bpf_filter[0] != '\0' ? config->bpf_filter : "(none)");
    printf("  parser_workers: %d\n", config->parser_workers);
    printf("  detection_workers: %d\n", config->detection_workers);
    printf("  queue_size: %d\n", config->queue_size);
    printf("  rotation_size_mb: %d\n", config->rotation_size_mb);
    printf("  log_level: %s\n", config->log_level);
    printf("  pcap_export: %s\n", config->pcap_export ? "true" : "false");
    printf("  dashboard_mode: %s\n", config->dashboard_mode);
    printf("  dashboard_refresh_ms: %d\n", config->dashboard_refresh_ms);
    printf("  metrics_enabled: %s\n", config->metrics_enabled ? "true" : "false");
    printf("  metrics_port: %d\n", config->metrics_port);
}
