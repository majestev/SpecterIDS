#include "capture.h"
#include "config.h"
#include "dashboard.h"
#include "detection.h"
#include "event.h"
#include "logger.h"
#include "metrics_server.h"
#include "modules.h"
#include "outputs.h"
#include "rules.h"
#include "storage.h"

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_reload_requested = 0;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    if (signal_number == SIGHUP) {
        g_reload_requested = 1;
    } else {
        g_stop_requested = 1;
    }
}

static void print_version(void)
{
    printf("SpecterIDS %s\n", SPECTERIDS_VERSION);
}

static void print_usage(const char *program_name)
{
    print_version();
    printf("Usage: %s [options]\n\n", program_name);
    printf("Options:\n");
    printf("  -i, --interface <name>   Network interface to capture from\n");
    printf("  --config <file>          Load config file before CLI overrides\n");
    printf("  --rules <file>           Load detection rules file\n");
    printf("  --log-dir <dir>          Directory for logs\n");
    printf("  --bpf <expression>       libpcap BPF filter (default: ip)\n");
    printf("  --json                   Enable alerts.jsonl output\n");
    printf("  --dashboard              Enable live terminal dashboard\n");
    printf("  --dashboard compact      Enable compact dashboard mode\n");
    printf("  --pcap-export            Export suspicious packets to captures/suspicious.pcap\n");
    printf("  --metrics                Enable localhost Prometheus-style metrics endpoint\n");
    printf("  --metrics-port <port>    Metrics endpoint port (default: 9090)\n");
    printf("  --list-modules           List built-in module interfaces\n");
    printf("  --verbose                Print packet summaries to terminal\n");
    printf("  --quiet                  Suppress runtime terminal output except summary/errors\n");
    printf("  --version                Show version\n");
    printf("  -h, --help               Show this help message\n\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0\n", program_name);
    printf("  sudo %s -i eth0 --verbose --json\n", program_name);
    printf("  sudo %s -i eth0 --dashboard --bpf \"tcp or udp\"\n", program_name);
    printf("  sudo %s --config config/specterids.conf\n", program_name);
}

static bool has_value_arg(int argc, char **argv, int index)
{
    return index + 1 < argc && argv[index + 1][0] != '\0' && argv[index + 1][0] != '-';
}

static int copy_cli_value(char *dst,
                          size_t dst_size,
                          const char *value,
                          const char *option_name)
{
    if (value == NULL || value[0] == '\0') {
        fprintf(stderr, "Missing value for %s\n", option_name);
        return -1;
    }

    if (strlen(value) >= dst_size) {
        fprintf(stderr, "Value for %s is too long\n", option_name);
        return -1;
    }

    ids_copy_string(dst, dst_size, value);
    return 0;
}

static const char *find_config_arg(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            if (!has_value_arg(argc, argv, i)) {
                fprintf(stderr, "Missing value for --config\n");
                return NULL;
            }
            return argv[i + 1];
        }
    }

    return NULL;
}

static int apply_cli_args(int argc, char **argv, app_config_t *config)
{
    int i;

    for (i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) &&
            has_value_arg(argc, argv, i)) {
            const char *option_name = argv[i];
            i++;
            if (copy_cli_value(config->interface_name,
                               sizeof(config->interface_name),
                               argv[i],
                               option_name) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--config") == 0 && has_value_arg(argc, argv, i)) {
            i++;
        } else if (strcmp(argv[i], "--rules") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->rules_file,
                               sizeof(config->rules_file),
                               argv[i],
                               "--rules") != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--log-dir") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->log_dir,
                               sizeof(config->log_dir),
                               argv[i],
                               "--log-dir") != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--bpf") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->bpf_filter,
                               sizeof(config->bpf_filter),
                               argv[i],
                               "--bpf") != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--json") == 0) {
            config->json_logs = true;
        } else if (strcmp(argv[i], "--dashboard") == 0) {
            config->dashboard = true;
            if (has_value_arg(argc, argv, i)) {
                i++;
                if (copy_cli_value(config->dashboard_mode,
                                   sizeof(config->dashboard_mode),
                                   argv[i],
                                   "--dashboard") != 0) {
                    return -1;
                }
            }
        } else if (strcmp(argv[i], "--pcap-export") == 0) {
            config->pcap_export = true;
        } else if (strcmp(argv[i], "--metrics") == 0) {
            config->metrics_enabled = true;
        } else if (strcmp(argv[i], "--metrics-port") == 0 && has_value_arg(argc, argv, i)) {
            int port = atoi(argv[++i]);
            if (port < 1024 || port > 65535) {
                fprintf(stderr, "Invalid --metrics-port value\n");
                return -1;
            }
            config->metrics_port = port;
        } else if (strcmp(argv[i], "--list-modules") == 0) {
            modules_print_builtin();
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config->verbose = true;
            config->quiet = false;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            config->quiet = true;
            config->verbose = false;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            exit(EXIT_SUCCESS);
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) != 0) {
        perror("sigaction(SIGINT)");
        return -1;
    }

    if (sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction(SIGTERM)");
        return -1;
    }

    if (sigaction(SIGHUP, &action, NULL) != 0) {
        perror("sigaction(SIGHUP)");
        return -1;
    }

    return 0;
}

static void output_event_handler(const ids_event_t *event, void *user_data)
{
    output_registry_t *registry = (output_registry_t *)user_data;

    (void)output_registry_process(registry, event);
}

int main(int argc, char **argv)
{
    app_config_t config;
    ids_rules_t rules;
    logger_t logger;
    dashboard_t dashboard;
    ids_stats_t stats;
    metrics_server_t metrics_server;
    ids_event_bus_t event_bus;
    output_registry_t output_registry;
    storage_t storage;
    detection_engine_t *engine = NULL;
    capture_options_t capture_options;
    const char *config_path;
    int exit_code = EXIT_FAILURE;

    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        print_version();
        return EXIT_SUCCESS;
    }

    config_set_defaults(&config);
    config_path = find_config_arg(argc, argv);
    if (config_path != NULL && config_load_file(&config, config_path) != 0) {
        return EXIT_FAILURE;
    }

    if (apply_cli_args(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (config.interface_name[0] == '\0') {
        fprintf(stderr, "Missing interface. Use -i <interface> or set interface= in config.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (install_signal_handlers() != 0) {
        return EXIT_FAILURE;
    }

    rules_set_defaults(&rules);
    if (config.rules_file[0] != '\0' && access(config.rules_file, R_OK) == 0) {
        if (rules_load_file(&rules, config.rules_file) != 0) {
            fprintf(stderr, "Warning: continuing with built-in rule defaults.\n");
        }
    } else {
        fprintf(stderr, "Warning: rules file '%s' not readable, using built-in defaults.\n", config.rules_file);
    }

    if (geteuid() != 0) {
        fprintf(stderr,
                "Warning: live capture usually requires root or CAP_NET_RAW/CAP_NET_ADMIN.\n");
    }

    if (storage_init(&storage, config.log_dir, config.capture_dir, config.reports_dir) != 0) {
        return EXIT_FAILURE;
    }

    if (ids_event_bus_init(&event_bus) != 0) {
        return EXIT_FAILURE;
    }

    if (ids_stats_init(&stats) != 0) {
        fprintf(stderr, "Failed to initialize statistics\n");
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }

    if (logger_init(&logger,
                    storage_log_dir(&storage),
                    config.json_logs,
                    config.verbose,
                    config.quiet,
                    (uint64_t)config.rotation_size_mb * 1024ULL * 1024ULL,
                    storage_capture_dir(&storage),
                    config.pcap_export,
                    config.compress_logs,
                    config.suspicious_context_packets) != 0) {
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }
    output_registry_init(&output_registry, &logger);
    (void)ids_event_bus_subscribe(&event_bus, IDS_EVENT_ALERT, output_event_handler, &output_registry);
    (void)ids_event_bus_subscribe(&event_bus, IDS_EVENT_OUTPUT_WRITTEN, output_event_handler, &output_registry);

    if (metrics_server_start(&metrics_server,
                             config.metrics_enabled,
                             config.metrics_port,
                             &stats,
                             &g_stop_requested) != 0) {
        fprintf(stderr, "Failed to start metrics endpoint\n");
        output_registry_cleanup(&output_registry);
        logger_close(&logger);
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }

    engine = detection_create(&rules);
    if (engine == NULL) {
        fprintf(stderr, "Failed to initialize detection engine\n");
        logger_close(&logger);
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }
    detection_set_sensitive_ports(engine, config.sensitive_ports, config.sensitive_port_count);

    dashboard_init(&dashboard,
                   config.dashboard,
                   config.quiet,
                   config.interface_name,
                   config.dashboard_mode,
                   config.dashboard_refresh_ms);

    if (!config.quiet) {
        print_version();
        printf("Mode: defensive educational IDS for authorized labs\n");
        printf("Interface: %s\n", config.interface_name);
        printf("System log: %s\n", logger.system_log_path);
        printf("Alert log: %s\n", logger.alert_log_path);
        if (config.json_logs) {
            printf("JSON alert log: %s\n", logger.alert_json_path);
        }
        if (config.pcap_export) {
            printf("Suspicious PCAP: %s\n", logger.pcap_path);
        }
        if (config.metrics_enabled) {
            printf("Metrics endpoint: http://127.0.0.1:%d/metrics\n", config.metrics_port);
        }
        config_print_effective(&config);
        rules_describe(&rules);
    }

    logger_log_status(&logger, "INFO", "capture starting");

    capture_options.interface_name = config.interface_name;
    capture_options.snaplen = config.snaplen;
    capture_options.promiscuous = 1;
    capture_options.timeout_ms = 1000;
    capture_options.verbose = config.verbose;
    capture_options.quiet = config.quiet;
    capture_options.bpf_filter = config.bpf_filter;
    capture_options.parser_workers = config.parser_workers;
    capture_options.detection_workers = config.detection_workers;
    capture_options.queue_size = (size_t)config.queue_size;
    capture_options.config_file = config_path;
    capture_options.rules_file = config.rules_file;
    capture_options.event_bus = &event_bus;
    capture_options.reload_requested = &g_reload_requested;

    if (capture_run(&capture_options, engine, &logger, &dashboard, &stats, &g_stop_requested) == 0) {
        exit_code = EXIT_SUCCESS;
    }

    logger_log_status(&logger, "INFO", "capture stopped");
    g_stop_requested = 1;
    dashboard_render_stats(&dashboard, &stats, true);
    metrics_server_stop(&metrics_server);
    dashboard_destroy(&dashboard);
    detection_destroy(engine);
    output_registry_cleanup(&output_registry);
    logger_close(&logger);
    ids_stats_destroy(&stats);
    ids_event_bus_destroy(&event_bus);

    return exit_code;
}
