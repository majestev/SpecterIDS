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
#include "storage_sqlite.h"

#include <signal.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
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
    printf("  --pcap <file>            Replay packets from an offline PCAP file\n");
    printf("  --pcap-replay            Preserve PCAP timing instead of reading as fast as possible\n");
    printf("  --pcap-speed <Nx>        Replay speed multiplier for --pcap-replay (0.1x-100x)\n");
    printf("  --speed <Nx>             Alias for --pcap-replay --pcap-speed <Nx>\n");
    printf("  --benchmark              Print deterministic offline replay benchmark summary\n");
    printf("  --config <file>          Load config file before CLI overrides\n");
    printf("  --rules <file>           Load detection rules file\n");
    printf("  --log-dir <dir>          Directory for logs\n");
    printf("  --bpf <expression>       libpcap BPF filter (default: ip or ip6 or arp)\n");
    printf("  --json                   Enable alerts.jsonl output\n");
    printf("  --dashboard [mode]       Enable dashboard (compact, detailed, advanced)\n");
    printf("  --dashboard-verbose      Enable advanced dashboard mode\n");
    printf("  --dashboard-interval <s> Dashboard refresh interval in seconds\n");
    printf("  --no-color               Disable ANSI colors and screen clearing\n");
    printf("  --pcap-export            Export suspicious packets to captures/suspicious.pcap\n");
    printf("  --metrics [port]         Enable localhost Prometheus-style metrics endpoint\n");
    printf("  --metrics-port <port>    Metrics endpoint port (default: 9090)\n");
    printf("  --sqlite <file>          Export packet summaries, alerts and metrics to SQLite\n");
    printf("  --detection-shards <n>   Detection state shards (1-256, default: 16)\n");
    printf("  --plugin <file>          Load a defensive detection plugin (.so)\n");
    printf("  --plugin-dir <dir>       Load defensive plugins from a directory\n");
    printf("  --list-modules           List built-in module interfaces\n");
    printf("  --verbose                Print packet summaries to terminal\n");
    printf("  --quiet                  Suppress runtime terminal output except summary/errors\n");
    printf("  --version                Show version\n");
    printf("  -h, --help               Show this help message\n\n");
    printf("Examples:\n");
    printf("  sudo %s -i eth0\n", program_name);
    printf("  sudo %s -i eth0 --verbose --json\n", program_name);
    printf("  sudo %s -i eth0 --dashboard --bpf \"tcp or udp\"\n", program_name);
    printf("  sudo %s -i eth0 --metrics 9090\n", program_name);
    printf("  %s --pcap samples/example.pcap --json\n", program_name);
    printf("  %s --pcap samples/example.pcap --benchmark\n", program_name);
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

static bool parse_cli_int(const char *value, int min_value, int max_value, int *out)
{
    char *endptr = NULL;
    long parsed;

    if (value == NULL || out == NULL) {
        return false;
    }

    errno = 0;
    parsed = strtol(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0') {
        return false;
    }
    if (parsed < (long)min_value || parsed > (long)max_value || parsed > INT_MAX) {
        return false;
    }

    *out = (int)parsed;
    return true;
}

static bool parse_cli_double(const char *value, double min_value, double max_value, double *out)
{
    char copy[32];
    char *endptr = NULL;
    double parsed;
    size_t len;

    if (value == NULL || out == NULL || value[0] == '\0' || strlen(value) >= sizeof(copy)) {
        return false;
    }

    ids_copy_string(copy, sizeof(copy), value);
    len = strlen(copy);
    if (len > 1U && (copy[len - 1U] == 'x' || copy[len - 1U] == 'X')) {
        copy[len - 1U] = '\0';
    }

    errno = 0;
    parsed = strtod(copy, &endptr);
    if (errno != 0 || endptr == copy || *endptr != '\0' ||
        parsed < min_value || parsed > max_value) {
        return false;
    }

    *out = parsed;
    return true;
}

static int append_cli_list_value(char *dst, size_t dst_size, const char *value, const char *option_name)
{
    size_t used;
    size_t value_len;

    if (value == NULL || value[0] == '\0') {
        fprintf(stderr, "Missing value for %s\n", option_name);
        return -1;
    }

    used = strlen(dst);
    value_len = strlen(value);
    if (value_len >= dst_size || used + value_len + (used > 0 ? 2U : 1U) > dst_size) {
        fprintf(stderr, "Value list for %s is too long\n", option_name);
        return -1;
    }

    if (used > 0) {
        dst[used++] = ',';
        dst[used] = '\0';
    }
    ids_copy_string(dst + used, dst_size - used, value);
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
        } else if (strcmp(argv[i], "--pcap") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->pcap_file,
                               sizeof(config->pcap_file),
                               argv[i],
                               "--pcap") != 0) {
                return -1;
            }
            config->offline_mode = true;
        } else if (strcmp(argv[i], "--pcap-replay") == 0) {
            config->pcap_replay = true;
        } else if ((strcmp(argv[i], "--pcap-speed") == 0 || strcmp(argv[i], "--speed") == 0) &&
                   has_value_arg(argc, argv, i)) {
            double speed;
            bool speed_alias = strcmp(argv[i], "--speed") == 0;
            i++;
            if (!parse_cli_double(argv[i], 0.1, 100.0, &speed)) {
                fprintf(stderr, "Invalid replay speed value\n");
                return -1;
            }
            config->pcap_speed = speed;
            if (speed_alias) {
                config->pcap_replay = true;
            }
        } else if (strcmp(argv[i], "--benchmark") == 0) {
            config->benchmark_mode = true;
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
        } else if (strcmp(argv[i], "--dashboard-verbose") == 0) {
            config->dashboard = true;
            ids_copy_string(config->dashboard_mode, sizeof(config->dashboard_mode), "advanced");
        } else if (strcmp(argv[i], "--dashboard-interval") == 0 && has_value_arg(argc, argv, i)) {
            int seconds;
            i++;
            if (!parse_cli_int(argv[i], 1, 3600, &seconds)) {
                fprintf(stderr, "Invalid --dashboard-interval value\n");
                return -1;
            }
            config->dashboard_refresh_ms = seconds * 1000;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            config->no_color = true;
        } else if (strcmp(argv[i], "--pcap-export") == 0) {
            config->pcap_export = true;
        } else if (strcmp(argv[i], "--metrics") == 0) {
            config->metrics_enabled = true;
            if (has_value_arg(argc, argv, i)) {
                int port;
                if (!parse_cli_int(argv[i + 1], 1024, 65535, &port)) {
                    fprintf(stderr, "Invalid --metrics port value\n");
                    return -1;
                }
                config->metrics_port = port;
                i++;
            }
        } else if (strcmp(argv[i], "--metrics-port") == 0 && has_value_arg(argc, argv, i)) {
            int port;
            i++;
            if (!parse_cli_int(argv[i], 1024, 65535, &port)) {
                fprintf(stderr, "Invalid --metrics-port value\n");
                return -1;
            }
            config->metrics_port = port;
        } else if (strcmp(argv[i], "--sqlite") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->sqlite_path,
                               sizeof(config->sqlite_path),
                               argv[i],
                               "--sqlite") != 0) {
                return -1;
            }
            config->sqlite_enabled = true;
        } else if (strcmp(argv[i], "--detection-shards") == 0 && has_value_arg(argc, argv, i)) {
            int shards;
            i++;
            if (!parse_cli_int(argv[i], 1, 256, &shards)) {
                fprintf(stderr, "Invalid --detection-shards value\n");
                return -1;
            }
            config->detection_shards = shards;
        } else if (strcmp(argv[i], "--plugin") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (append_cli_list_value(config->plugin_paths,
                                      sizeof(config->plugin_paths),
                                      argv[i],
                                      "--plugin") != 0) {
                return -1;
            }
            config->plugins_enabled = true;
        } else if (strcmp(argv[i], "--plugin-dir") == 0 && has_value_arg(argc, argv, i)) {
            i++;
            if (copy_cli_value(config->plugin_dir,
                               sizeof(config->plugin_dir),
                               argv[i],
                               "--plugin-dir") != 0) {
                return -1;
            }
            config->plugins_enabled = true;
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

static void print_benchmark_summary(ids_stats_t *stats)
{
    ids_stats_snapshot_t snapshot;

    if (stats == NULL) {
        return;
    }

    ids_stats_snapshot(stats, &snapshot);
    printf("SpecterIDS benchmark replay\n");
    printf("  packets_parsed=%llu\n", (unsigned long long)snapshot.parsed_packets);
    printf("  runtime_seconds=%.6f\n", snapshot.uptime_seconds);
    printf("  packets_per_second=%.2f\n", snapshot.packets_per_second);
    printf("  mbps=%.6f\n", snapshot.mbps);
    printf("  alerts=%llu\n", (unsigned long long)snapshot.alert_count);
    printf("  avg_parse_us=%.3f\n", snapshot.avg_parse_us);
    printf("  avg_detection_us=%.3f\n", snapshot.avg_detection_us);
    printf("  avg_logging_us=%.3f\n", snapshot.avg_logging_us);
    printf("  queue_drops=%llu\n", (unsigned long long)snapshot.queue_drops);
    printf("  malformed_packets=%llu\n", (unsigned long long)snapshot.malformed_packets);
    printf("  ipv6_ratio=%.6f\n", snapshot.ipv6_ratio);
}

static int install_signal_handlers(void)
{
    struct sigaction action;
    struct sigaction pipe_ignore;

    /* Ignore SIGPIPE: prevents process termination when a metrics client or
       logger write target disconnects mid-write. Errors are handled via return
       values from send()/write() instead. */
    memset(&pipe_ignore, 0, sizeof(pipe_ignore));
    pipe_ignore.sa_handler = SIG_IGN;
    sigemptyset(&pipe_ignore.sa_mask);
    if (sigaction(SIGPIPE, &pipe_ignore, NULL) != 0) {
        perror("sigaction(SIGPIPE)");
        return -1;
    }

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
    storage_sqlite_t *sqlite_storage = NULL;
    detection_engine_t *engine = NULL;
    capture_options_t capture_options;
    const char *config_path;
    const char *input_mode;
    const char *input_target;
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

    if (config.offline_mode && config.pcap_file[0] == '\0') {
        fprintf(stderr, "Missing PCAP path. Use --pcap <file> or set pcap_file= in config.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (config.benchmark_mode && !config.offline_mode) {
        fprintf(stderr, "--benchmark requires --pcap <file> for deterministic offline replay.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /*
     * Offline replay with more than one parser or detection worker is
     * non-deterministic: workers compete for queue slots, so packet processing
     * order varies between runs. Benchmark results and alert outputs may differ
     * across runs. Force single workers in benchmark mode; warn in plain offline
     * mode. Users who need speed over determinism can set workers explicitly.
     */
    if (config.offline_mode) {
        if (config.benchmark_mode) {
            config.parser_workers = 1;
            config.detection_workers = 1;
        } else if ((config.parser_workers > 1 || config.detection_workers > 1) && !config.quiet) {
            fprintf(stderr,
                    "Note: offline replay with multiple workers is non-deterministic. "
                    "Set parser_workers=1 detection_workers=1 for reproducible output.\n");
        }
    }

    if (!config.offline_mode && config.interface_name[0] == '\0') {
        fprintf(stderr, "Missing interface. Use -i <interface>, --pcap <file>, or set interface= in config.\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (install_signal_handlers() != 0) {
        return EXIT_FAILURE;
    }

    rules_set_defaults(&rules);
    if (config.rules_file[0] != '\0' && access(config.rules_file, R_OK) == 0) {
        if (rules_load_file(&rules, config.rules_file) != 0) {
            fprintf(stderr,
                    "Warning: failed to parse rules file '%s'; continuing with built-in defaults.\n"
                    "  Check that the file uses the key=value format documented in config/specterids.conf.\n",
                    config.rules_file);
        }
    } else if (config.rules_file[0] != '\0') {
        fprintf(stderr,
                "Warning: rules file '%s' not found or not readable; using built-in defaults.\n"
                "  To create one: cp rules/default.rules %s\n",
                config.rules_file, config.rules_file);
    } else {
        fprintf(stderr, "Warning: no rules file configured; using built-in defaults.\n");
    }
    rules.beaconing.min_hits = config.beaconing_min_hits;
    rules.beaconing.interval_seconds = config.beaconing_interval;
    rules.beaconing.tolerance_seconds = config.beaconing_tolerance;
    rules.beaconing.ignore_private = config.beaconing_ignore_private;
    if (config.beaconing_whitelist[0] != '\0') {
        ids_copy_string(rules.beaconing.whitelist, sizeof(rules.beaconing.whitelist), config.beaconing_whitelist);
    }

    if (!config.offline_mode && geteuid() != 0) {
        fprintf(stderr,
                "Warning: live capture usually requires root or CAP_NET_RAW/CAP_NET_ADMIN.\n");
    }

    if (storage_init(&storage, config.log_dir, config.capture_dir, config.reports_dir) != 0) {
        return EXIT_FAILURE;
    }

    if (ids_event_bus_init(&event_bus) != 0) {
        return EXIT_FAILURE;
    }
    if (ids_event_bus_start_async(&event_bus, (size_t)config.queue_size) != 0) {
        fprintf(stderr, "Warning: async event dispatcher unavailable; using synchronous event delivery.\n");
    }

    if (ids_stats_init(&stats) != 0) {
        fprintf(stderr, "Failed to initialize statistics\n");
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }
    ids_stats_set_detection_shards(&stats, (uint64_t)config.detection_shards);

    if (logger_init(&logger,
                    storage_log_dir(&storage),
                    config.json_logs,
                    config.verbose,
                    config.quiet,
                    (uint64_t)(unsigned int)config.rotation_size_mb * 1024ULL * 1024ULL,
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

    input_mode = config.offline_mode ? "OFFLINE" : "LIVE";
    input_target = config.offline_mode ? config.pcap_file : config.interface_name;
    sqlite_storage = storage_sqlite_create();
    if (sqlite_storage == NULL) {
        fprintf(stderr, "Failed to initialize SQLite storage wrapper\n");
        output_registry_cleanup(&output_registry);
        logger_close(&logger);
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }
    storage_sqlite_attach_stats(sqlite_storage, &stats);
    if (storage_sqlite_open(sqlite_storage,
                            config.sqlite_enabled,
                            config.sqlite_path,
                            input_mode,
                            input_target) != 0) {
        logger_log_status(&logger, "WARN", "SQLite storage unavailable; continuing without SQLite export");
    }
    (void)ids_event_bus_subscribe(&event_bus, IDS_EVENT_PACKET_PARSED, storage_sqlite_event_handler, sqlite_storage);
    (void)ids_event_bus_subscribe(&event_bus, IDS_EVENT_DETECTION_COMPLETE, storage_sqlite_event_handler, sqlite_storage);
    (void)ids_event_bus_subscribe(&event_bus, IDS_EVENT_ALERT, storage_sqlite_event_handler, sqlite_storage);

    if (metrics_server_start(&metrics_server,
                             config.metrics_enabled,
                             config.metrics_port,
                             &stats,
                             &g_stop_requested) != 0) {
        fprintf(stderr,
                "Failed to start metrics endpoint on port %d.\n"
                "  Check that the port is not already in use: ss -tlnp | grep %d\n",
                config.metrics_port, config.metrics_port);
        storage_sqlite_destroy(sqlite_storage);
        output_registry_cleanup(&output_registry);
        logger_close(&logger);
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }

    engine = detection_create_with_shards(&rules, (size_t)config.detection_shards);
    if (engine == NULL) {
        fprintf(stderr,
                "Failed to initialize detection engine with %d shards.\n"
                "  Reduce detection_shards= in config or check available memory.\n",
                config.detection_shards);
        g_stop_requested = 1;
        metrics_server_stop(&metrics_server);
        storage_sqlite_destroy(sqlite_storage);
        output_registry_cleanup(&output_registry);
        logger_close(&logger);
        ids_stats_destroy(&stats);
        ids_event_bus_destroy(&event_bus);
        return EXIT_FAILURE;
    }
    detection_set_sensitive_ports(engine, config.sensitive_ports, config.sensitive_port_count);
    if (config.plugins_enabled) {
        if (config.plugin_dir[0] != '\0') {
            int loaded = detection_load_plugins_from_dir(engine, config.plugin_dir);
            if (loaded < 0) {
                fprintf(stderr, "Warning: plugin directory '%s' could not be scanned.\n", config.plugin_dir);
            } else if (!config.quiet) {
                printf("Plugins loaded from directory: %d\n", loaded);
            }
        }
        if (config.plugin_paths[0] != '\0') {
            int loaded = detection_load_plugins_from_csv(engine, config.plugin_paths);
            if (loaded < 0) {
                fprintf(stderr, "Warning: one or more configured plugins could not be loaded.\n");
            } else if (!config.quiet) {
                printf("Plugins loaded from CLI/config list: %d\n", loaded);
            }
        }
    }

    dashboard_init(&dashboard,
                   config.dashboard,
                   config.quiet,
                   !config.no_color,
                   input_target,
                   config.dashboard_mode,
                   config.dashboard_refresh_ms);

    if (!config.quiet) {
        print_version();
        printf("Mode: defensive educational IDS for authorized labs\n");
        printf("Input mode: %s\n", input_mode);
        printf("Input target: %s\n", input_target);
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
        if (config.sqlite_enabled) {
            printf("SQLite export: %s%s\n",
                   config.sqlite_path,
                   storage_sqlite_compiled() ? "" : " (disabled in this build)");
        }
        config_print_effective(&config);
        rules_describe(&rules);
    }

    logger_log_status(&logger, "INFO", "capture starting");

    capture_options.interface_name = config.interface_name;
    capture_options.pcap_file = config.pcap_file;
    capture_options.snaplen = config.snaplen;
    capture_options.promiscuous = 1;
    capture_options.timeout_ms = 1000;
    capture_options.offline = config.offline_mode;
    capture_options.pcap_replay = config.pcap_replay;
    capture_options.verbose = config.verbose;
    capture_options.quiet = config.quiet;
    capture_options.pcap_speed = config.pcap_speed;
    capture_options.bpf_filter = config.bpf_filter;
    capture_options.parser_workers = config.parser_workers;
    capture_options.detection_workers = config.detection_workers;
    capture_options.queue_size = (size_t)config.queue_size;
    capture_options.config_file = config_path;
    capture_options.rules_file = config.rules_file;
    capture_options.correlation_window_seconds = config.correlation_window;
    capture_options.event_bus = &event_bus;
    capture_options.reload_requested = &g_reload_requested;

    if (capture_run(&capture_options, engine, &logger, &dashboard, &stats, &g_stop_requested) == 0) {
        exit_code = EXIT_SUCCESS;
    }

    logger_log_status(&logger, "INFO", "capture stopped");
    g_stop_requested = 1;
    ids_event_bus_stop_async(&event_bus);
    (void)output_registry_flush(&output_registry);
    dashboard_render_stats(&dashboard, &stats, true);
    if (config.benchmark_mode) {
        print_benchmark_summary(&stats);
    }
    storage_sqlite_record_metrics(sqlite_storage, &stats);
    storage_sqlite_finish_session(sqlite_storage, &stats);
    metrics_server_stop(&metrics_server);
    dashboard_destroy(&dashboard);
    detection_destroy(engine);
    storage_sqlite_destroy(sqlite_storage);
    output_registry_cleanup(&output_registry);
    logger_close(&logger);
    ids_stats_destroy(&stats);
    ids_event_bus_destroy(&event_bus);

    return exit_code;
}
