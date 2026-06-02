#ifndef SPECTERIDS_CAPTURE_H
#define SPECTERIDS_CAPTURE_H

#include <stdbool.h>
#include <signal.h>

#include "dashboard.h"
#include "detection.h"
#include "event.h"
#include "logger.h"
#include "stats.h"

typedef struct {
    const char *interface_name;
    const char *pcap_file;
    int snaplen;
    int promiscuous;
    int timeout_ms;
    bool offline;
    bool pcap_replay;
    bool verbose;
    bool quiet;
    double pcap_speed;
    const char *bpf_filter;
    int parser_workers;
    int detection_workers;
    size_t queue_size;
    const char *config_file;
    const char *rules_file;
    int correlation_window_seconds;
    ids_event_bus_t *event_bus;
    volatile sig_atomic_t *reload_requested;
} capture_options_t;

int capture_run(const capture_options_t *options,
                detection_engine_t *engine,
                logger_t *logger,
                dashboard_t *dashboard,
                ids_stats_t *stats,
                volatile sig_atomic_t *stop_requested);

#endif
