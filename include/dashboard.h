#ifndef SPECTERIDS_DASHBOARD_H
#define SPECTERIDS_DASHBOARD_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>

#include "common.h"
#include "detection.h"
#include "parser.h"
#include "stats.h"

#define DASHBOARD_RECENT_ALERTS 8
#define DASHBOARD_TOP_IPS 10

typedef struct {
    char ip[SPECTERIDS_IP_STR_LEN];
    uint64_t packets;
} dashboard_ip_stat_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_alerts;
    uint64_t alerts_by_severity[IDS_SEVERITY_COUNT];
    struct timeval started_at;
    struct timeval last_render_at;
    alert_t recent_alerts[DASHBOARD_RECENT_ALERTS];
    size_t recent_alert_count;
    dashboard_ip_stat_t top_sources[DASHBOARD_TOP_IPS];
    size_t top_source_count;
    char interface_name[SPECTERIDS_IFACE_LEN];
    char mode[SPECTERIDS_MODE_LEN];
    int refresh_ms;
    bool live_enabled;
    bool quiet;
    pthread_mutex_t lock;
} dashboard_t;

void dashboard_init(dashboard_t *dashboard,
                    bool live_enabled,
                    bool quiet,
                    const char *interface_name,
                    const char *mode,
                    int refresh_ms);
void dashboard_destroy(dashboard_t *dashboard);
void dashboard_record_packet(dashboard_t *dashboard, const packet_info_t *packet);
void dashboard_record_alert(dashboard_t *dashboard, const alert_t *alert);
void dashboard_maybe_render(dashboard_t *dashboard);
void dashboard_render_stats(dashboard_t *dashboard, ids_stats_t *stats, bool final_summary);
void dashboard_print_summary(dashboard_t *dashboard);

#endif
