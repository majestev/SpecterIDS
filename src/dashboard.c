#include "dashboard.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static double elapsed_seconds_between(const struct timeval *start, const struct timeval *end)
{
    double seconds = (double)(end->tv_sec - start->tv_sec);
    seconds += (double)(end->tv_usec - start->tv_usec) / 1000000.0;

    if (seconds <= 0.0) {
        return 0.001;
    }

    return seconds;
}

static double elapsed_seconds_since(const struct timeval *start)
{
    struct timeval now;

    gettimeofday(&now, NULL);
    return elapsed_seconds_between(start, &now);
}

void dashboard_init(dashboard_t *dashboard,
                    bool live_enabled,
                    bool quiet,
                    const char *interface_name,
                    const char *mode,
                    int refresh_ms)
{
    if (dashboard == NULL) {
        return;
    }

    memset(dashboard, 0, sizeof(*dashboard));
    dashboard->live_enabled = live_enabled;
    dashboard->quiet = quiet;
    dashboard->refresh_ms = refresh_ms > 0 ? refresh_ms : 1000;
    ids_copy_string(dashboard->interface_name, sizeof(dashboard->interface_name), interface_name);
    ids_copy_string(dashboard->mode, sizeof(dashboard->mode), mode != NULL ? mode : "detailed");
    gettimeofday(&dashboard->started_at, NULL);
    dashboard->last_render_at = dashboard->started_at;
    pthread_mutex_init(&dashboard->lock, NULL);
}

void dashboard_destroy(dashboard_t *dashboard)
{
    if (dashboard == NULL) {
        return;
    }

    pthread_mutex_destroy(&dashboard->lock);
}

static dashboard_ip_stat_t *find_or_create_ip_stat(dashboard_t *dashboard, const char *ip)
{
    size_t i;
    size_t lowest_index = 0;

    for (i = 0; i < dashboard->top_source_count; i++) {
        if (strcmp(dashboard->top_sources[i].ip, ip) == 0) {
            return &dashboard->top_sources[i];
        }
        if (dashboard->top_sources[i].packets < dashboard->top_sources[lowest_index].packets) {
            lowest_index = i;
        }
    }

    if (dashboard->top_source_count < DASHBOARD_TOP_IPS) {
        dashboard_ip_stat_t *slot = &dashboard->top_sources[dashboard->top_source_count++];
        ids_copy_string(slot->ip, sizeof(slot->ip), ip);
        slot->packets = 0;
        return slot;
    }

    ids_copy_string(dashboard->top_sources[lowest_index].ip,
                    sizeof(dashboard->top_sources[lowest_index].ip),
                    ip);
    dashboard->top_sources[lowest_index].packets = 0;
    return &dashboard->top_sources[lowest_index];
}

void dashboard_record_packet(dashboard_t *dashboard, const packet_info_t *packet)
{
    dashboard_ip_stat_t *stat;

    if (dashboard == NULL || packet == NULL) {
        return;
    }

    pthread_mutex_lock(&dashboard->lock);
    dashboard->total_packets++;
    stat = find_or_create_ip_stat(dashboard, packet->src_ip);
    stat->packets++;
    pthread_mutex_unlock(&dashboard->lock);
}

void dashboard_record_alert(dashboard_t *dashboard, const alert_t *alert)
{
    if (dashboard == NULL || alert == NULL) {
        return;
    }

    pthread_mutex_lock(&dashboard->lock);
    dashboard->total_alerts++;
    if (alert->severity >= 0 && alert->severity < IDS_SEVERITY_COUNT) {
        dashboard->alerts_by_severity[alert->severity]++;
    }

    if (dashboard->recent_alert_count < DASHBOARD_RECENT_ALERTS) {
        dashboard->recent_alerts[dashboard->recent_alert_count++] = *alert;
    } else {
        memmove(dashboard->recent_alerts,
                dashboard->recent_alerts + 1,
                (DASHBOARD_RECENT_ALERTS - 1) * sizeof(dashboard->recent_alerts[0]));
        dashboard->recent_alerts[DASHBOARD_RECENT_ALERTS - 1] = *alert;
    }
    pthread_mutex_unlock(&dashboard->lock);
}

static void print_top_sources(const dashboard_t *dashboard)
{
    size_t printed = 0;
    bool used[DASHBOARD_TOP_IPS] = {false};

    while (printed < dashboard->top_source_count) {
        uint64_t best_packets = 0;
        size_t best_index = 0;
        bool found = false;
        size_t i;

        for (i = 0; i < dashboard->top_source_count; i++) {
            if (!used[i] && dashboard->top_sources[i].packets >= best_packets) {
                best_packets = dashboard->top_sources[i].packets;
                best_index = i;
                found = true;
            }
        }

        if (!found) {
            break;
        }

        used[best_index] = true;
        printf("    %-39s %" PRIu64 "\n",
               dashboard->top_sources[best_index].ip,
               dashboard->top_sources[best_index].packets);
        printed++;
    }
}

static void dashboard_render_locked(dashboard_t *dashboard, bool final_summary)
{
    double elapsed = elapsed_seconds_since(&dashboard->started_at);
    double packets_per_second = (double)dashboard->total_packets / elapsed;
    size_t i;

    if (!final_summary && dashboard->live_enabled) {
        printf("\033[2J\033[H");
    }

    printf("SpecterIDS %s\n", final_summary ? "session summary" : "dashboard");
    printf("  Interface: %s\n", dashboard->interface_name[0] != '\0' ? dashboard->interface_name : "(unknown)");
    printf("  Uptime: %.1f seconds\n", elapsed);
    printf("  Total packets: %" PRIu64 "\n", dashboard->total_packets);
    printf("  Packets/sec: %.2f\n", packets_per_second);
    printf("  Total alerts: %" PRIu64 "\n", dashboard->total_alerts);
    printf("  Alerts by severity: LOW=%" PRIu64 " MEDIUM=%" PRIu64 " HIGH=%" PRIu64 " CRITICAL=%" PRIu64 "\n",
           dashboard->alerts_by_severity[IDS_SEVERITY_LOW],
           dashboard->alerts_by_severity[IDS_SEVERITY_MEDIUM],
           dashboard->alerts_by_severity[IDS_SEVERITY_HIGH],
           dashboard->alerts_by_severity[IDS_SEVERITY_CRITICAL]);

    if (dashboard->top_source_count > 0) {
        printf("  Top source IPs:\n");
        print_top_sources(dashboard);
    }

    if (dashboard->recent_alert_count > 0) {
        printf("  Recent alerts:\n");
        for (i = 0; i < dashboard->recent_alert_count; i++) {
            printf("    - [%s] [%s] src=%s dst=%s\n",
                   ids_severity_name(dashboard->recent_alerts[i].severity),
                   detection_alert_type_name(dashboard->recent_alerts[i].type),
                   dashboard->recent_alerts[i].source_ip,
                   dashboard->recent_alerts[i].destination_ip);
        }
    }

    if (!final_summary) {
        printf("\nPress Ctrl+C to stop.\n");
    }
    fflush(stdout);
}

void dashboard_maybe_render(dashboard_t *dashboard)
{
    struct timeval now;

    if (dashboard == NULL || !dashboard->live_enabled || dashboard->quiet) {
        return;
    }

    gettimeofday(&now, NULL);
    pthread_mutex_lock(&dashboard->lock);
    if (elapsed_seconds_between(&dashboard->last_render_at, &now) >= (double)dashboard->refresh_ms / 1000.0) {
        dashboard->last_render_at = now;
        dashboard_render_locked(dashboard, false);
    }
    pthread_mutex_unlock(&dashboard->lock);
}

static const char *severity_color(ids_severity_t severity)
{
    switch (severity) {
    case IDS_SEVERITY_LOW:
        return "\033[36m";
    case IDS_SEVERITY_MEDIUM:
        return "\033[33m";
    case IDS_SEVERITY_HIGH:
        return "\033[35m";
    case IDS_SEVERITY_CRITICAL:
        return "\033[31m";
    case IDS_SEVERITY_COUNT:
    default:
        return "\033[0m";
    }
}

static void print_bar(uint64_t value, uint64_t max_value)
{
    size_t i;
    size_t width = 24;
    size_t filled = max_value == 0 ? 0 : (size_t)((value * width) / max_value);

    if (filled > width) {
        filled = width;
    }

    putchar('[');
    for (i = 0; i < width; i++) {
        putchar(i < filled ? '#' : '.');
    }
    putchar(']');
}

static void print_top_items(const char *title, const ids_top_counter_t *items)
{
    size_t i;
    uint64_t max_value = 0;

    for (i = 0; i < IDS_STATS_TOP_ITEMS; i++) {
        if (items[i].key[0] != '\0' && items[i].value > max_value) {
            max_value = items[i].value;
        }
    }

    printf("  %s\n", title);
    for (i = 0; i < IDS_STATS_TOP_ITEMS; i++) {
        if (items[i].key[0] == '\0') {
            continue;
        }
        printf("    %-24s %10" PRIu64 " ", items[i].key, items[i].value);
        print_bar(items[i].value, max_value);
        putchar('\n');
    }
}

void dashboard_render_stats(dashboard_t *dashboard, ids_stats_t *stats, bool final_summary)
{
    ids_stats_snapshot_t snapshot;
    size_t i;
    bool compact;

    if (dashboard == NULL || stats == NULL) {
        return;
    }

    if (!final_summary && (!dashboard->live_enabled || dashboard->quiet)) {
        return;
    }

    ids_stats_snapshot(stats, &snapshot);
    compact = strcmp(dashboard->mode, "compact") == 0;

    if (!final_summary && dashboard->live_enabled && !dashboard->quiet) {
        printf("\033[2J\033[H");
    }

    printf("\033[1mSpecterIDS %s\033[0m | iface=%s | mode=%s | uptime=%.1fs\n",
           final_summary ? "summary" : "dashboard",
           dashboard->interface_name[0] != '\0' ? dashboard->interface_name : "(unknown)",
           dashboard->mode,
           snapshot.uptime_seconds);
    printf("  packets=%" PRIu64 " parsed=%" PRIu64 " drops=%" PRIu64 " parse_errors=%" PRIu64
           " pps=%.2f mbps=%.3f alerts/min=%.2f\n",
           snapshot.captured_packets,
           snapshot.parsed_packets,
           snapshot.dropped_packets + snapshot.queue_drops,
           snapshot.parse_errors,
           snapshot.packets_per_second,
           snapshot.mbps,
           snapshot.alerts_per_minute);
    printf("  queues packet=%zu parsed=%zu log=%zu | cpu=%.3fs mem=%ldKB\n",
           snapshot.packet_queue_depth,
           snapshot.parsed_queue_depth,
           snapshot.log_queue_depth,
           snapshot.cpu_seconds,
           snapshot.memory_kb);
    printf("  latency avg parse=%.3fus detection=%.3fus logging=%.3fus | queue_pressure=%.0f\n",
           snapshot.avg_parse_us,
           snapshot.avg_detection_us,
           snapshot.avg_logging_us,
           snapshot.queue_pressure);
    printf("  alerts LOW=%s%" PRIu64 "\033[0m MEDIUM=%s%" PRIu64 "\033[0m HIGH=%s%" PRIu64
           "\033[0m CRITICAL=%s%" PRIu64 "\033[0m total=%" PRIu64 "\n",
           severity_color(IDS_SEVERITY_LOW),
           snapshot.alerts_by_severity[IDS_SEVERITY_LOW],
           severity_color(IDS_SEVERITY_MEDIUM),
           snapshot.alerts_by_severity[IDS_SEVERITY_MEDIUM],
           severity_color(IDS_SEVERITY_HIGH),
           snapshot.alerts_by_severity[IDS_SEVERITY_HIGH],
           severity_color(IDS_SEVERITY_CRITICAL),
           snapshot.alerts_by_severity[IDS_SEVERITY_CRITICAL],
           snapshot.alert_count);

    if (!compact) {
        printf("  protocols UNKNOWN=%" PRIu64 " TCP=%" PRIu64 " UDP=%" PRIu64 " ICMP=%" PRIu64 " ARP=%" PRIu64 "\n",
               snapshot.protocols[PACKET_PROTO_UNKNOWN],
               snapshot.protocols[PACKET_PROTO_TCP],
               snapshot.protocols[PACKET_PROTO_UDP],
               snapshot.protocols[PACKET_PROTO_ICMP],
               snapshot.protocols[PACKET_PROTO_ARP]);
        print_top_items("Top source IPs", snapshot.top_sources);
        print_top_items("Top destination ports", snapshot.top_ports);
        printf("  Top alert types\n");
        for (i = 0; i < ALERT_TYPE_COUNT; i++) {
            if (snapshot.alerts_by_type[i] == 0) {
                continue;
            }
            printf("    %-24s %" PRIu64 "\n",
                   detection_alert_type_name((alert_type_t)i),
                   snapshot.alerts_by_type[i]);
        }
    }

    if (!final_summary) {
        printf("\nPress Ctrl+C to stop.\n");
    }
    fflush(stdout);
}

void dashboard_print_summary(dashboard_t *dashboard)
{
    if (dashboard == NULL) {
        return;
    }

    pthread_mutex_lock(&dashboard->lock);
    dashboard_render_locked(dashboard, true);
    pthread_mutex_unlock(&dashboard->lock);
}
