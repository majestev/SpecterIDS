#include "metrics_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static void write_metrics_response(int client_fd, ids_stats_t *stats)
{
    ids_stats_snapshot_t snapshot;
    char body[4096];
    char response[4608];
    int body_len;
    int response_len;

    ids_stats_snapshot(stats, &snapshot);
    body_len = snprintf(body,
                        sizeof(body),
                        "specter_packets_total %llu\n"
                        "specter_packets_parsed_total %llu\n"
                        "specter_parse_errors_total %llu\n"
                        "specter_drops_total %llu\n"
                        "specter_alerts_total %llu\n"
                        "specter_bytes_total %llu\n"
                        "specter_pps %.3f\n"
                        "specter_mbps %.6f\n"
                        "specter_queue_raw %zu\n"
                        "specter_queue_parsed %zu\n"
                        "specter_queue_log %zu\n"
                        "specter_queue_drops_total %llu\n"
                        "specter_avg_parse_us %.3f\n"
                        "specter_avg_detection_us %.3f\n"
                        "specter_avg_logging_us %.3f\n"
                        "specter_alerts_low_total %llu\n"
                        "specter_alerts_medium_total %llu\n"
                        "specter_alerts_high_total %llu\n"
                        "specter_alerts_critical_total %llu\n",
                        (unsigned long long)snapshot.captured_packets,
                        (unsigned long long)snapshot.parsed_packets,
                        (unsigned long long)snapshot.parse_errors,
                        (unsigned long long)snapshot.dropped_packets,
                        (unsigned long long)snapshot.alert_count,
                        (unsigned long long)snapshot.bytes_seen,
                        snapshot.packets_per_second,
                        snapshot.mbps,
                        snapshot.packet_queue_depth,
                        snapshot.parsed_queue_depth,
                        snapshot.log_queue_depth,
                        (unsigned long long)snapshot.queue_drops,
                        snapshot.avg_parse_us,
                        snapshot.avg_detection_us,
                        snapshot.avg_logging_us,
                        (unsigned long long)snapshot.alerts_by_severity[IDS_SEVERITY_LOW],
                        (unsigned long long)snapshot.alerts_by_severity[IDS_SEVERITY_MEDIUM],
                        (unsigned long long)snapshot.alerts_by_severity[IDS_SEVERITY_HIGH],
                        (unsigned long long)snapshot.alerts_by_severity[IDS_SEVERITY_CRITICAL]);
    if (body_len < 0) {
        return;
    }

    response_len = snprintf(response,
                            sizeof(response),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain; version=0.0.4\r\n"
                            "Content-Length: %d\r\n"
                            "Connection: close\r\n\r\n%s",
                            body_len,
                            body);
    if (response_len > 0) {
        size_t offset = 0;
        size_t total = (size_t)response_len;
        while (offset < total) {
            ssize_t written = write(client_fd, response + offset, total - offset);
            if (written <= 0) {
                break;
            }
            offset += (size_t)written;
        }
    }
}

static void *metrics_thread_main(void *arg)
{
    metrics_server_t *server = (metrics_server_t *)arg;
    int listen_fd;
    int yes = 1;
    struct sockaddr_in address;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return NULL;
    }

    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)server->port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listen_fd, 8) != 0) {
        close(listen_fd);
        return NULL;
    }

    while (!*server->stop_requested) {
        fd_set readfds;
        struct timeval timeout;
        int ready;

        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        ready = select(listen_fd + 1, &readfds, NULL, NULL, &timeout);
        if (ready <= 0) {
            continue;
        }

        if (FD_ISSET(listen_fd, &readfds)) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                char request[512];
                ssize_t n = read(client_fd, request, sizeof(request) - 1U);
                if (n > 0) {
                    request[n] = '\0';
                    if (strncmp(request, "GET /metrics ", 13) == 0 ||
                        strncmp(request, "GET / ", 6) == 0) {
                        write_metrics_response(client_fd, server->stats);
                    }
                }
                close(client_fd);
            }
        }
    }

    close(listen_fd);
    return NULL;
}

int metrics_server_start(metrics_server_t *server,
                         bool enabled,
                         int port,
                         ids_stats_t *stats,
                         volatile sig_atomic_t *stop_requested)
{
    if (server == NULL) {
        return -1;
    }

    memset(server, 0, sizeof(*server));
    server->enabled = enabled;
    server->port = port;
    server->stats = stats;
    server->stop_requested = stop_requested;

    if (!enabled) {
        return 0;
    }

    if (stats == NULL || stop_requested == NULL || port <= 0) {
        return -1;
    }

    if (pthread_create(&server->thread, NULL, metrics_thread_main, server) != 0) {
        return -1;
    }

    server->running = true;
    return 0;
}

void metrics_server_stop(metrics_server_t *server)
{
    if (server == NULL || !server->running) {
        return;
    }

    pthread_join(server->thread, NULL);
    server->running = false;
}
