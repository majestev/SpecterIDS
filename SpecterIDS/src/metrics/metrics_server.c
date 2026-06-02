#include "metrics_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static void append_metric(char *body, size_t body_size, size_t *used, const char *format, ...)
{
    va_list args;
    int written;

    if (body == NULL || used == NULL || *used >= body_size) {
        return;
    }

    va_start(args, format);
    written = vsnprintf(body + *used, body_size - *used, format, args);
    va_end(args);
    if (written < 0) {
        return;
    }
    if ((size_t)written >= body_size - *used) {
        *used = body_size - 1U;
        body[*used] = '\0';
        return;
    }
    *used += (size_t)written;
}

static void write_all(int fd, const char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        /*
         * MSG_NOSIGNAL prevents SIGPIPE if the client disconnects mid-response.
         * Without this, a Prometheus scraper that closes the connection kills
         * the SpecterIDS process.
         */
        ssize_t written = send(fd, buffer + offset, length - offset, MSG_NOSIGNAL);

        if (written <= 0) {
            break;
        }
        offset += (size_t)written;
    }
}

#define METRICS_BODY_SIZE 16384U

static void write_metrics_response(int client_fd, ids_stats_t *stats)
{
    ids_stats_snapshot_t snapshot;
    char body[METRICS_BODY_SIZE];
    char header[512];
    size_t body_len = 0;
    int response_len;

    ids_stats_snapshot(stats, &snapshot);
    memset(body, 0, sizeof(body));

#define A(fmt, ...) append_metric(body, sizeof(body), &body_len, fmt, __VA_ARGS__)
#define T(name, kind) append_metric(body, sizeof(body), &body_len, "# TYPE %s %s\n", name, kind)

    T("parser_latency_us", "gauge");
    A("parser_latency_us{proto=\"all\"} %.3f\n", snapshot.avg_parse_us);
    T("detection_latency_us", "gauge");
    A("detection_latency_us{module=\"all\"} %.3f\n", snapshot.avg_detection_us);
    T("correlation_latency_us", "gauge");
    A("correlation_latency_us %.3f\n", snapshot.avg_correlation_us);
    T("queue_depth", "gauge");
    A("queue_depth{name=\"raw\"} %zu\n", snapshot.packet_queue_depth);
    A("queue_depth{name=\"parsed\"} %zu\n", snapshot.parsed_queue_depth);
    A("queue_depth{name=\"log\"} %zu\n", snapshot.log_queue_depth);
    A("queue_depth{name=\"events\"} %zu\n", snapshot.event_queue_depth);
    T("queue_drops_total", "counter");
    A("queue_drops_total{name=\"pipeline\"} %llu\n", (unsigned long long)snapshot.queue_drops);
    A("queue_drops_total{name=\"events\"} %llu\n", (unsigned long long)snapshot.event_dropped);
    T("packets_malformed_total", "counter");
    A("packets_malformed_total{proto=\"all\"} %llu\n", (unsigned long long)snapshot.malformed_packets);
    T("packets_dropped_total", "counter");
    A("packets_dropped_total %llu\n", (unsigned long long)snapshot.dropped_packets);
    T("storage_write_latency_us", "gauge");
    A("storage_write_latency_us %.3f\n", snapshot.avg_storage_write_us);
    T("storage_errors_total", "counter");
    A("storage_errors_total %llu\n", (unsigned long long)snapshot.storage_errors);
    T("storage_retries_total", "counter");
    A("storage_retries_total %llu\n", (unsigned long long)snapshot.storage_retries);
    T("memory_pool_utilization", "gauge");
    A("memory_pool_utilization %.6f\n", snapshot.memory_pool_utilization);
    T("memory_pool_failed_acquires_total", "counter");
    A("memory_pool_failed_acquires_total %llu\n", (unsigned long long)snapshot.pool_failed_acquires);
    T("memory_pool_invalid_releases_total", "counter");
    A("memory_pool_invalid_releases_total %llu\n", (unsigned long long)snapshot.pool_invalid_releases);
    T("plugin_latency_us", "gauge");
    A("plugin_latency_us{name=\"all\"} %.3f\n", snapshot.avg_plugin_latency_us);
    T("plugin_errors_total", "counter");
    A("plugin_errors_total{name=\"all\"} %llu\n", (unsigned long long)snapshot.plugin_errors);
    T("uptime_seconds", "gauge");
    A("uptime_seconds %.3f\n", snapshot.uptime_seconds);
    T("heartbeat_total", "counter");
    A("heartbeat_total %llu\n", (unsigned long long)snapshot.heartbeat_total);
    T("throughput_pps", "gauge");
    A("throughput_pps %.3f\n", snapshot.packets_per_second);
    T("shard_utilization", "gauge");
    A("shard_utilization{id=\"aggregate\"} %.3f\n", snapshot.shard_pressure);
    T("packets_total", "counter");
    A("packets_total %llu\n", (unsigned long long)snapshot.captured_packets);
    T("packets_parsed_total", "counter");
    A("packets_parsed_total %llu\n", (unsigned long long)snapshot.parsed_packets);
    T("alerts_total", "counter");
    A("alerts_total %llu\n", (unsigned long long)snapshot.alert_count);
    T("alerts_by_severity_total", "counter");
    A("alerts_by_severity_total{severity=\"low\"} %llu\n",      (unsigned long long)snapshot.alerts_by_severity[0]);
    A("alerts_by_severity_total{severity=\"medium\"} %llu\n",   (unsigned long long)snapshot.alerts_by_severity[1]);
    A("alerts_by_severity_total{severity=\"high\"} %llu\n",     (unsigned long long)snapshot.alerts_by_severity[2]);
    A("alerts_by_severity_total{severity=\"critical\"} %llu\n", (unsigned long long)snapshot.alerts_by_severity[3]);
    T("ipv4_packets_total", "counter");
    A("ipv4_packets_total %llu\n", (unsigned long long)snapshot.ipv4_packets);
    T("ipv6_packets_total", "counter");
    A("ipv6_packets_total %llu\n", (unsigned long long)snapshot.ipv6_packets);
    T("plugin_packets_total", "counter");
    A("plugin_packets_total %llu\n", (unsigned long long)snapshot.plugin_packets);
    T("plugin_alerts_total", "counter");
    A("plugin_alerts_total %llu\n", (unsigned long long)snapshot.plugin_alerts);
    T("events_published_total", "counter");
    A("events_published_total %llu\n", (unsigned long long)snapshot.event_published);
    T("events_dispatched_total", "counter");
    A("events_dispatched_total %llu\n", (unsigned long long)snapshot.event_dispatched);
    T("detection_lru_evictions_total", "counter");
    A("detection_lru_evictions_total %llu\n", (unsigned long long)snapshot.shard_evictions);
    T("detection_source_memory_bytes", "gauge");
    A("detection_source_memory_bytes %zu\n", snapshot.source_memory_bytes);

#undef T
#undef A

    response_len = snprintf(header,
                            sizeof(header),
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/plain; version=0.0.4\r\n"
                            "Content-Length: %zu\r\n"
                            "Connection: close\r\n\r\n",
                            body_len);
    if (response_len <= 0 || (size_t)response_len >= sizeof(header)) {
        return;
    }

    write_all(client_fd, header, (size_t)response_len);
    write_all(client_fd, body, body_len);
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
                ssize_t n;
                struct timeval recv_timeout;

                recv_timeout.tv_sec = 2;
                recv_timeout.tv_usec = 0;
                (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                                 &recv_timeout, sizeof(recv_timeout));
                n = read(client_fd, request, sizeof(request) - 1U);
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
