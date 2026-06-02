#include "detection.h"
#include "stats.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define BENCH_PACKETS 200000

static double elapsed_seconds(const struct timeval *start, const struct timeval *end)
{
    double seconds = (double)(end->tv_sec - start->tv_sec);
    seconds += (double)(end->tv_usec - start->tv_usec) / 1000000.0;
    return seconds > 0.0 ? seconds : 0.001;
}

static packet_info_t make_packet(size_t i)
{
    packet_info_t packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "10.0.%zu.%zu", (i / 255U) % 255U, i % 255U);
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "192.0.2.%zu", (i % 200U) + 1U);
    packet.protocol = PACKET_PROTO_TCP;
    packet.src_port = (uint16_t)(40000U + (i % 1000U));
    packet.dst_port = (uint16_t)(1U + (i % 1024U));
    packet.tcp_syn = true;
    packet.length = 60;
    packet.captured_length = 60;
    packet.timestamp.tv_sec = 1700000000 + (time_t)(i / 1000U);
    return packet;
}

int main(void)
{
    ids_rules_t rules;
    detection_engine_t *engine;
    alert_t alerts[SPECTERIDS_MAX_ALERTS_PER_PACKET];
    struct timeval start;
    struct timeval end;
    size_t i;
    uint64_t total_alerts = 0;
    double seconds;

    rules_set_defaults(&rules);
    engine = detection_create(&rules);
    if (engine == NULL) {
        return 1;
    }

    gettimeofday(&start, NULL);
    for (i = 0; i < BENCH_PACKETS; i++) {
        packet_info_t packet = make_packet(i);
        total_alerts += detection_process_packet(engine, &packet, alerts, SPECTERIDS_MAX_ALERTS_PER_PACKET);
    }
    gettimeofday(&end, NULL);
    seconds = elapsed_seconds(&start, &end);

    printf("# SpecterIDS Benchmark\n\n");
    printf("| Metric | Value |\n");
    printf("| --- | ---: |\n");
    printf("| Packets processed | %d |\n", BENCH_PACKETS);
    printf("| Runtime seconds | %.6f |\n", seconds);
    printf("| Packets/sec | %.2f |\n", (double)BENCH_PACKETS / seconds);
    printf("| Alerts generated | %llu |\n", (unsigned long long)total_alerts);
    printf("| Average latency (microseconds/packet) | %.3f |\n", (seconds * 1000000.0) / (double)BENCH_PACKETS);

    detection_destroy(engine);
    return 0;
}
