#include "detection.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static packet_info_t make_tcp_packet(const char *src, uint16_t dst_port, time_t seconds)
{
    packet_info_t packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "%s", src);
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "192.0.2.10");
    packet.protocol = PACKET_PROTO_TCP;
    packet.src_port = 40000;
    packet.dst_port = dst_port;
    packet.tcp_syn = true;
    packet.tcp_ack = false;
    packet.length = 60;
    packet.captured_length = 60;
    packet.timestamp.tv_sec = seconds;
    return packet;
}

static void test_port_scan_alert(void)
{
    ids_rules_t rules;
    detection_engine_t *engine;
    alert_t alerts[4];
    size_t count = 0;
    int port;

    rules_set_defaults(&rules);
    rules.port_scan.threshold = 3;
    rules.port_scan.window_seconds = 10;
    rules.ssh_bruteforce.enabled = false;
    rules.syn_flood.enabled = false;
    rules.beaconing.enabled = false;

    engine = detection_create(&rules);
    assert(engine != NULL);

    for (port = 80; port < 84; port++) {
        packet_info_t packet = make_tcp_packet("198.51.100.20", (uint16_t)port, 1000 + port - 80);
        count = detection_process_packet(engine, &packet, alerts, 4);
    }

    assert(count == 1);
    assert(alerts[0].type == ALERT_TYPE_PORT_SCAN);
    assert(alerts[0].severity == IDS_SEVERITY_HIGH);
    detection_destroy(engine);
}

static void test_ssh_bruteforce_alert(void)
{
    ids_rules_t rules;
    detection_engine_t *engine;
    alert_t alerts[4];
    size_t count = 0;
    int i;

    rules_set_defaults(&rules);
    rules.port_scan.enabled = false;
    rules.syn_flood.enabled = false;
    rules.beaconing.enabled = false;
    rules.ssh_bruteforce.threshold = 2;
    rules.ssh_bruteforce.window_seconds = 60;

    engine = detection_create(&rules);
    assert(engine != NULL);

    for (i = 0; i < 3; i++) {
        packet_info_t packet = make_tcp_packet("198.51.100.30", 22, 2000 + i);
        count = detection_process_packet(engine, &packet, alerts, 4);
    }

    assert(count == 1);
    assert(alerts[0].type == ALERT_TYPE_SSH_BRUTE_FORCE);
    detection_destroy(engine);
}

static void test_syn_flood_alert(void)
{
    ids_rules_t rules;
    detection_engine_t *engine;
    alert_t alerts[4];
    size_t count = 0;
    int i;

    rules_set_defaults(&rules);
    rules.port_scan.enabled = false;
    rules.ssh_bruteforce.enabled = false;
    rules.beaconing.enabled = false;
    rules.syn_flood.threshold = 3;
    rules.syn_flood.window_seconds = 5;

    engine = detection_create(&rules);
    assert(engine != NULL);

    for (i = 0; i < 4; i++) {
        packet_info_t packet = make_tcp_packet("198.51.100.40", 443, 3000 + i);
        count = detection_process_packet(engine, &packet, alerts, 4);
    }

    assert(count == 1);
    assert(alerts[0].type == ALERT_TYPE_SYN_FLOOD);
    assert(alerts[0].severity == IDS_SEVERITY_CRITICAL);
    detection_destroy(engine);
}

int main(void)
{
    test_port_scan_alert();
    test_ssh_bruteforce_alert();
    test_syn_flood_alert();
    puts("test_detection: ok");
    return 0;
}
