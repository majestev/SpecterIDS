#include "detection.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static packet_info_t make_syn_packet(uint16_t dst_port, time_t seconds)
{
    packet_info_t packet;

    memset(&packet, 0, sizeof(packet));
    snprintf(packet.src_ip, sizeof(packet.src_ip), "%s", "198.51.100.80");
    snprintf(packet.dst_ip, sizeof(packet.dst_ip), "%s", "192.0.2.50");
    packet.ip_version = 4;
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

int main(void)
{
    ids_rules_t rules;
    detection_engine_t *engine;
    alert_t alerts[4];
    size_t count = 0;
    int i;
    char error[160];

    rules_set_defaults(&rules);
    rules.port_scan.enabled = false;
    rules.syn_flood.enabled = false;
    rules.ssh_bruteforce.enabled = false;
    rules.connection_excess.enabled = false;
    rules.sensitive_port.enabled = false;
    rules.rate_anomaly.enabled = false;
    rules.beaconing.enabled = false;

    engine = detection_create_with_shards(&rules, 4);
    assert(engine != NULL);
    assert(detection_load_plugin(engine,
                                 "plugins/libspecter_portscan.so",
                                 error,
                                 sizeof(error)) == 0);
    assert(detection_plugin_count(engine) == 1);

    for (i = 0; i < 8; i++) {
        packet_info_t packet = make_syn_packet((uint16_t)(5000 + i), 1000 + i);
        count = detection_process_packet(engine, &packet, alerts, 4);
    }

    assert(count == 1);
    assert(alerts[0].type == ALERT_TYPE_PORT_SCAN);
    assert(detection_plugin_packets(engine) == 8);
    assert(detection_plugin_alerts(engine) == 1);
    detection_destroy(engine);
    puts("test_plugin_loading: ok");
    return 0;
}
