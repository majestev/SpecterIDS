#include "plugin_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PLUGIN_THRESHOLD 8U
#define PLUGIN_MAX_PORTS 32U
#define PLUGIN_WINDOW_SECONDS 30

typedef struct {
    char source_ip[SPECTERIDS_IP_STR_LEN];
    uint16_t ports[PLUGIN_MAX_PORTS];
    size_t port_count;
    time_t window_start;
    time_t last_alert;
} portscan_plugin_state_t;

static void plugin_copy_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

static int plugin_init(void **state)
{
    portscan_plugin_state_t *plugin_state;

    if (state == NULL) {
        return -1;
    }

    plugin_state = calloc(1, sizeof(*plugin_state));
    if (plugin_state == NULL) {
        return -1;
    }

    *state = plugin_state;
    return 0;
}

static bool port_seen(const portscan_plugin_state_t *state, uint16_t port)
{
    size_t i;

    for (i = 0; i < state->port_count; i++) {
        if (state->ports[i] == port) {
            return true;
        }
    }

    return false;
}

static void reset_window(portscan_plugin_state_t *state, const packet_info_t *packet)
{
    memset(state->source_ip, 0, sizeof(state->source_ip));
    plugin_copy_string(state->source_ip, sizeof(state->source_ip), packet->src_ip);
    memset(state->ports, 0, sizeof(state->ports));
    state->port_count = 0;
    state->window_start = packet->timestamp.tv_sec;
}

static int plugin_start(void *state)
{
    return state != NULL ? 0 : -1;
}

static size_t plugin_packet_handler(void *state,
                                    const packet_info_t *packet,
                                    alert_t *alerts,
                                    size_t max_alerts)
{
    portscan_plugin_state_t *plugin_state = (portscan_plugin_state_t *)state;

    if (plugin_state == NULL || packet == NULL || alerts == NULL || max_alerts == 0) {
        return 0;
    }

    if (packet->protocol != PACKET_PROTO_TCP || !packet->tcp_syn || packet->tcp_ack) {
        return 0;
    }

    if (plugin_state->source_ip[0] == '\0' ||
        strcmp(plugin_state->source_ip, packet->src_ip) != 0 ||
        packet->timestamp.tv_sec - plugin_state->window_start > PLUGIN_WINDOW_SECONDS) {
        reset_window(plugin_state, packet);
    }

    if (!port_seen(plugin_state, packet->dst_port) && plugin_state->port_count < PLUGIN_MAX_PORTS) {
        plugin_state->ports[plugin_state->port_count++] = packet->dst_port;
    }

    if (plugin_state->port_count < PLUGIN_THRESHOLD ||
        packet->timestamp.tv_sec - plugin_state->last_alert < PLUGIN_WINDOW_SECONDS) {
        return 0;
    }

    memset(&alerts[0], 0, sizeof(alerts[0]));
    alerts[0].type = ALERT_TYPE_PORT_SCAN;
    alerts[0].severity = IDS_SEVERITY_MEDIUM;
    plugin_copy_string(alerts[0].source_ip, sizeof(alerts[0].source_ip), packet->src_ip);
    plugin_copy_string(alerts[0].destination_ip, sizeof(alerts[0].destination_ip), packet->dst_ip);
    snprintf(alerts[0].reason,
             sizeof(alerts[0].reason),
             "Dynamic plugin observed %zu unique TCP destination ports in %d seconds",
             plugin_state->port_count,
             PLUGIN_WINDOW_SECONDS);
    snprintf(alerts[0].correlation_id,
             sizeof(alerts[0].correlation_id),
             "plugin-%ld-%u",
             (long)packet->timestamp.tv_sec,
             packet->dst_port);
    alerts[0].risk_score = 25;
    alerts[0].confidence_score = 65;
    alerts[0].timestamp = packet->timestamp;
    plugin_state->last_alert = packet->timestamp.tv_sec;
    return 1;
}

static void plugin_stop(void *state)
{
    (void)state;
}

static void plugin_unload(void *state)
{
    free(state);
}

static const specterids_plugin_descriptor_t PLUGIN = {
    .abi_version = SPECTERIDS_PLUGIN_ABI_VERSION,
    .min_core_abi = 2U,
    .capabilities = SPECTERIDS_PLUGIN_CAP_PACKET,
    .name = "specter_portscan",
    .description = "Defensive example plugin that watches unique TCP destination ports.",
    .init = plugin_init,
    .start = plugin_start,
    .packet_handler = plugin_packet_handler,
    .alert_handler = NULL,
    .stop = plugin_stop,
    .unload = plugin_unload
};

const specterids_plugin_descriptor_t *specterids_plugin_descriptor(void)
{
    return &PLUGIN;
}
