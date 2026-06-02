#include "datalink.h"

#include <stdio.h>
#include <string.h>

#define ETH_HEADER_LEN 14U
#define VLAN_HEADER_LEN 4U
#define SLL_HEADER_LEN 16U
#define SLL2_HEADER_LEN 20U
#define ETHERTYPE_8021Q 0x8100U
#define ETHERTYPE_8021AD 0x88A8U

static uint16_t read_be16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static void set_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s", message);
    }
}

static void format_mac(const uint8_t *data, char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    snprintf(buffer,
             buffer_size,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             data[0],
             data[1],
             data[2],
             data[3],
             data[4],
             data[5]);
}

static bool has_bytes(size_t caplen, size_t offset, size_t needed)
{
    return offset <= caplen && needed <= caplen - offset;
}

static int parse_ethernet(const uint8_t *packet,
                          size_t packet_len,
                          datalink_frame_t *frame,
                          char *error,
                          size_t error_size)
{
    size_t l2_len = ETH_HEADER_LEN;
    uint16_t ethertype;

    if (!has_bytes(packet_len, 0, ETH_HEADER_LEN)) {
        set_error(error, error_size, "truncated Ethernet frame");
        return -1;
    }

    format_mac(packet + 6, frame->src_mac, sizeof(frame->src_mac));
    format_mac(packet, frame->dst_mac, sizeof(frame->dst_mac));
    ethertype = read_be16(packet + 12);

    while (ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD) {
        if (!has_bytes(packet_len, l2_len, VLAN_HEADER_LEN)) {
            set_error(error, error_size, "truncated VLAN Ethernet frame");
            return -1;
        }
        ethertype = read_be16(packet + l2_len + 2U);
        l2_len += VLAN_HEADER_LEN;
    }

    if (!has_bytes(packet_len, l2_len, 0)) {
        set_error(error, error_size, "invalid Ethernet frame length");
        return -1;
    }

    frame->ethertype = ethertype;
    frame->network_payload = packet + l2_len;
    frame->network_len = packet_len - l2_len;
    return 0;
}

static int parse_linux_sll(const uint8_t *packet,
                           size_t packet_len,
                           datalink_frame_t *frame,
                           char *error,
                           size_t error_size)
{
    if (!has_bytes(packet_len, 0, SLL_HEADER_LEN)) {
        set_error(error, error_size, "truncated Linux cooked frame");
        return -1;
    }

    if (read_be16(packet + 4U) >= 6U) {
        format_mac(packet + 6, frame->src_mac, sizeof(frame->src_mac));
    }
    frame->ethertype = read_be16(packet + 14U);
    frame->network_payload = packet + SLL_HEADER_LEN;
    frame->network_len = packet_len - SLL_HEADER_LEN;
    return 0;
}

static int parse_linux_sll2(const uint8_t *packet,
                            size_t packet_len,
                            datalink_frame_t *frame,
                            char *error,
                            size_t error_size)
{
    if (!has_bytes(packet_len, 0, SLL2_HEADER_LEN)) {
        set_error(error, error_size, "truncated Linux cooked v2 frame");
        return -1;
    }

    frame->ethertype = read_be16(packet);
    if (packet[11] >= 6U) {
        format_mac(packet + 12, frame->src_mac, sizeof(frame->src_mac));
    }
    frame->network_payload = packet + SLL2_HEADER_LEN;
    frame->network_len = packet_len - SLL2_HEADER_LEN;
    return 0;
}

static int parse_raw_ip(const uint8_t *packet,
                        size_t packet_len,
                        datalink_frame_t *frame,
                        char *error,
                        size_t error_size)
{
    uint8_t version;

    if (packet == NULL || packet_len == 0) {
        set_error(error, error_size, "empty raw IP packet");
        return -1;
    }

    version = (uint8_t)(packet[0] >> 4U);
    if (version == 4U) {
        frame->ethertype = IDS_ETHERTYPE_IPV4;
    } else if (version == 6U) {
        frame->ethertype = IDS_ETHERTYPE_IPV6;
    } else {
        set_error(error, error_size, "unsupported raw IP version");
        return -1;
    }

    frame->network_payload = packet;
    frame->network_len = packet_len;
    return 0;
}

int datalink_parse_frame(int datalink_type,
                         const uint8_t *packet,
                         size_t packet_len,
                         datalink_frame_t *frame,
                         char *error,
                         size_t error_size)
{
    if (packet == NULL || frame == NULL) {
        set_error(error, error_size, "invalid datalink parser argument");
        return -1;
    }

    memset(frame, 0, sizeof(*frame));

    switch (datalink_type) {
    case DLT_EN10MB:
        return parse_ethernet(packet, packet_len, frame, error, error_size);
    case DLT_LINUX_SLL:
        return parse_linux_sll(packet, packet_len, frame, error, error_size);
    case DLT_LINUX_SLL2:
        return parse_linux_sll2(packet, packet_len, frame, error, error_size);
    case DLT_RAW:
        return parse_raw_ip(packet, packet_len, frame, error, error_size);
    default:
        set_error(error, error_size, "unsupported datalink type");
        return -1;
    }
}

int datalink_parse(int datalink_type,
                   const uint8_t *packet,
                   size_t packet_len,
                   const uint8_t **network_payload,
                   size_t *network_len,
                   uint16_t *ethertype)
{
    datalink_frame_t frame;

    if (network_payload == NULL || network_len == NULL || ethertype == NULL) {
        return -1;
    }

    if (datalink_parse_frame(datalink_type, packet, packet_len, &frame, NULL, 0) != 0) {
        return -1;
    }

    *network_payload = frame.network_payload;
    *network_len = frame.network_len;
    *ethertype = frame.ethertype;
    return 0;
}

bool datalink_is_supported(int datalink_type)
{
    return datalink_type == DLT_EN10MB ||
           datalink_type == DLT_LINUX_SLL ||
           datalink_type == DLT_LINUX_SLL2 ||
           datalink_type == DLT_RAW;
}

const char *datalink_type_name(int datalink_type)
{
    switch (datalink_type) {
    case DLT_EN10MB:
        return "DLT_EN10MB/Ethernet";
    case DLT_LINUX_SLL:
        return "DLT_LINUX_SLL/Linux cooked";
    case DLT_LINUX_SLL2:
        return "DLT_LINUX_SLL2/Linux cooked v2";
    case DLT_RAW:
        return "DLT_RAW/Raw IP";
    default:
        return "unsupported datalink";
    }
}
