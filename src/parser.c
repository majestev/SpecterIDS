#include "parser.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#define ETH_HEADER_LEN 14U
#define VLAN_HEADER_LEN 4U
#define ETHERTYPE_IPV4 0x0800U
#define ETHERTYPE_ARP 0x0806U
#define ETHERTYPE_8021Q 0x8100U
#define ETHERTYPE_8021AD 0x88A8U
#define IPV4_MIN_HEADER_LEN 20U
#define TCP_MIN_HEADER_LEN 20U
#define UDP_HEADER_LEN 8U
#define ARP_IPV4_ETHERNET_LEN 28U
#define DNS_PORT 53U
#define ICMP_MIN_HEADER_LEN 1U
#define IP_FLAG_MORE_FRAGMENTS 0x2000U
#define IPV4_TOTAL_LENGTH_OFFSET 2U
#define TCP_FLAG_SYN 0x02U
#define TCP_FLAG_ACK 0x10U

static uint16_t read_be16(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static void format_mac(const unsigned char *data, char *buffer, size_t buffer_size)
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

static void set_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size > 0) {
        snprintf(error, error_size, "%s", message);
    }
}

static bool has_bytes(size_t caplen, size_t offset, size_t needed)
{
    return offset <= caplen && needed <= caplen - offset;
}

bool parser_parse_packet(const packet_header_t *header,
                         const unsigned char *packet,
                         packet_info_t *out,
                         char *error,
                         size_t error_size)
{
    size_t l2_len = ETH_HEADER_LEN;
    uint16_t ether_type;
    uint8_t version_ihl;
    uint8_t ip_version;
    uint8_t ip_header_len;
    uint8_t ip_protocol;
    uint16_t ip_total_length;
    uint16_t fragment_info;
    uint16_t fragment_offset;
    bool more_fragments;
    size_t ip_offset;
    size_t transport_offset;
    size_t ip_payload_end;
    struct in_addr src_addr;
    struct in_addr dst_addr;

    if (header == NULL || packet == NULL || out == NULL) {
        set_error(error, error_size, "invalid parser argument");
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->protocol = PACKET_PROTO_UNKNOWN;
    out->length = header->length;
    out->captured_length = header->captured_length;
    out->timestamp = header->timestamp;

    if (header->captured_length < ETH_HEADER_LEN) {
        set_error(error, error_size, "truncated Ethernet frame");
        return false;
    }

    format_mac(packet + 6, out->src_mac, sizeof(out->src_mac));
    format_mac(packet, out->dst_mac, sizeof(out->dst_mac));
    ether_type = read_be16(packet + 12);

    /*
     * Basic 802.1Q/802.1ad VLAN support keeps the parser useful on common
     * lab switches without turning this into a full layer-2 decoder.
     */
    if (ether_type == ETHERTYPE_8021Q || ether_type == ETHERTYPE_8021AD) {
        if (header->captured_length < ETH_HEADER_LEN + VLAN_HEADER_LEN) {
            set_error(error, error_size, "truncated VLAN Ethernet frame");
            return false;
        }
        ether_type = read_be16(packet + 16);
        l2_len += VLAN_HEADER_LEN;
    }

    out->ether_type = ether_type;

    if (ether_type == ETHERTYPE_ARP) {
        struct in_addr arp_sender;
        struct in_addr arp_target;

        if (!has_bytes(header->captured_length, l2_len, ARP_IPV4_ETHERNET_LEN)) {
            set_error(error, error_size, "truncated ARP packet");
            return false;
        }

        if (read_be16(packet + l2_len) != 1U ||
            read_be16(packet + l2_len + 2U) != ETHERTYPE_IPV4 ||
            packet[l2_len + 4U] != 6U ||
            packet[l2_len + 5U] != 4U) {
            set_error(error, error_size, "unsupported ARP format");
            return false;
        }

        out->protocol = PACKET_PROTO_ARP;
        out->arp_operation = read_be16(packet + l2_len + 6U);
        format_mac(packet + l2_len + 8U, out->arp_sender_mac, sizeof(out->arp_sender_mac));
        memcpy(&arp_sender.s_addr, packet + l2_len + 14U, sizeof(arp_sender.s_addr));
        memcpy(&arp_target.s_addr, packet + l2_len + 24U, sizeof(arp_target.s_addr));
        if (inet_ntop(AF_INET, &arp_sender, out->arp_sender_ip, sizeof(out->arp_sender_ip)) == NULL ||
            inet_ntop(AF_INET, &arp_target, out->arp_target_ip, sizeof(out->arp_target_ip)) == NULL) {
            set_error(error, error_size, "failed to format ARP address");
            return false;
        }
        ids_copy_string(out->src_ip, sizeof(out->src_ip), out->arp_sender_ip);
        ids_copy_string(out->dst_ip, sizeof(out->dst_ip), out->arp_target_ip);
        return true;
    }

    if (ether_type != ETHERTYPE_IPV4) {
        set_error(error, error_size, "non-IPv4 packet");
        return false;
    }

    if (!has_bytes(header->captured_length, l2_len, IPV4_MIN_HEADER_LEN)) {
        set_error(error, error_size, "truncated IPv4 header");
        return false;
    }

    ip_offset = l2_len;
    version_ihl = packet[ip_offset];
    ip_version = (uint8_t)(version_ihl >> 4);
    ip_header_len = (uint8_t)((version_ihl & 0x0FU) * 4U);

    if (ip_version != 4 || ip_header_len < IPV4_MIN_HEADER_LEN) {
        set_error(error, error_size, "invalid IPv4 header");
        return false;
    }

    if (!has_bytes(header->captured_length, ip_offset, ip_header_len)) {
        set_error(error, error_size, "truncated IPv4 options");
        return false;
    }

    ip_total_length = read_be16(packet + ip_offset + IPV4_TOTAL_LENGTH_OFFSET);
    if (ip_total_length < ip_header_len) {
        set_error(error, error_size, "invalid IPv4 total length");
        return false;
    }

    ip_protocol = packet[ip_offset + 9];
    out->ip_total_length = ip_total_length;
    memcpy(&src_addr.s_addr, packet + ip_offset + 12, sizeof(src_addr.s_addr));
    memcpy(&dst_addr.s_addr, packet + ip_offset + 16, sizeof(dst_addr.s_addr));

    if (inet_ntop(AF_INET, &src_addr, out->src_ip, sizeof(out->src_ip)) == NULL ||
        inet_ntop(AF_INET, &dst_addr, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        set_error(error, error_size, "failed to format IPv4 address");
        return false;
    }

    fragment_info = read_be16(packet + ip_offset + 6);
    fragment_offset = (uint16_t)(fragment_info & 0x1FFFU);
    more_fragments = (fragment_info & IP_FLAG_MORE_FRAGMENTS) != 0;
    transport_offset = ip_offset + ip_header_len;
    ip_payload_end = ip_offset + ip_total_length;
    if (ip_payload_end > header->captured_length) {
        ip_payload_end = header->captured_length;
        out->truncated = true;
    }
    out->fragmented = fragment_offset != 0 || more_fragments;

    switch (ip_protocol) {
    case IPPROTO_TCP:
        out->protocol = PACKET_PROTO_TCP;
        if (out->fragmented || !has_bytes(ip_payload_end, transport_offset, TCP_MIN_HEADER_LEN)) {
            out->truncated = !out->fragmented;
            return true;
        }
        out->src_port = read_be16(packet + transport_offset);
        out->dst_port = read_be16(packet + transport_offset + 2);
        out->tcp_syn = (packet[transport_offset + 13] & TCP_FLAG_SYN) != 0;
        out->tcp_ack = (packet[transport_offset + 13] & TCP_FLAG_ACK) != 0;
        {
            uint8_t tcp_header_len = (uint8_t)((packet[transport_offset + 12] >> 4U) * 4U);
            if (tcp_header_len < TCP_MIN_HEADER_LEN || !has_bytes(ip_payload_end, transport_offset, tcp_header_len)) {
                out->truncated = true;
                return true;
            }
            out->payload_length = (uint32_t)(ip_payload_end - transport_offset - tcp_header_len);
        }
        break;
    case IPPROTO_UDP:
        out->protocol = PACKET_PROTO_UDP;
        if (out->fragmented || !has_bytes(ip_payload_end, transport_offset, UDP_HEADER_LEN)) {
            out->truncated = !out->fragmented;
            return true;
        }
        out->src_port = read_be16(packet + transport_offset);
        out->dst_port = read_be16(packet + transport_offset + 2);
        {
            uint16_t udp_length = read_be16(packet + transport_offset + 4U);
            if (udp_length >= UDP_HEADER_LEN) {
                out->payload_length = (uint32_t)(udp_length - UDP_HEADER_LEN);
            }
        }
        out->dns = out->src_port == DNS_PORT || out->dst_port == DNS_PORT;
        break;
    case IPPROTO_ICMP:
        out->protocol = PACKET_PROTO_ICMP;
        if (!has_bytes(ip_payload_end, transport_offset, ICMP_MIN_HEADER_LEN)) {
            out->truncated = true;
            return true;
        }
        break;
    default:
        out->protocol = PACKET_PROTO_UNKNOWN;
        break;
    }

    return true;
}

const char *parser_protocol_name(packet_protocol_t protocol)
{
    switch (protocol) {
    case PACKET_PROTO_TCP:
        return "TCP";
    case PACKET_PROTO_UDP:
        return "UDP";
    case PACKET_PROTO_ICMP:
        return "ICMP";
    case PACKET_PROTO_ARP:
        return "ARP";
    case PACKET_PROTO_COUNT:
    case PACKET_PROTO_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}
