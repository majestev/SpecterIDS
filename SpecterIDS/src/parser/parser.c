#include "parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#define IPV4_MIN_HEADER_LEN 20U
#define IPV6_HEADER_LEN 40U
#define TCP_MIN_HEADER_LEN 20U
#define UDP_HEADER_LEN 8U
#define ARP_IPV4_ETHERNET_LEN 28U
#define DNS_PORT 53U
#define ICMP_MIN_HEADER_LEN 1U
#define IP_FLAG_MORE_FRAGMENTS 0x2000U
#define IPV4_TOTAL_LENGTH_OFFSET 2U
#define TCP_FLAG_SYN 0x02U
#define TCP_FLAG_ACK 0x10U
#define IPV6_NH_HOPOPTS 0U
#define IPV6_NH_TCP 6U
#define IPV6_NH_UDP 17U
#define IPV6_NH_ROUTING 43U
#define IPV6_NH_FRAGMENT 44U
#define IPV6_NH_ICMPV6 58U
#define IPV6_NH_NONE 59U
#define IPV6_NH_DSTOPTS 60U
#define IPV6_NH_AH 51U

static uint16_t read_be16(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
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

static bool parse_arp_ipv4(const unsigned char *payload,
                           size_t payload_len,
                           const datalink_frame_t *frame,
                           packet_info_t *out,
                           char *error,
                           size_t error_size)
{
    struct in_addr arp_sender;
    struct in_addr arp_target;

    if (!has_bytes(payload_len, 0, ARP_IPV4_ETHERNET_LEN)) {
        set_error(error, error_size, "truncated ARP packet");
        return false;
    }

    if (read_be16(payload) != 1U ||
        read_be16(payload + 2U) != IDS_ETHERTYPE_IPV4 ||
        payload[4U] != 6U ||
        payload[5U] != 4U) {
        set_error(error, error_size, "unsupported ARP format");
        return false;
    }

    out->protocol = PACKET_PROTO_ARP;
    out->arp_operation = read_be16(payload + 6U);
    ids_copy_string(out->arp_sender_mac, sizeof(out->arp_sender_mac), frame->src_mac);
    memcpy(&arp_sender.s_addr, payload + 14U, sizeof(arp_sender.s_addr));
    memcpy(&arp_target.s_addr, payload + 24U, sizeof(arp_target.s_addr));
    if (inet_ntop(AF_INET, &arp_sender, out->arp_sender_ip, sizeof(out->arp_sender_ip)) == NULL ||
        inet_ntop(AF_INET, &arp_target, out->arp_target_ip, sizeof(out->arp_target_ip)) == NULL) {
        set_error(error, error_size, "failed to format ARP address");
        return false;
    }
    ids_copy_string(out->src_ip, sizeof(out->src_ip), out->arp_sender_ip);
    ids_copy_string(out->dst_ip, sizeof(out->dst_ip), out->arp_target_ip);
    return true;
}

static void parse_transport(packet_info_t *out,
                            const unsigned char *packet,
                            size_t packet_len,
                            size_t transport_offset,
                            uint8_t protocol)
{
    switch (protocol) {
    case IPPROTO_TCP:
        out->protocol = PACKET_PROTO_TCP;
        if (out->fragmented || !has_bytes(packet_len, transport_offset, TCP_MIN_HEADER_LEN)) {
            out->truncated = !out->fragmented;
            return;
        }
        out->src_port = read_be16(packet + transport_offset);
        out->dst_port = read_be16(packet + transport_offset + 2U);
        out->tcp_syn = (packet[transport_offset + 13U] & TCP_FLAG_SYN) != 0;
        out->tcp_ack = (packet[transport_offset + 13U] & TCP_FLAG_ACK) != 0;
        {
            uint8_t tcp_header_len = (uint8_t)((packet[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_len < TCP_MIN_HEADER_LEN ||
                !has_bytes(packet_len, transport_offset, tcp_header_len)) {
                out->truncated = true;
                return;
            }
            out->payload_length = (uint32_t)(packet_len - transport_offset - tcp_header_len);
        }
        break;
    case IPPROTO_UDP:
        out->protocol = PACKET_PROTO_UDP;
        if (out->fragmented || !has_bytes(packet_len, transport_offset, UDP_HEADER_LEN)) {
            out->truncated = !out->fragmented;
            return;
        }
        out->src_port = read_be16(packet + transport_offset);
        out->dst_port = read_be16(packet + transport_offset + 2U);
        {
            uint16_t udp_length = read_be16(packet + transport_offset + 4U);
            if (udp_length >= UDP_HEADER_LEN) {
                out->payload_length = (uint32_t)(udp_length - UDP_HEADER_LEN);
            }
            if (udp_length > packet_len - transport_offset) {
                out->truncated = true;
            }
        }
        out->dns = out->src_port == DNS_PORT || out->dst_port == DNS_PORT;
        break;
    case IPPROTO_ICMP:
        out->protocol = PACKET_PROTO_ICMP;
        if (!has_bytes(packet_len, transport_offset, ICMP_MIN_HEADER_LEN)) {
            out->truncated = true;
        }
        break;
    case IPV6_NH_ICMPV6:
        out->protocol = PACKET_PROTO_ICMPV6;
        if (!has_bytes(packet_len, transport_offset, ICMP_MIN_HEADER_LEN)) {
            out->truncated = true;
        }
        break;
    default:
        out->protocol = PACKET_PROTO_UNKNOWN;
        break;
    }
}

static bool parse_ipv4(const unsigned char *payload,
                       size_t payload_len,
                       packet_info_t *out,
                       char *error,
                       size_t error_size)
{
    uint8_t version_ihl;
    uint8_t ip_header_len;
    uint16_t ip_total_length;
    uint16_t fragment_info;
    uint16_t fragment_offset;
    size_t transport_offset;
    size_t ip_payload_end;
    struct in_addr src_addr;
    struct in_addr dst_addr;

    if (!has_bytes(payload_len, 0, IPV4_MIN_HEADER_LEN)) {
        set_error(error, error_size, "truncated IPv4 header");
        return false;
    }

    version_ihl = payload[0];
    out->ip_version = (uint8_t)(version_ihl >> 4U);
    ip_header_len = (uint8_t)((version_ihl & 0x0FU) * 4U);
    if (out->ip_version != 4U || ip_header_len < IPV4_MIN_HEADER_LEN) {
        set_error(error, error_size, "invalid IPv4 header");
        return false;
    }

    if (!has_bytes(payload_len, 0, ip_header_len)) {
        set_error(error, error_size, "truncated IPv4 options");
        return false;
    }

    ip_total_length = read_be16(payload + IPV4_TOTAL_LENGTH_OFFSET);
    if (ip_total_length < ip_header_len) {
        set_error(error, error_size, "invalid IPv4 total length");
        return false;
    }

    out->ip_next_header = payload[9U];
    out->ip_hop_limit = payload[8U];
    out->ip_total_length = ip_total_length;
    memcpy(&src_addr.s_addr, payload + 12U, sizeof(src_addr.s_addr));
    memcpy(&dst_addr.s_addr, payload + 16U, sizeof(dst_addr.s_addr));

    if (inet_ntop(AF_INET, &src_addr, out->src_ip, sizeof(out->src_ip)) == NULL ||
        inet_ntop(AF_INET, &dst_addr, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        set_error(error, error_size, "failed to format IPv4 address");
        return false;
    }

    fragment_info = read_be16(payload + 6U);
    fragment_offset = (uint16_t)(fragment_info & 0x1FFFU);
    out->fragmented = fragment_offset != 0 || (fragment_info & IP_FLAG_MORE_FRAGMENTS) != 0;

    transport_offset = ip_header_len;
    ip_payload_end = ip_total_length;
    if (ip_payload_end > payload_len) {
        ip_payload_end = payload_len;
        out->truncated = true;
    }

    parse_transport(out, payload, ip_payload_end, transport_offset, out->ip_next_header);
    return true;
}

static bool is_ipv6_extension_header(uint8_t next_header)
{
    return next_header == IPV6_NH_HOPOPTS ||
           next_header == IPV6_NH_ROUTING ||
           next_header == IPV6_NH_FRAGMENT ||
           next_header == IPV6_NH_DSTOPTS ||
           next_header == IPV6_NH_AH;
}

static bool skip_ipv6_extensions(const unsigned char *payload,
                                 size_t payload_len,
                                 uint8_t *next_header,
                                 size_t *offset,
                                 packet_info_t *out,
                                 char *error,
                                 size_t error_size)
{
    unsigned int guard = 0;

    while (is_ipv6_extension_header(*next_header)) {
        uint8_t current = *next_header;

        if (++guard > 8U) {
            set_error(error, error_size, "too many IPv6 extension headers");
            return false;
        }

        if (current == IPV6_NH_FRAGMENT) {
            uint16_t frag_info;

            if (!has_bytes(payload_len, *offset, 8U)) {
                set_error(error, error_size, "truncated IPv6 fragment header");
                return false;
            }
            *next_header = payload[*offset];
            frag_info = read_be16(payload + *offset + 2U);
            *offset += 8U;
            /*
             * A fragment extension header with offset=0 and M=0 is a complete
             * atomic datagram — not actually fragmented. Only mark fragmented
             * when the fragment offset is non-zero OR the More Fragments bit
             * is set. Setting fragmented=true unconditionally before this check
             * caused atomic datagrams to be misclassified, skipping transport
             * layer parsing for them.
             */
            if ((frag_info & 0xFFF8U) != 0 || (frag_info & 0x0001U) != 0) {
                out->fragmented = true;
                return true;
            }
            continue;
        }

        if (current == IPV6_NH_AH) {
            uint8_t hdr_ext_len;
            size_t header_len;

            if (!has_bytes(payload_len, *offset, 2U)) {
                set_error(error, error_size, "truncated IPv6 AH header");
                return false;
            }
            *next_header = payload[*offset];
            hdr_ext_len = payload[*offset + 1U];
            header_len = ((size_t)hdr_ext_len + 2U) * 4U;
            if (!has_bytes(payload_len, *offset, header_len)) {
                set_error(error, error_size, "truncated IPv6 AH payload");
                return false;
            }
            *offset += header_len;
            continue;
        }

        if (!has_bytes(payload_len, *offset, 2U)) {
            set_error(error, error_size, "truncated IPv6 extension header");
            return false;
        }
        {
            uint8_t hdr_ext_len = payload[*offset + 1U];
            size_t header_len = ((size_t)hdr_ext_len + 1U) * 8U;
            *next_header = payload[*offset];
            if (!has_bytes(payload_len, *offset, header_len)) {
                set_error(error, error_size, "truncated IPv6 extension payload");
                return false;
            }
            *offset += header_len;
        }
    }

    return true;
}

static bool parse_ipv6(const unsigned char *payload,
                       size_t payload_len,
                       packet_info_t *out,
                       char *error,
                       size_t error_size)
{
    uint8_t version;
    uint16_t ipv6_payload_length;
    uint8_t next_header;
    size_t transport_offset;
    size_t payload_end;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;

    if (!has_bytes(payload_len, 0, IPV6_HEADER_LEN)) {
        set_error(error, error_size, "truncated IPv6 header");
        return false;
    }

    version = (uint8_t)(payload[0] >> 4U);
    if (version != 6U) {
        set_error(error, error_size, "invalid IPv6 header");
        return false;
    }

    ipv6_payload_length = read_be16(payload + 4U);
    next_header = payload[6U];
    out->ip_version = 6U;
    out->ip_next_header = next_header;
    out->ip_hop_limit = payload[7U];
    out->ip_total_length = (uint32_t)IPV6_HEADER_LEN + ipv6_payload_length;

    memcpy(&src_addr, payload + 8U, sizeof(src_addr));
    memcpy(&dst_addr, payload + 24U, sizeof(dst_addr));
    if (inet_ntop(AF_INET6, &src_addr, out->src_ip, sizeof(out->src_ip)) == NULL ||
        inet_ntop(AF_INET6, &dst_addr, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        set_error(error, error_size, "failed to format IPv6 address");
        return false;
    }

    payload_end = (size_t)IPV6_HEADER_LEN + ipv6_payload_length;
    if (payload_end > payload_len) {
        payload_end = payload_len;
        out->truncated = true;
    }

    transport_offset = IPV6_HEADER_LEN;
    if (!skip_ipv6_extensions(payload,
                              payload_end,
                              &next_header,
                              &transport_offset,
                              out,
                              error,
                              error_size)) {
        return false;
    }
    out->ip_next_header = next_header;

    if (out->fragmented && transport_offset >= payload_end) {
        return true;
    }

    if (next_header == IPV6_NH_NONE) {
        out->protocol = PACKET_PROTO_UNKNOWN;
        return true;
    }

    parse_transport(out, payload, payload_end, transport_offset, next_header);
    return true;
}

bool parser_parse_packet(const packet_header_t *header,
                         const unsigned char *packet,
                         packet_info_t *out,
                         char *error,
                         size_t error_size)
{
    datalink_frame_t frame;
    int datalink_type;

    if (header == NULL || packet == NULL || out == NULL) {
        set_error(error, error_size, "invalid parser argument");
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->protocol = PACKET_PROTO_UNKNOWN;
    out->length = header->length;
    out->captured_length = header->captured_length;
    out->timestamp = header->timestamp;

    datalink_type = header->datalink_type != 0 ? header->datalink_type : DLT_EN10MB;
    if (datalink_parse_frame(datalink_type,
                             packet,
                             header->captured_length,
                             &frame,
                             error,
                             error_size) != 0) {
        return false;
    }

    out->ether_type = frame.ethertype;
    ids_copy_string(out->src_mac, sizeof(out->src_mac), frame.src_mac);
    ids_copy_string(out->dst_mac, sizeof(out->dst_mac), frame.dst_mac);

    if (frame.ethertype == IDS_ETHERTYPE_ARP) {
        return parse_arp_ipv4(frame.network_payload, frame.network_len, &frame, out, error, error_size);
    }

    if (frame.ethertype == IDS_ETHERTYPE_IPV4) {
        return parse_ipv4(frame.network_payload, frame.network_len, out, error, error_size);
    }

    if (frame.ethertype == IDS_ETHERTYPE_IPV6) {
        return parse_ipv6(frame.network_payload, frame.network_len, out, error, error_size);
    }

    set_error(error, error_size, "unsupported network protocol");
    return false;
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
    case PACKET_PROTO_ICMPV6:
        return "ICMPv6";
    case PACKET_PROTO_ARP:
        return "ARP";
    case PACKET_PROTO_COUNT:
    case PACKET_PROTO_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}
