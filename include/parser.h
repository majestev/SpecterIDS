#ifndef SPECTERIDS_PARSER_H
#define SPECTERIDS_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include "common.h"

typedef enum {
    PACKET_PROTO_UNKNOWN = 0,
    PACKET_PROTO_TCP,
    PACKET_PROTO_UDP,
    PACKET_PROTO_ICMP,
    PACKET_PROTO_ARP,
    PACKET_PROTO_COUNT
} packet_protocol_t;

typedef struct {
    uint32_t length;
    uint32_t captured_length;
    struct timeval timestamp;
} packet_header_t;

typedef struct {
    char src_ip[SPECTERIDS_IP_STR_LEN];
    char dst_ip[SPECTERIDS_IP_STR_LEN];
    char src_mac[SPECTERIDS_MAC_STR_LEN];
    char dst_mac[SPECTERIDS_MAC_STR_LEN];
    char arp_sender_ip[SPECTERIDS_IP_STR_LEN];
    char arp_target_ip[SPECTERIDS_IP_STR_LEN];
    char arp_sender_mac[SPECTERIDS_MAC_STR_LEN];
    packet_protocol_t protocol;
    uint16_t ether_type;
    uint16_t arp_operation;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t length;
    uint32_t captured_length;
    uint32_t ip_total_length;
    uint32_t payload_length;
    struct timeval timestamp;
    bool tcp_syn;
    bool tcp_ack;
    bool dns;
    bool truncated;
    bool fragmented;
} packet_info_t;

bool parser_parse_packet(const packet_header_t *header,
                         const unsigned char *packet,
                         packet_info_t *out,
                         char *error,
                         size_t error_size);

const char *parser_protocol_name(packet_protocol_t protocol);

#endif
