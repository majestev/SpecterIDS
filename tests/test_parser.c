#include "parser.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void put_be16(unsigned char *dst, uint16_t value)
{
    dst[0] = (unsigned char)(value >> 8);
    dst[1] = (unsigned char)(value & 0xffU);
}

static void build_tcp_packet(unsigned char *packet, size_t *packet_len)
{
    memset(packet, 0, 64);

    put_be16(packet + 12, 0x0800);
    packet[14] = 0x45;
    put_be16(packet + 16, 40);
    packet[22] = 64;
    packet[23] = 6;
    packet[26] = 192;
    packet[27] = 0;
    packet[28] = 2;
    packet[29] = 1;
    packet[30] = 198;
    packet[31] = 51;
    packet[32] = 100;
    packet[33] = 2;
    put_be16(packet + 34, 12345);
    put_be16(packet + 36, 80);
    packet[46] = 0x50;
    packet[47] = 0x02;
    *packet_len = 54;
}

static void test_parse_tcp_packet(void)
{
    unsigned char packet[64];
    size_t packet_len;
    packet_header_t header;
    packet_info_t info;
    char error[128];

    build_tcp_packet(packet, &packet_len);
    memset(&header, 0, sizeof(header));
    header.length = (uint32_t)packet_len;
    header.captured_length = (uint32_t)packet_len;
    header.timestamp.tv_sec = 100;

    assert(parser_parse_packet(&header, packet, &info, error, sizeof(error)));
    assert(info.protocol == PACKET_PROTO_TCP);
    assert(strcmp(info.src_ip, "192.0.2.1") == 0);
    assert(strcmp(info.dst_ip, "198.51.100.2") == 0);
    assert(info.src_port == 12345);
    assert(info.dst_port == 80);
    assert(info.tcp_syn);
    assert(!info.tcp_ack);
}

static void test_truncated_packet_is_safe(void)
{
    unsigned char packet[8] = {0};
    packet_header_t header;
    packet_info_t info;
    char error[128];

    memset(&header, 0, sizeof(header));
    header.length = sizeof(packet);
    header.captured_length = sizeof(packet);

    assert(!parser_parse_packet(&header, packet, &info, error, sizeof(error)));
}

int main(void)
{
    test_parse_tcp_packet();
    test_truncated_packet_is_safe();
    puts("test_parser: ok");
    return 0;
}
