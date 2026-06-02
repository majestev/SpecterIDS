#include "parser.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static size_t load_hex_fixture(const char *path, unsigned char *buffer, size_t buffer_size)
{
    FILE *fp = fopen(path, "r");
    int high = -1;
    int c;
    size_t len = 0;

    assert(fp != NULL);
    while ((c = fgetc(fp)) != EOF) {
        int value;

        if (isspace((unsigned char)c)) {
            continue;
        }
        value = hex_value(c);
        assert(value >= 0);
        if (high < 0) {
            high = value;
        } else {
            assert(len < buffer_size);
            buffer[len++] = (unsigned char)((high << 4) | value);
            high = -1;
        }
    }
    assert(high < 0);
    assert(fclose(fp) == 0);
    return len;
}

static bool parse_fixture(const char *path, packet_info_t *info)
{
    unsigned char packet[256];
    packet_header_t header;
    char error[128];
    size_t packet_len = load_hex_fixture(path, packet, sizeof(packet));

    memset(&header, 0, sizeof(header));
    header.length = (uint32_t)packet_len;
    header.captured_length = (uint32_t)packet_len;
    header.datalink_type = DLT_EN10MB;
    header.timestamp.tv_sec = 100;
    return parser_parse_packet(&header, packet, info, error, sizeof(error));
}

static void test_ipv4_tcp_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv4_tcp.hex", &info));
    assert(info.ip_version == 4);
    assert(info.protocol == PACKET_PROTO_TCP);
    assert(strcmp(info.src_ip, "192.0.2.1") == 0);
    assert(strcmp(info.dst_ip, "198.51.100.2") == 0);
    assert(info.src_port == 12345);
    assert(info.dst_port == 80);
    assert(info.tcp_syn);
    assert(!info.tcp_ack);
}

static void test_ipv4_udp_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv4_udp.hex", &info));
    assert(info.ip_version == 4);
    assert(info.protocol == PACKET_PROTO_UDP);
    assert(info.src_port == 12345);
    assert(info.dst_port == 53);
    assert(info.dns);
}

static void test_ipv4_icmp_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv4_icmp.hex", &info));
    assert(info.ip_version == 4);
    assert(info.protocol == PACKET_PROTO_ICMP);
}

static void test_ipv6_tcp_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv6_tcp.hex", &info));
    assert(info.ip_version == 6);
    assert(info.protocol == PACKET_PROTO_TCP);
    assert(strcmp(info.src_ip, "2001:db8::1") == 0);
    assert(strcmp(info.dst_ip, "2001:db8::2") == 0);
    assert(info.src_port == 12345);
    assert(info.dst_port == 80);
}

static void test_ipv6_udp_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv6_udp.hex", &info));
    assert(info.ip_version == 6);
    assert(info.protocol == PACKET_PROTO_UDP);
    assert(info.dst_port == 53);
}

static void test_ipv6_icmpv6_fixture(void)
{
    packet_info_t info;

    assert(parse_fixture("tests/fixtures/ethernet_ipv6_icmpv6.hex", &info));
    assert(info.ip_version == 6);
    assert(info.protocol == PACKET_PROTO_ICMPV6);
}

static void test_truncated_and_unknown_are_safe(void)
{
    packet_info_t info;
    unsigned char packet[256];
    packet_header_t header;
    char error[128];
    size_t packet_len = load_hex_fixture("tests/fixtures/ethernet_ipv4_tcp.hex", packet, sizeof(packet));

    assert(!parse_fixture("tests/fixtures/truncated.hex", &info));
    assert(!parse_fixture("tests/fixtures/unknown_ethertype.hex", &info));

    memset(&header, 0, sizeof(header));
    header.length = (uint32_t)packet_len;
    header.captured_length = (uint32_t)packet_len;
    header.datalink_type = 999999;
    assert(!parser_parse_packet(&header, packet, &info, error, sizeof(error)));
    assert(strstr(error, "unsupported datalink") != NULL);
}

static void test_linux_sll_fixture(void)
{
    unsigned char ethernet[256];
    unsigned char packet[256];
    packet_info_t info;
    packet_header_t header;
    char error[128];
    size_t ethernet_len = load_hex_fixture("tests/fixtures/ethernet_ipv4_tcp.hex", ethernet, sizeof(ethernet));
    size_t network_len = ethernet_len - 14U;
    size_t packet_len = 16U + network_len;

    memset(packet, 0, sizeof(packet));
    packet[4] = 0x00U;
    packet[5] = 0x06U;
    memcpy(packet + 6U, ethernet + 6U, 6U);
    packet[14] = 0x08U;
    packet[15] = 0x00U;
    memcpy(packet + 16U, ethernet + 14U, network_len);

    memset(&header, 0, sizeof(header));
    header.length = (uint32_t)packet_len;
    header.captured_length = (uint32_t)packet_len;
    header.datalink_type = DLT_LINUX_SLL;

    assert(parser_parse_packet(&header, packet, &info, error, sizeof(error)));
    assert(info.ip_version == 4);
    assert(info.protocol == PACKET_PROTO_TCP);
    assert(strcmp(info.src_mac, "66:77:88:99:aa:bb") == 0);
}

static void test_raw_ipv6_fixture(void)
{
    unsigned char ethernet[256];
    packet_info_t info;
    packet_header_t header;
    char error[128];
    size_t ethernet_len = load_hex_fixture("tests/fixtures/ethernet_ipv6_udp.hex", ethernet, sizeof(ethernet));
    const unsigned char *raw = ethernet + 14U;
    size_t raw_len = ethernet_len - 14U;

    memset(&header, 0, sizeof(header));
    header.length = (uint32_t)raw_len;
    header.captured_length = (uint32_t)raw_len;
    header.datalink_type = DLT_RAW;

    assert(parser_parse_packet(&header, raw, &info, error, sizeof(error)));
    assert(info.ip_version == 6);
    assert(info.protocol == PACKET_PROTO_UDP);
}

int main(void)
{
    test_ipv4_tcp_fixture();
    test_ipv4_udp_fixture();
    test_ipv4_icmp_fixture();
    test_ipv6_tcp_fixture();
    test_ipv6_udp_fixture();
    test_ipv6_icmpv6_fixture();
    test_truncated_and_unknown_are_safe();
    test_linux_sll_fixture();
    test_raw_ipv6_fixture();
    puts("test_parser: ok");
    return 0;
}
