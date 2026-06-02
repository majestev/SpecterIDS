#include "parser.h"

#if defined(__has_include)
#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#elif __has_include(<pcap.h>)
#include <pcap.h>
#else
#include <pcap.h>
#endif
#else
#include <pcap.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void replay_pcap(const char *path, size_t expected_ok_min, size_t expected_errors_min)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr *header;
    int datalink;
    int rc;
    size_t ok = 0;
    size_t errors = 0;

    memset(errbuf, 0, sizeof(errbuf));
    pcap = pcap_open_offline(path, errbuf);
    assert(pcap != NULL);
    datalink = pcap_datalink(pcap);

    while ((rc = pcap_next_ex(pcap, &header, &data)) == 1) {
        packet_header_t ids_header;
        packet_info_t info;
        char error[128];

        memset(&ids_header, 0, sizeof(ids_header));
        ids_header.length = header->len;
        ids_header.captured_length = header->caplen;
        ids_header.datalink_type = datalink;
        ids_header.timestamp = header->ts;

        if (parser_parse_packet(&ids_header, data, &info, error, sizeof(error))) {
            ok++;
        } else {
            errors++;
        }
    }

    assert(rc == PCAP_ERROR_BREAK);
    pcap_close(pcap);
    assert(ok >= expected_ok_min);
    assert(errors >= expected_errors_min);
}

int main(void)
{
    replay_pcap("samples/example.pcap", 1, 0);
    replay_pcap("tests/pcaps/ipv6.pcap", 1, 0);
    replay_pcap("tests/pcaps/malformed.pcap", 0, 1);
    replay_pcap("tests/pcaps/portscan.pcap", 1, 0);
    replay_pcap("tests/pcaps/bruteforce.pcap", 1, 0);
    replay_pcap("tests/pcaps/synflood.pcap", 1, 0);
    replay_pcap("tests/pcaps/beaconing.pcap", 1, 0);
    puts("test_pcap_regression: ok");
    return 0;
}
