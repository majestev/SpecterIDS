#include "parser.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

int main(void)
{
    unsigned char buffer[SPECTERIDS_MAX_PACKET_BYTES];
    packet_header_t header;
    packet_info_t info;
    char error[128];
    uint32_t seed = 0x51515151U;
    size_t i;

    memset(&header, 0, sizeof(header));

    for (i = 0; i < 5000; i++) {
        size_t len = xorshift32(&seed) % sizeof(buffer);
        size_t j;

        for (j = 0; j < len; j++) {
            buffer[j] = (unsigned char)(xorshift32(&seed) & 0xffU);
        }

        header.length = (uint32_t)len;
        header.captured_length = (uint32_t)len;
        header.timestamp.tv_sec = (time_t)i;
        (void)parser_parse_packet(&header, buffer, &info, error, sizeof(error));
    }

    puts("fuzz_parser: ok");
    return 0;
}
