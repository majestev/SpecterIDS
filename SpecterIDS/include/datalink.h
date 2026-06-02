#ifndef SPECTERIDS_DATALINK_H
#define SPECTERIDS_DATALINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common.h"

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#define IDS_ETHERTYPE_IPV4 0x0800U
#define IDS_ETHERTYPE_ARP 0x0806U
#define IDS_ETHERTYPE_IPV6 0x86DDU

typedef struct {
    const uint8_t *network_payload;
    size_t network_len;
    uint16_t ethertype;
    char src_mac[SPECTERIDS_MAC_STR_LEN];
    char dst_mac[SPECTERIDS_MAC_STR_LEN];
} datalink_frame_t;

int datalink_parse(int datalink_type,
                   const uint8_t *packet,
                   size_t packet_len,
                   const uint8_t **network_payload,
                   size_t *network_len,
                   uint16_t *ethertype);

int datalink_parse_frame(int datalink_type,
                         const uint8_t *packet,
                         size_t packet_len,
                         datalink_frame_t *frame,
                         char *error,
                         size_t error_size);

bool datalink_is_supported(int datalink_type);
const char *datalink_type_name(int datalink_type);

#endif
