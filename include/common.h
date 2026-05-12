#ifndef SPECTERIDS_COMMON_H
#define SPECTERIDS_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SPECTERIDS_VERSION "3.0.0"
#define SPECTERIDS_IP_STR_LEN 46
#define SPECTERIDS_REASON_LEN 256
#define SPECTERIDS_PATH_LEN 4096
#define SPECTERIDS_BPF_LEN 256
#define SPECTERIDS_IFACE_LEN 64
#define SPECTERIDS_MAC_STR_LEN 18
#define SPECTERIDS_MODE_LEN 32
#define SPECTERIDS_LOG_LEVEL_LEN 16
#define SPECTERIDS_LIST_LEN 512
#define SPECTERIDS_CORRELATION_ID_LEN 32
#define SPECTERIDS_MAX_PACKET_BYTES 4096
#define SPECTERIDS_MAX_ALERTS_PER_PACKET 16
#define SPECTERIDS_MAX_SENSITIVE_PORTS 64
#define SPECTERIDS_DEFAULT_QUEUE_SIZE 1024
#define SPECTERIDS_DEFAULT_WORKERS 2

typedef enum {
    IDS_SEVERITY_LOW = 0,
    IDS_SEVERITY_MEDIUM,
    IDS_SEVERITY_HIGH,
    IDS_SEVERITY_CRITICAL,
    IDS_SEVERITY_COUNT
} ids_severity_t;

const char *ids_severity_name(ids_severity_t severity);
bool ids_parse_severity(const char *value, ids_severity_t *out);
bool ids_parse_bool(const char *value, bool *out);
void ids_copy_string(char *dst, size_t dst_size, const char *src);
char *ids_trim(char *value);

#endif
