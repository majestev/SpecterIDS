#ifndef SPECTERIDS_COMMON_H
#define SPECTERIDS_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

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

/* FNV-1a 64-bit hash over a NUL-terminated string */
static inline uint64_t ids_fnv1a_str(const char *s)
{
    uint64_t hash = 14695981039346656037ULL;
    const unsigned char *cursor = (const unsigned char *)s;

    while (cursor != NULL && *cursor != '\0') {
        hash ^= (uint64_t)*cursor++;
        hash *= 1099511628211ULL;
    }

    return hash;
}

/* Monotonic nanosecond clock — shared to avoid per-TU duplication */
static inline uint64_t ids_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

const char *ids_severity_name(ids_severity_t severity);
bool ids_parse_severity(const char *value, ids_severity_t *out);
bool ids_parse_bool(const char *value, bool *out);
void ids_copy_string(char *dst, size_t dst_size, const char *src);
char *ids_trim(char *value);

#endif
