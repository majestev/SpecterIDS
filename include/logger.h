#ifndef SPECTERIDS_LOGGER_H
#define SPECTERIDS_LOGGER_H

#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>

#include "common.h"
#include "detection.h"
#include "parser.h"

#define LOGGER_CONTEXT_MAX 32

typedef struct {
    packet_header_t header;
    size_t data_len;
    unsigned char data[SPECTERIDS_MAX_PACKET_BYTES];
} logger_context_packet_t;

typedef struct {
    FILE *system_file;
    FILE *alerts_text_file;
    FILE *alerts_json_file;
    bool json_enabled;
    bool verbose;
    bool quiet;
    bool initialized;
    bool pcap_export_enabled;
    bool compress_logs;
    uint64_t rotation_size_bytes;
    uint64_t system_bytes_written;
    uint64_t alert_bytes_written;
    uint64_t alert_json_bytes_written;
    FILE *pcap_file;
    char pcap_path[SPECTERIDS_PATH_LEN];
    logger_context_packet_t context_packets[LOGGER_CONTEXT_MAX];
    size_t context_count;
    size_t context_index;
    size_t context_limit;
    char system_log_path[SPECTERIDS_PATH_LEN];
    char alert_log_path[SPECTERIDS_PATH_LEN];
    char alert_json_path[SPECTERIDS_PATH_LEN];
    pthread_mutex_t lock;
} logger_t;

int logger_init(logger_t *logger,
                const char *log_dir,
                bool json_enabled,
                bool verbose,
                bool quiet,
                uint64_t rotation_size_bytes,
                const char *capture_dir,
                bool pcap_export_enabled,
                bool compress_logs,
                int suspicious_context_packets);
void logger_close(logger_t *logger);

int logger_log_packet(logger_t *logger, const packet_info_t *packet);
int logger_log_packet_raw(logger_t *logger,
                          const packet_info_t *packet,
                          const packet_header_t *header,
                          const unsigned char *data,
                          size_t data_len);
int logger_log_alert(logger_t *logger, const alert_t *alert);
int logger_log_alerts(logger_t *logger,
                      const alert_t *alerts,
                      size_t alert_count,
                      const packet_header_t *header,
                      const unsigned char *data,
                      size_t data_len);
void logger_log_status(logger_t *logger, const char *level, const char *message);
void logger_format_timestamp(const struct timeval *timestamp,
                             bool iso8601,
                             char *buffer,
                             size_t buffer_size);

#endif
