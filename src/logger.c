#include "logger.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

static int ensure_log_dir(const char *path)
{
    struct stat statbuf;

    if (mkdir(path, 0755) == 0) {
        return 0;
    }

    if (errno == EEXIST) {
        if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
            return 0;
        }
        errno = ENOTDIR;
        return -1;
    }

    return -1;
}

void logger_format_timestamp(const struct timeval *timestamp,
                             bool iso8601,
                             char *buffer,
                             size_t buffer_size)
{
    time_t seconds;
    struct tm local_time;

    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    if (timestamp == NULL) {
        snprintf(buffer, buffer_size, "unknown-time");
        return;
    }

    seconds = timestamp->tv_sec;
    if (localtime_r(&seconds, &local_time) == NULL) {
        snprintf(buffer, buffer_size, "unknown-time");
        return;
    }

    strftime(buffer, buffer_size, iso8601 ? "%Y-%m-%dT%H:%M:%S" : "%Y-%m-%d %H:%M:%S", &local_time);
}

static void json_write_string(FILE *fp, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)(value != NULL ? value : "");

    fputc('"', fp);
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"':
            fputs("\\\"", fp);
            break;
        case '\\':
            fputs("\\\\", fp);
            break;
        case '\n':
            fputs("\\n", fp);
            break;
        case '\r':
            fputs("\\r", fp);
            break;
        case '\t':
            fputs("\\t", fp);
            break;
        default:
            if (*cursor < 0x20U) {
                fprintf(fp, "\\u%04x", *cursor);
            } else {
                fputc(*cursor, fp);
            }
            break;
        }
        cursor++;
    }
    fputc('"', fp);
}

static int build_log_path(char *dst, size_t dst_size, const char *dir, const char *file)
{
    int written;

    written = snprintf(dst, dst_size, "%s/%s", dir, file);
    if (written < 0 || (size_t)written >= dst_size) {
        return -1;
    }

    return 0;
}

static uint64_t file_size_or_zero(const char *path)
{
    struct stat statbuf;

    if (path == NULL || stat(path, &statbuf) != 0 || statbuf.st_size < 0) {
        return 0;
    }

    return (uint64_t)statbuf.st_size;
}

static void rotate_file_if_needed(FILE **file, const char *path, uint64_t *bytes_written, uint64_t limit)
{
    char rotated[SPECTERIDS_PATH_LEN];

    if (file == NULL || *file == NULL || path == NULL || bytes_written == NULL || limit == 0 ||
        *bytes_written < limit) {
        return;
    }

    if (snprintf(rotated, sizeof(rotated), "%s.1", path) < 0 ||
        strlen(path) + 2U >= sizeof(rotated)) {
        return;
    }

    fclose(*file);
    *file = NULL;
    (void)rename(path, rotated);
    *file = fopen(path, "a");
    if (*file != NULL) {
        setvbuf(*file, NULL, _IOLBF, 0);
        *bytes_written = 0;
    }
}

static void write_pcap_global_header(FILE *fp)
{
    uint32_t magic = 0xa1b2c3d4U;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = SPECTERIDS_MAX_PACKET_BYTES;
    uint32_t network = 1;

    (void)fwrite(&magic, sizeof(magic), 1, fp);
    (void)fwrite(&version_major, sizeof(version_major), 1, fp);
    (void)fwrite(&version_minor, sizeof(version_minor), 1, fp);
    (void)fwrite(&thiszone, sizeof(thiszone), 1, fp);
    (void)fwrite(&sigfigs, sizeof(sigfigs), 1, fp);
    (void)fwrite(&snaplen, sizeof(snaplen), 1, fp);
    (void)fwrite(&network, sizeof(network), 1, fp);
}

static void write_pcap_packet(FILE *fp,
                              const packet_header_t *header,
                              const unsigned char *data,
                              size_t data_len)
{
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;

    if (fp == NULL || header == NULL || data == NULL || data_len == 0) {
        return;
    }

    ts_sec = (uint32_t)header->timestamp.tv_sec;
    ts_usec = (uint32_t)header->timestamp.tv_usec;
    incl_len = (uint32_t)data_len;
    orig_len = header->length;

    (void)fwrite(&ts_sec, sizeof(ts_sec), 1, fp);
    (void)fwrite(&ts_usec, sizeof(ts_usec), 1, fp);
    (void)fwrite(&incl_len, sizeof(incl_len), 1, fp);
    (void)fwrite(&orig_len, sizeof(orig_len), 1, fp);
    (void)fwrite(data, data_len, 1, fp);
}

static void print_packet_line(FILE *fp, const packet_info_t *packet, const char *timestamp)
{
    if (packet->protocol == PACKET_PROTO_TCP || packet->protocol == PACKET_PROTO_UDP) {
        fprintf(fp,
                "[%s] [%s] src=%s:%u dst=%s:%u len=%u caplen=%u%s%s\n",
                timestamp,
                parser_protocol_name(packet->protocol),
                packet->src_ip,
                packet->src_port,
                packet->dst_ip,
                packet->dst_port,
                packet->length,
                packet->captured_length,
                packet->truncated ? " truncated=true" : "",
                packet->fragmented ? " fragmented=true" : "");
    } else {
        fprintf(fp,
                "[%s] [%s] src=%s dst=%s len=%u caplen=%u%s%s\n",
                timestamp,
                parser_protocol_name(packet->protocol),
                packet->src_ip,
                packet->dst_ip,
                packet->length,
                packet->captured_length,
                packet->truncated ? " truncated=true" : "",
                packet->fragmented ? " fragmented=true" : "");
    }
}

int logger_init(logger_t *logger,
                const char *log_dir,
                bool json_enabled,
                bool verbose,
                bool quiet,
                uint64_t rotation_size_bytes,
                const char *capture_dir,
                bool pcap_export_enabled,
                bool compress_logs,
                int suspicious_context_packets)
{
    if (logger == NULL || log_dir == NULL || log_dir[0] == '\0') {
        return -1;
    }

    memset(logger, 0, sizeof(*logger));
    logger->json_enabled = json_enabled;
    logger->verbose = verbose;
    logger->quiet = quiet;
    logger->rotation_size_bytes = rotation_size_bytes;
    logger->pcap_export_enabled = pcap_export_enabled;
    logger->compress_logs = compress_logs;
    if (suspicious_context_packets < 0) {
        suspicious_context_packets = 0;
    }
    if (suspicious_context_packets > LOGGER_CONTEXT_MAX) {
        suspicious_context_packets = LOGGER_CONTEXT_MAX;
    }
    logger->context_limit = (size_t)suspicious_context_packets;

    if (ensure_log_dir(log_dir) != 0) {
        fprintf(stderr, "Failed to create log directory '%s': %s\n", log_dir, strerror(errno));
        return -1;
    }

    if (build_log_path(logger->system_log_path,
                       sizeof(logger->system_log_path),
                       log_dir,
                       "specterids.log") != 0 ||
        build_log_path(logger->alert_log_path,
                       sizeof(logger->alert_log_path),
                       log_dir,
                       "alerts.log") != 0 ||
        build_log_path(logger->alert_json_path,
                       sizeof(logger->alert_json_path),
                       log_dir,
                       "alerts.jsonl") != 0) {
        fprintf(stderr, "Log path is too long\n");
        return -1;
    }
    logger->system_bytes_written = file_size_or_zero(logger->system_log_path);
    logger->alert_bytes_written = file_size_or_zero(logger->alert_log_path);
    logger->alert_json_bytes_written = file_size_or_zero(logger->alert_json_path);

    if (pthread_mutex_init(&logger->lock, NULL) != 0) {
        fprintf(stderr, "Failed to initialize logger mutex\n");
        return -1;
    }
    logger->initialized = true;

    logger->system_file = fopen(logger->system_log_path, "a");
    if (logger->system_file == NULL) {
        fprintf(stderr, "Failed to open log '%s': %s\n", logger->system_log_path, strerror(errno));
        logger_close(logger);
        return -1;
    }

    logger->alerts_text_file = fopen(logger->alert_log_path, "a");
    if (logger->alerts_text_file == NULL) {
        fprintf(stderr, "Failed to open alert log '%s': %s\n", logger->alert_log_path, strerror(errno));
        logger_close(logger);
        return -1;
    }

    if (json_enabled) {
        logger->alerts_json_file = fopen(logger->alert_json_path, "a");
        if (logger->alerts_json_file == NULL) {
            fprintf(stderr, "Failed to open JSON alert log '%s': %s\n", logger->alert_json_path, strerror(errno));
            logger_close(logger);
            return -1;
        }
    }

    if (pcap_export_enabled) {
        if (capture_dir == NULL || capture_dir[0] == '\0') {
            capture_dir = "captures";
        }
        if (ensure_log_dir(capture_dir) != 0) {
            fprintf(stderr, "Failed to create capture directory '%s': %s\n", capture_dir, strerror(errno));
            logger_close(logger);
            return -1;
        }
        if (build_log_path(logger->pcap_path,
                           sizeof(logger->pcap_path),
                           capture_dir,
                           "suspicious.pcap") != 0) {
            fprintf(stderr, "PCAP path is too long\n");
            logger_close(logger);
            return -1;
        }
        logger->pcap_file = fopen(logger->pcap_path, "wb");
        if (logger->pcap_file == NULL) {
            fprintf(stderr, "Failed to open PCAP export '%s': %s\n", logger->pcap_path, strerror(errno));
            logger_close(logger);
            return -1;
        }
        write_pcap_global_header(logger->pcap_file);
    }

    setvbuf(logger->system_file, NULL, _IOLBF, 0);
    setvbuf(logger->alerts_text_file, NULL, _IOLBF, 0);
    if (logger->alerts_json_file != NULL) {
        setvbuf(logger->alerts_json_file, NULL, _IOLBF, 0);
    }
    if (logger->pcap_file != NULL) {
        setvbuf(logger->pcap_file, NULL, _IOLBF, 0);
    }

    logger_log_status(logger, "INFO", "logger initialized");
    if (compress_logs) {
        logger_log_status(logger, "WARN", "compress_logs requested; external logrotate compression is recommended in this build");
    }
    return 0;
}

void logger_close(logger_t *logger)
{
    if (logger == NULL || !logger->initialized) {
        return;
    }

    pthread_mutex_lock(&logger->lock);
    if (logger->system_file != NULL) {
        fclose(logger->system_file);
        logger->system_file = NULL;
    }
    if (logger->alerts_text_file != NULL) {
        fclose(logger->alerts_text_file);
        logger->alerts_text_file = NULL;
    }
    if (logger->alerts_json_file != NULL) {
        fclose(logger->alerts_json_file);
        logger->alerts_json_file = NULL;
    }
    if (logger->pcap_file != NULL) {
        fclose(logger->pcap_file);
        logger->pcap_file = NULL;
    }
    pthread_mutex_unlock(&logger->lock);
    pthread_mutex_destroy(&logger->lock);
    logger->initialized = false;
}

void logger_log_status(logger_t *logger, const char *level, const char *message)
{
    struct timeval now;
    char timestamp[32];

    if (logger == NULL || logger->system_file == NULL || level == NULL || message == NULL) {
        return;
    }

    gettimeofday(&now, NULL);
    logger_format_timestamp(&now, false, timestamp, sizeof(timestamp));

    pthread_mutex_lock(&logger->lock);
    logger->system_bytes_written += (uint64_t)fprintf(logger->system_file, "[%s] [%s] %s\n", timestamp, level, message);
    rotate_file_if_needed(&logger->system_file,
                          logger->system_log_path,
                          &logger->system_bytes_written,
                          logger->rotation_size_bytes);
    pthread_mutex_unlock(&logger->lock);
}

int logger_log_packet(logger_t *logger, const packet_info_t *packet)
{
    char timestamp[32];

    if (logger == NULL || packet == NULL || logger->system_file == NULL) {
        return -1;
    }

    logger_format_timestamp(&packet->timestamp, false, timestamp, sizeof(timestamp));

    pthread_mutex_lock(&logger->lock);
    print_packet_line(logger->system_file, packet, timestamp);
    logger->system_bytes_written += 128U;
    rotate_file_if_needed(&logger->system_file,
                          logger->system_log_path,
                          &logger->system_bytes_written,
                          logger->rotation_size_bytes);
    if (logger->verbose && !logger->quiet) {
        print_packet_line(stdout, packet, timestamp);
    }
    pthread_mutex_unlock(&logger->lock);

    return 0;
}

int logger_log_packet_raw(logger_t *logger,
                          const packet_info_t *packet,
                          const packet_header_t *header,
                          const unsigned char *data,
                          size_t data_len)
{
    int rc;

    rc = logger_log_packet(logger, packet);
    if (logger == NULL || header == NULL || data == NULL || data_len == 0 || logger->context_limit == 0) {
        return rc;
    }

    pthread_mutex_lock(&logger->lock);
    logger->context_packets[logger->context_index].header = *header;
    logger->context_packets[logger->context_index].data_len =
        data_len > SPECTERIDS_MAX_PACKET_BYTES ? SPECTERIDS_MAX_PACKET_BYTES : data_len;
    memcpy(logger->context_packets[logger->context_index].data,
           data,
           logger->context_packets[logger->context_index].data_len);
    logger->context_index = (logger->context_index + 1U) % logger->context_limit;
    if (logger->context_count < logger->context_limit) {
        logger->context_count++;
    }
    pthread_mutex_unlock(&logger->lock);
    return rc;
}

int logger_log_alert(logger_t *logger, const alert_t *alert)
{
    char text_timestamp[32];
    char json_timestamp[32];

    if (logger == NULL || alert == NULL || logger->alerts_text_file == NULL) {
        return -1;
    }

    logger_format_timestamp(&alert->timestamp, false, text_timestamp, sizeof(text_timestamp));
    logger_format_timestamp(&alert->timestamp, true, json_timestamp, sizeof(json_timestamp));

    pthread_mutex_lock(&logger->lock);
    logger->alert_bytes_written += (uint64_t)fprintf(logger->alerts_text_file,
                                                     "[%s] [%s] [%s] src=%s dst=%s risk=%d cid=%s reason=\"%s\"\n",
                                                     text_timestamp,
                                                     ids_severity_name(alert->severity),
                                                     detection_alert_type_name(alert->type),
                                                     alert->source_ip,
                                                     alert->destination_ip,
                                                     alert->risk_score,
                                                     alert->correlation_id,
                                                     alert->reason);

    if (logger->alerts_json_file != NULL) {
        fputs("{\"timestamp\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, json_timestamp);
        fputs(",\"severity\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, ids_severity_name(alert->severity));
        fputs(",\"type\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, detection_alert_type_name(alert->type));
        fputs(",\"src_ip\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, alert->source_ip);
        fputs(",\"dst_ip\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, alert->destination_ip);
        fputs(",\"reason\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, alert->reason);
        fputs(",\"risk_score\":", logger->alerts_json_file);
        fprintf(logger->alerts_json_file, "%d", alert->risk_score);
        fputs(",\"correlation_id\":", logger->alerts_json_file);
        json_write_string(logger->alerts_json_file, alert->correlation_id);
        fputs("}\n", logger->alerts_json_file);
        logger->alert_json_bytes_written += 256U;
    }

    rotate_file_if_needed(&logger->alerts_text_file,
                          logger->alert_log_path,
                          &logger->alert_bytes_written,
                          logger->rotation_size_bytes);
    rotate_file_if_needed(&logger->alerts_json_file,
                          logger->alert_json_path,
                          &logger->alert_json_bytes_written,
                          logger->rotation_size_bytes);

    if (!logger->quiet) {
        printf("[%s] [%s] [%s] src=%s dst=%s risk=%d reason=\"%s\"\n",
               text_timestamp,
               ids_severity_name(alert->severity),
               detection_alert_type_name(alert->type),
               alert->source_ip,
               alert->destination_ip,
               alert->risk_score,
               alert->reason);
        fflush(stdout);
    }
    pthread_mutex_unlock(&logger->lock);

    return 0;
}

int logger_log_alerts(logger_t *logger,
                      const alert_t *alerts,
                      size_t alert_count,
                      const packet_header_t *header,
                      const unsigned char *data,
                      size_t data_len)
{
    size_t i;

    if (logger == NULL || alerts == NULL) {
        return -1;
    }

    for (i = 0; i < alert_count; i++) {
        (void)logger_log_alert(logger, &alerts[i]);
    }

    if (alert_count > 0 && logger->pcap_file != NULL) {
        size_t i;
        pthread_mutex_lock(&logger->lock);
        for (i = 0; i < logger->context_count; i++) {
            size_t index = (logger->context_index + LOGGER_CONTEXT_MAX - logger->context_count + i) % logger->context_limit;
            write_pcap_packet(logger->pcap_file,
                              &logger->context_packets[index].header,
                              logger->context_packets[index].data,
                              logger->context_packets[index].data_len);
        }
        if (logger->context_count == 0) {
            write_pcap_packet(logger->pcap_file, header, data, data_len);
        }
        pthread_mutex_unlock(&logger->lock);
    }

    return 0;
}
