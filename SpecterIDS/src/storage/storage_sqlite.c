#include "storage_sqlite.h"

#include "common.h"
#include "detection.h"
#include "parser.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#ifdef SPECTERIDS_ENABLE_SQLITE
#include <sqlite3.h>

static uint64_t storage_monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}
#endif

struct storage_sqlite {
    bool enabled;
    char path[SPECTERIDS_PATH_LEN];
    long long session_id;
    ids_stats_t *stats;
    uint64_t retries; /* SQLITE_BUSY retries since open; visible to stats */
    pthread_mutex_t lock;
#ifdef SPECTERIDS_ENABLE_SQLITE
    sqlite3 *db;
    sqlite3_stmt *insert_packet;
    sqlite3_stmt *insert_alert;
    sqlite3_stmt *insert_detection;
#endif
};

storage_sqlite_t *storage_sqlite_create(void)
{
    storage_sqlite_t *storage = calloc(1, sizeof(storage_sqlite_t));

    if (storage == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&storage->lock, NULL) != 0) {
        free(storage);
        return NULL;
    }
    return storage;
}

bool storage_sqlite_compiled(void)
{
#ifdef SPECTERIDS_ENABLE_SQLITE
    return true;
#else
    return false;
#endif
}

void storage_sqlite_attach_stats(storage_sqlite_t *storage, ids_stats_t *stats)
{
    if (storage == NULL) {
        return;
    }

    pthread_mutex_lock(&storage->lock);
    storage->stats = stats;
    pthread_mutex_unlock(&storage->lock);
}

#ifdef SPECTERIDS_ENABLE_SQLITE
static void format_timestamp(const struct timeval *timestamp, char *buffer, size_t buffer_size)
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
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S", &local_time);
}

static void ensure_parent_dir(const char *path)
{
    char copy[SPECTERIDS_PATH_LEN];
    char *slash;

    if (path == NULL || strlen(path) >= sizeof(copy)) {
        return;
    }

    ids_copy_string(copy, sizeof(copy), path);
    slash = strrchr(copy, '/');
    if (slash == NULL || slash == copy) {
        return;
    }
    *slash = '\0';
    if (mkdir(copy, 0755) != 0 && errno != EEXIST) {
        return;
    }
}

static int exec_sql(sqlite3 *db, const char *sql)
{
    char *error = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", error != NULL ? error : "unknown");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int step_with_retry(storage_sqlite_t *storage, sqlite3_stmt *stmt)
{
    static const unsigned int delays_ms[] = {10U, 25U, 50U};
    unsigned int attempt;
    int rc;

    for (attempt = 0; attempt <= 3U; attempt++) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            return 0;
        }
        if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
            break;
        }
        if (attempt < 3U) {
            storage->retries++;
            ids_stats_record_storage_retry(storage->stats);
            sqlite3_reset(stmt);
            sqlite3_sleep((int)delays_ms[attempt]);
        }
    }

    fprintf(stderr, "SQLite statement failed: %s\n", sqlite3_errmsg(storage->db));
    return -1;
}

static void record_storage_result(storage_sqlite_t *storage, int result, uint64_t elapsed_ns)
{
    if (storage == NULL || storage->stats == NULL) {
        return;
    }

    if (result == 0) {
        ids_stats_record_storage_write(storage->stats, 1);
        if (elapsed_ns > 0) {
            ids_stats_record_storage_time(storage->stats, elapsed_ns);
        }
    } else {
        ids_stats_record_storage_error(storage->stats, 1);
    }
}

static int prepare_statements(storage_sqlite_t *storage)
{
    const char *packet_sql =
        "INSERT INTO packet_summary(session_id,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,"
        "ip_version,ether_type,truncated,fragmented) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)";
    const char *alert_sql =
        "INSERT INTO alerts(session_id,timestamp,severity,type,src_ip,dst_ip,reason,risk_score,correlation_id) "
        "VALUES(?,?,?,?,?,?,?,?,?)";
    const char *detection_sql =
        "INSERT INTO detections(session_id,timestamp,src_ip,dst_ip,protocol,alert_count) "
        "VALUES(?,?,?,?,?,?)";

    if (sqlite3_prepare_v2(storage->db, packet_sql, -1, &storage->insert_packet, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(storage->db, alert_sql, -1, &storage->insert_alert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(storage->db, detection_sql, -1, &storage->insert_detection, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite prepare failed: %s\n", sqlite3_errmsg(storage->db));
        return -1;
    }
    return 0;
}

static void close_sqlite_handles(storage_sqlite_t *storage)
{
    if (storage == NULL) {
        return;
    }

    if (storage->insert_packet != NULL) {
        sqlite3_finalize(storage->insert_packet);
        storage->insert_packet = NULL;
    }
    if (storage->insert_alert != NULL) {
        sqlite3_finalize(storage->insert_alert);
        storage->insert_alert = NULL;
    }
    if (storage->insert_detection != NULL) {
        sqlite3_finalize(storage->insert_detection);
        storage->insert_detection = NULL;
    }
    if (storage->db != NULL) {
        sqlite3_close(storage->db);
        storage->db = NULL;
    }
}

static int create_schema(sqlite3 *db)
{
    return exec_sql(db,
                    "PRAGMA journal_mode=WAL;"
                    "CREATE TABLE IF NOT EXISTS sessions("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "started_at TEXT NOT NULL,"
                    "ended_at TEXT,"
                    "input_mode TEXT,"
                    "input_target TEXT,"
                    "packets_total INTEGER DEFAULT 0,"
                    "alerts_total INTEGER DEFAULT 0);"
                    "CREATE TABLE IF NOT EXISTS packet_summary("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "session_id INTEGER,"
                    "timestamp TEXT,"
                    "src_ip TEXT,"
                    "dst_ip TEXT,"
                    "protocol TEXT,"
                    "src_port INTEGER,"
                    "dst_port INTEGER,"
                    "length INTEGER,"
                    "ip_version INTEGER,"
                    "ether_type INTEGER,"
                    "truncated INTEGER,"
                    "fragmented INTEGER);"
                    "CREATE TABLE IF NOT EXISTS alerts("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "session_id INTEGER,"
                    "timestamp TEXT,"
                    "severity TEXT,"
                    "type TEXT,"
                    "src_ip TEXT,"
                    "dst_ip TEXT,"
                    "reason TEXT,"
                    "risk_score INTEGER,"
                    "correlation_id TEXT);"
                    "CREATE TABLE IF NOT EXISTS detections("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "session_id INTEGER,"
                    "timestamp TEXT,"
                    "src_ip TEXT,"
                    "dst_ip TEXT,"
                    "protocol TEXT,"
                    "alert_count INTEGER);"
                    "CREATE TABLE IF NOT EXISTS metrics("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    "session_id INTEGER,"
                    "timestamp TEXT,"
                    "packets_total INTEGER,"
                    "alerts_total INTEGER,"
                    "pps REAL,"
                    "mbps REAL,"
                    "queue_drops INTEGER,"
                    "storage_writes INTEGER,"
                    "storage_errors INTEGER,"
                    "plugin_alerts INTEGER,"
                    "ipv6_ratio REAL,"
                    "events_published INTEGER,"
                    "events_dropped INTEGER);");
}
#endif

int storage_sqlite_open(storage_sqlite_t *storage,
                        bool enabled,
                        const char *path,
                        const char *input_mode,
                        const char *input_target)
{
    struct timeval now;
    char timestamp[32];

    if (storage == NULL) {
        return -1;
    }

    storage->enabled = false;
    if (!enabled) {
        return 0;
    }

#ifndef SPECTERIDS_ENABLE_SQLITE
    (void)path;
    (void)input_mode;
    (void)input_target;
    (void)now;
    (void)timestamp;
    fprintf(stderr, "Warning: SQLite requested but this binary was built without SQLite support. Use make sqlite.\n");
    return -2;
#else
    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    ensure_parent_dir(path);
    ids_copy_string(storage->path, sizeof(storage->path), path);
    if (sqlite3_open(path, &storage->db) != SQLITE_OK) {
        fprintf(stderr, "SQLite open failed for '%s': %s\n", path, sqlite3_errmsg(storage->db));
        sqlite3_close(storage->db);
        storage->db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(storage->db, 250);

    if (create_schema(storage->db) != 0 || prepare_statements(storage) != 0) {
        close_sqlite_handles(storage);
        return -1;
    }

    gettimeofday(&now, NULL);
    format_timestamp(&now, timestamp, sizeof(timestamp));
    {
        sqlite3_stmt *stmt = NULL;
        const char *sql = "INSERT INTO sessions(started_at,input_mode,input_target) VALUES(?,?,?)";

        if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQLite session prepare failed: %s\n", sqlite3_errmsg(storage->db));
            close_sqlite_handles(storage);
            return -1;
        }
        sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, input_mode != NULL ? input_mode : "UNKNOWN", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, input_target != NULL ? input_target : "", -1, SQLITE_TRANSIENT);
        if (step_with_retry(storage, stmt) != 0) {
            sqlite3_finalize(stmt);
            record_storage_result(storage, -1, 0);
            close_sqlite_handles(storage);
            return -1;
        }
        record_storage_result(storage, 0, 0);
        sqlite3_finalize(stmt);
        storage->session_id = sqlite3_last_insert_rowid(storage->db);
    }

    storage->enabled = true;
    return 0;
#endif
}

void storage_sqlite_event_handler(const ids_event_t *event, void *user_data)
{
    storage_sqlite_t *storage = (storage_sqlite_t *)user_data;

    if (storage == NULL || event == NULL || !storage->enabled) {
        return;
    }

#ifdef SPECTERIDS_ENABLE_SQLITE
    pthread_mutex_lock(&storage->lock);
    if (event->type == IDS_EVENT_PACKET_PARSED && event->packet != NULL && storage->insert_packet != NULL) {
        char timestamp[32];
        uint64_t started_ns;
        uint64_t finished_ns;
        int result;

        format_timestamp(&event->packet->timestamp, timestamp, sizeof(timestamp));
        sqlite3_reset(storage->insert_packet);
        sqlite3_clear_bindings(storage->insert_packet);
        sqlite3_bind_int64(storage->insert_packet, 1, storage->session_id);
        sqlite3_bind_text(storage->insert_packet, 2, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_packet, 3, event->packet->src_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_packet, 4, event->packet->dst_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_packet, 5, parser_protocol_name(event->packet->protocol), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(storage->insert_packet, 6, event->packet->src_port);
        sqlite3_bind_int(storage->insert_packet, 7, event->packet->dst_port);
        sqlite3_bind_int(storage->insert_packet, 8, (int)event->packet->length);
        sqlite3_bind_int(storage->insert_packet, 9, event->packet->ip_version);
        sqlite3_bind_int(storage->insert_packet, 10, event->packet->ether_type);
        sqlite3_bind_int(storage->insert_packet, 11, event->packet->truncated ? 1 : 0);
        sqlite3_bind_int(storage->insert_packet, 12, event->packet->fragmented ? 1 : 0);
        started_ns = storage_monotonic_ns();
        result = step_with_retry(storage, storage->insert_packet);
        finished_ns = storage_monotonic_ns();
        record_storage_result(storage,
                              result,
                              finished_ns >= started_ns ? finished_ns - started_ns : 0);
    } else if (event->type == IDS_EVENT_ALERT && event->alert != NULL && storage->insert_alert != NULL) {
        char timestamp[32];
        uint64_t started_ns;
        uint64_t finished_ns;
        int result;

        format_timestamp(&event->alert->timestamp, timestamp, sizeof(timestamp));
        sqlite3_reset(storage->insert_alert);
        sqlite3_clear_bindings(storage->insert_alert);
        sqlite3_bind_int64(storage->insert_alert, 1, storage->session_id);
        sqlite3_bind_text(storage->insert_alert, 2, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_alert, 3, ids_severity_name(event->alert->severity), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_alert, 4, detection_alert_type_name(event->alert->type), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_alert, 5, event->alert->source_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_alert, 6, event->alert->destination_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_alert, 7, event->alert->reason, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(storage->insert_alert, 8, event->alert->risk_score);
        sqlite3_bind_text(storage->insert_alert, 9, event->alert->correlation_id, -1, SQLITE_TRANSIENT);
        started_ns = storage_monotonic_ns();
        result = step_with_retry(storage, storage->insert_alert);
        finished_ns = storage_monotonic_ns();
        record_storage_result(storage,
                              result,
                              finished_ns >= started_ns ? finished_ns - started_ns : 0);
    } else if (event->type == IDS_EVENT_DETECTION_COMPLETE &&
               event->packet != NULL &&
               storage->insert_detection != NULL) {
        char timestamp[32];
        uint64_t started_ns;
        uint64_t finished_ns;
        int result;

        format_timestamp(&event->packet->timestamp, timestamp, sizeof(timestamp));
        sqlite3_reset(storage->insert_detection);
        sqlite3_clear_bindings(storage->insert_detection);
        sqlite3_bind_int64(storage->insert_detection, 1, storage->session_id);
        sqlite3_bind_text(storage->insert_detection, 2, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_detection, 3, event->packet->src_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_detection, 4, event->packet->dst_ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(storage->insert_detection, 5, parser_protocol_name(event->packet->protocol), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(storage->insert_detection, 6, (sqlite3_int64)event->alert_count);
        started_ns = storage_monotonic_ns();
        result = step_with_retry(storage, storage->insert_detection);
        finished_ns = storage_monotonic_ns();
        record_storage_result(storage,
                              result,
                              finished_ns >= started_ns ? finished_ns - started_ns : 0);
    }
    pthread_mutex_unlock(&storage->lock);
#endif
}

void storage_sqlite_record_metrics(storage_sqlite_t *storage, ids_stats_t *stats)
{
    ids_stats_snapshot_t snapshot;
    struct timeval now;
    char timestamp[32];

    if (storage == NULL || stats == NULL || !storage->enabled) {
        return;
    }

#ifdef SPECTERIDS_ENABLE_SQLITE
    pthread_mutex_lock(&storage->lock);
    ids_stats_snapshot(stats, &snapshot);
    gettimeofday(&now, NULL);
    format_timestamp(&now, timestamp, sizeof(timestamp));
    {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "INSERT INTO metrics(session_id,timestamp,packets_total,alerts_total,pps,mbps,queue_drops,"
            "storage_writes,storage_errors,plugin_alerts,ipv6_ratio,events_published,events_dropped) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)";

        if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQLite metrics prepare failed: %s\n", sqlite3_errmsg(storage->db));
            pthread_mutex_unlock(&storage->lock);
            return;
        }
        sqlite3_bind_int64(stmt, 1, storage->session_id);
        sqlite3_bind_text(stmt, 2, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)snapshot.parsed_packets);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)snapshot.alert_count);
        sqlite3_bind_double(stmt, 5, snapshot.packets_per_second);
        sqlite3_bind_double(stmt, 6, snapshot.mbps);
        sqlite3_bind_int64(stmt, 7, (sqlite3_int64)snapshot.queue_drops);
        sqlite3_bind_int64(stmt, 8, (sqlite3_int64)snapshot.storage_writes);
        sqlite3_bind_int64(stmt, 9, (sqlite3_int64)snapshot.storage_errors);
        sqlite3_bind_int64(stmt, 10, (sqlite3_int64)snapshot.plugin_alerts);
        sqlite3_bind_double(stmt, 11, snapshot.ipv6_ratio);
        sqlite3_bind_int64(stmt, 12, (sqlite3_int64)snapshot.event_published);
        sqlite3_bind_int64(stmt, 13, (sqlite3_int64)snapshot.event_dropped);
        {
            uint64_t started_ns = storage_monotonic_ns();
            int result = step_with_retry(storage, stmt);
            uint64_t finished_ns = storage_monotonic_ns();

            record_storage_result(storage,
                                  result,
                                  finished_ns >= started_ns ? finished_ns - started_ns : 0);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&storage->lock);
#else
    (void)snapshot;
    (void)now;
    (void)timestamp;
#endif
}

void storage_sqlite_finish_session(storage_sqlite_t *storage, ids_stats_t *stats)
{
    ids_stats_snapshot_t snapshot;
    struct timeval now;
    char timestamp[32];

    if (storage == NULL || stats == NULL || !storage->enabled) {
        return;
    }

#ifdef SPECTERIDS_ENABLE_SQLITE
    pthread_mutex_lock(&storage->lock);
    ids_stats_snapshot(stats, &snapshot);
    gettimeofday(&now, NULL);
    format_timestamp(&now, timestamp, sizeof(timestamp));
    {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "UPDATE sessions SET ended_at=?, packets_total=?, alerts_total=? WHERE id=?";

        if (sqlite3_prepare_v2(storage->db, sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQLite session finish prepare failed: %s\n", sqlite3_errmsg(storage->db));
            pthread_mutex_unlock(&storage->lock);
            return;
        }
        sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)snapshot.parsed_packets);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)snapshot.alert_count);
        sqlite3_bind_int64(stmt, 4, storage->session_id);
        {
            uint64_t started_ns = storage_monotonic_ns();
            int result = step_with_retry(storage, stmt);
            uint64_t finished_ns = storage_monotonic_ns();

            record_storage_result(storage,
                                  result,
                                  finished_ns >= started_ns ? finished_ns - started_ns : 0);
        }
        sqlite3_finalize(stmt);
    }
    pthread_mutex_unlock(&storage->lock);
#else
    (void)snapshot;
    (void)now;
    (void)timestamp;
#endif
}

void storage_sqlite_destroy(storage_sqlite_t *storage)
{
    if (storage == NULL) {
        return;
    }

#ifdef SPECTERIDS_ENABLE_SQLITE
    close_sqlite_handles(storage);
#endif
    pthread_mutex_destroy(&storage->lock);
    free(storage);
}
