#ifndef SPECTERIDS_EVENT_H
#define SPECTERIDS_EVENT_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "detection.h"
#include "parser.h"

#define IDS_EVENT_MAX_SUBSCRIBERS 16
#define IDS_EVENT_MESSAGE_LEN 160
#define IDS_EVENT_UUID_LEN 37
#define IDS_EVENT_SOURCE_LEN 64

typedef enum {
    IDS_EVENT_PACKET_CAPTURED = 0,
    IDS_EVENT_DATALINK_PARSED,
    IDS_EVENT_NETWORK_PACKET_PARSED,
    IDS_EVENT_PACKET_PARSED,
    IDS_EVENT_DETECTION_COMPLETE,
    IDS_EVENT_CORRELATION,
    IDS_EVENT_ALERT,
    IDS_EVENT_OUTPUT_WRITTEN,
    IDS_EVENT_STORAGE,
    IDS_EVENT_METRICS,
    IDS_EVENT_RELOAD,
    IDS_EVENT_HEALTH,
    IDS_EVENT_TYPE_COUNT
} ids_event_type_t;

typedef enum {
    IDS_EVENT_PRIORITY_UNSET = 0,
    IDS_EVENT_PRIORITY_LOW,
    IDS_EVENT_PRIORITY_NORMAL,
    IDS_EVENT_PRIORITY_HIGH,
    IDS_EVENT_PRIORITY_CRITICAL
} ids_event_priority_t;

typedef struct {
    uint64_t event_id;
    char uuid[IDS_EVENT_UUID_LEN];
    ids_event_type_t type;
    ids_event_priority_t priority;
    const packet_info_t *packet;
    const alert_t *alert;
    packet_info_t packet_copy;
    alert_t alert_copy;
    size_t alert_count;
    const char *message;
    char message_copy[IDS_EVENT_MESSAGE_LEN];
    bool has_packet;
    bool has_alert;
    struct timeval timestamp;
    struct timeval queued_at;
    struct timeval dispatched_at;
    uint64_t monotonic_timestamp_ns;
    uint64_t queued_monotonic_ns;
    uint64_t dispatched_monotonic_ns;
    uint64_t stage_timestamps_ns[IDS_EVENT_TYPE_COUNT];
    uint64_t enqueue_latency_ns;
    uint64_t dispatch_latency_ns;
    uint64_t dropped_before_publish;
    uint32_t retry_count;
    bool backpressure;
    char source_metadata[IDS_EVENT_SOURCE_LEN];
} ids_event_t;

typedef void (*ids_event_handler_t)(const ids_event_t *event, void *user_data);

typedef struct {
    ids_event_handler_t handler;
    void *user_data;
} ids_event_subscriber_t;

typedef struct {
    ids_event_t *events;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    bool closed;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} ids_event_queue_t;

typedef struct {
    uint64_t published_events;
    uint64_t dispatched_events;
    uint64_t dropped_events;
    size_t queue_depth;
    size_t queue_capacity;
} ids_event_bus_snapshot_t;

typedef struct {
    ids_event_subscriber_t subscribers[IDS_EVENT_TYPE_COUNT][IDS_EVENT_MAX_SUBSCRIBERS];
    size_t subscriber_count[IDS_EVENT_TYPE_COUNT];
    /*
     * Bitmask: bit N is set when at least one subscriber is registered for event type N.
     * Read lock-free with memory_order_relaxed from publish hot-path.
     * Written once per subscriber registration (rare, not on hot path).
     * IDS_EVENT_TYPE_COUNT <= 32, so uint32_t covers all types.
     */
    _Atomic uint32_t subscriber_bitmask;
    pthread_mutex_t lock;
    ids_event_queue_t queue;
    pthread_t worker;
    bool async_enabled;
    bool async_running;
    uint64_t next_event_id;
    uint64_t published_events;
    uint64_t dispatched_events;
    uint64_t dropped_events;
} ids_event_bus_t;

int ids_event_bus_init(ids_event_bus_t *bus);
void ids_event_bus_destroy(ids_event_bus_t *bus);
int ids_event_bus_start_async(ids_event_bus_t *bus, size_t queue_capacity);
void ids_event_bus_stop_async(ids_event_bus_t *bus);
int ids_event_bus_subscribe(ids_event_bus_t *bus,
                            ids_event_type_t type,
                            ids_event_handler_t handler,
                            void *user_data);
void ids_event_bus_publish(ids_event_bus_t *bus, const ids_event_t *event);
uint64_t ids_event_bus_dropped(ids_event_bus_t *bus);
void ids_event_bus_snapshot(ids_event_bus_t *bus, ids_event_bus_snapshot_t *snapshot);
const char *ids_event_type_name(ids_event_type_t type);

int ids_event_queue_init(ids_event_queue_t *queue, size_t capacity);
void ids_event_queue_destroy(ids_event_queue_t *queue);
void ids_event_queue_close(ids_event_queue_t *queue);
bool ids_event_queue_push(ids_event_queue_t *queue, const ids_event_t *event);
bool ids_event_queue_pop(ids_event_queue_t *queue, ids_event_t *event);

#endif
