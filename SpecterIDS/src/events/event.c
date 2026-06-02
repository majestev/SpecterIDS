#include "event.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

/* ids_monotonic_ns() is provided by common.h via event.h → detection.h → parser.h → common.h */
static uint64_t event_monotonic_ns(void)
{
    return ids_monotonic_ns();
}

static void event_format_uuid(uint64_t event_id, uint64_t monotonic_ns, char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0) {
        return;
    }

    snprintf(buffer,
             buffer_size,
             "%08llx-%04llx-4%03llx-8%03llx-%012llx",
             (unsigned long long)(event_id & 0xffffffffULL),
             (unsigned long long)((monotonic_ns >> 48U) & 0xffffULL),
             (unsigned long long)((monotonic_ns >> 36U) & 0x0fffULL),
             (unsigned long long)((monotonic_ns >> 24U) & 0x0fffULL),
             (unsigned long long)(monotonic_ns & 0xffffffffffffULL));
}

static ids_event_priority_t default_priority_for_type(ids_event_type_t type)
{
    switch (type) {
    case IDS_EVENT_ALERT:
        return IDS_EVENT_PRIORITY_HIGH;
    case IDS_EVENT_HEALTH:
    case IDS_EVENT_RELOAD:
        return IDS_EVENT_PRIORITY_CRITICAL;
    case IDS_EVENT_OUTPUT_WRITTEN:
    case IDS_EVENT_STORAGE:
    case IDS_EVENT_METRICS:
        return IDS_EVENT_PRIORITY_LOW;
    case IDS_EVENT_PACKET_CAPTURED:
    case IDS_EVENT_DATALINK_PARSED:
    case IDS_EVENT_NETWORK_PACKET_PARSED:
    case IDS_EVENT_PACKET_PARSED:
    case IDS_EVENT_DETECTION_COMPLETE:
    case IDS_EVENT_CORRELATION:
    case IDS_EVENT_TYPE_COUNT:
    default:
        return IDS_EVENT_PRIORITY_NORMAL;
    }
}

static void event_rebind(ids_event_t *event)
{
    if (event == NULL) {
        return;
    }

    if (event->has_packet) {
        event->packet = &event->packet_copy;
    }
    if (event->has_alert) {
        event->alert = &event->alert_copy;
    }
    if (event->message_copy[0] != '\0') {
        event->message = event->message_copy;
    }
}

static void event_make_owned(ids_event_t *dst, const ids_event_t *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }

    *dst = *src;
    if (src->packet != NULL) {
        dst->packet_copy = *src->packet;
        dst->has_packet = true;
    }
    if (src->alert != NULL) {
        dst->alert_copy = *src->alert;
        dst->has_alert = true;
    }
    if (src->message != NULL && src->message[0] != '\0') {
        snprintf(dst->message_copy, sizeof(dst->message_copy), "%s", src->message);
    }
    event_rebind(dst);
}

static void event_prepare_owned(ids_event_bus_t *bus, ids_event_t *dst, const ids_event_t *src)
{
    struct timeval now;
    uint64_t now_ns;

    event_make_owned(dst, src);
    gettimeofday(&now, NULL);
    now_ns = event_monotonic_ns();
    if (dst->priority <= IDS_EVENT_PRIORITY_UNSET || dst->priority > IDS_EVENT_PRIORITY_CRITICAL) {
        dst->priority = default_priority_for_type(dst->type);
    }
    if (dst->timestamp.tv_sec == 0 && dst->timestamp.tv_usec == 0) {
        dst->timestamp = now;
    }
    dst->queued_at = now;
    dst->queued_monotonic_ns = now_ns;
    if (dst->monotonic_timestamp_ns == 0) {
        dst->monotonic_timestamp_ns = now_ns;
    }
    if (dst->type >= 0 && dst->type < IDS_EVENT_TYPE_COUNT) {
        dst->stage_timestamps_ns[dst->type] = now_ns;
    }
    if (dst->source_metadata[0] == '\0') {
        if (dst->packet != NULL && dst->packet->src_ip[0] != '\0') {
            snprintf(dst->source_metadata, sizeof(dst->source_metadata), "%s", dst->packet->src_ip);
        } else if (dst->alert != NULL && dst->alert->source_ip[0] != '\0') {
            snprintf(dst->source_metadata, sizeof(dst->source_metadata), "%s", dst->alert->source_ip);
        }
    }

    pthread_mutex_lock(&bus->lock);
    bus->next_event_id++;
    dst->event_id = bus->next_event_id;
    dst->dropped_before_publish = bus->dropped_events;
    bus->published_events++;
    pthread_mutex_unlock(&bus->lock);
    event_format_uuid(dst->event_id, dst->monotonic_timestamp_ns, dst->uuid, sizeof(dst->uuid));
}

static void event_bus_dispatch(ids_event_bus_t *bus, ids_event_t *event)
{
    ids_event_subscriber_t subscribers[IDS_EVENT_MAX_SUBSCRIBERS];
    size_t count;
    size_t i;

    if (bus == NULL || event == NULL || event->type < 0 || event->type >= IDS_EVENT_TYPE_COUNT) {
        return;
    }

    gettimeofday(&event->dispatched_at, NULL);
    event->dispatched_monotonic_ns = event_monotonic_ns();
    if (event->dispatched_monotonic_ns >= event->queued_monotonic_ns) {
        event->dispatch_latency_ns = event->dispatched_monotonic_ns - event->queued_monotonic_ns;
    }
    pthread_mutex_lock(&bus->lock);
    count = bus->subscriber_count[event->type];
    if (count > IDS_EVENT_MAX_SUBSCRIBERS) {
        count = IDS_EVENT_MAX_SUBSCRIBERS;
    }
    memcpy(subscribers, bus->subscribers[event->type], count * sizeof(subscribers[0]));
    pthread_mutex_unlock(&bus->lock);

    for (i = 0; i < count; i++) {
        subscribers[i].handler(event, subscribers[i].user_data);
    }

    pthread_mutex_lock(&bus->lock);
    bus->dispatched_events++;
    pthread_mutex_unlock(&bus->lock);
}

static void *event_worker_main(void *arg)
{
    ids_event_bus_t *bus = (ids_event_bus_t *)arg;
    ids_event_t event;

    while (ids_event_queue_pop(&bus->queue, &event)) {
        event_bus_dispatch(bus, &event);
    }

    return NULL;
}

static bool event_queue_try_push_owned(ids_event_queue_t *queue, const ids_event_t *event)
{
    if (queue == NULL || event == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    if (queue->closed || queue->count == queue->capacity) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    queue->events[queue->tail] = *event;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

int ids_event_bus_init(ids_event_bus_t *bus)
{
    if (bus == NULL) {
        return -1;
    }

    memset(bus, 0, sizeof(*bus));
    atomic_init(&bus->subscriber_bitmask, 0U);
    return pthread_mutex_init(&bus->lock, NULL);
}

void ids_event_bus_destroy(ids_event_bus_t *bus)
{
    if (bus == NULL) {
        return;
    }

    ids_event_bus_stop_async(bus);
    pthread_mutex_destroy(&bus->lock);
}

int ids_event_bus_start_async(ids_event_bus_t *bus, size_t queue_capacity)
{
    bool already_enabled;

    if (bus == NULL || queue_capacity == 0) {
        return -1;
    }

    pthread_mutex_lock(&bus->lock);
    already_enabled = bus->async_enabled;
    pthread_mutex_unlock(&bus->lock);
    if (already_enabled) {
        return -1;
    }

    if (ids_event_queue_init(&bus->queue, queue_capacity) != 0) {
        return -1;
    }

    pthread_mutex_lock(&bus->lock);
    bus->async_enabled = true;
    pthread_mutex_unlock(&bus->lock);
    if (pthread_create(&bus->worker, NULL, event_worker_main, bus) != 0) {
        pthread_mutex_lock(&bus->lock);
        bus->async_enabled = false;
        pthread_mutex_unlock(&bus->lock);
        ids_event_queue_destroy(&bus->queue);
        return -1;
    }

    pthread_mutex_lock(&bus->lock);
    bus->async_running = true;
    pthread_mutex_unlock(&bus->lock);
    return 0;
}

void ids_event_bus_stop_async(ids_event_bus_t *bus)
{
    bool async_enabled;
    bool async_running;

    if (bus == NULL) {
        return;
    }

    pthread_mutex_lock(&bus->lock);
    async_enabled = bus->async_enabled;
    async_running = bus->async_running;
    pthread_mutex_unlock(&bus->lock);
    if (!async_enabled) {
        return;
    }

    ids_event_queue_close(&bus->queue);
    if (async_running) {
        pthread_join(bus->worker, NULL);
        pthread_mutex_lock(&bus->lock);
        bus->async_running = false;
        pthread_mutex_unlock(&bus->lock);
    }
    ids_event_queue_destroy(&bus->queue);
    pthread_mutex_lock(&bus->lock);
    bus->async_enabled = false;
    pthread_mutex_unlock(&bus->lock);
}

int ids_event_bus_subscribe(ids_event_bus_t *bus,
                            ids_event_type_t type,
                            ids_event_handler_t handler,
                            void *user_data)
{
    size_t index;

    if (bus == NULL || handler == NULL || type < 0 || type >= IDS_EVENT_TYPE_COUNT) {
        return -1;
    }

    pthread_mutex_lock(&bus->lock);
    if (bus->subscriber_count[type] >= IDS_EVENT_MAX_SUBSCRIBERS) {
        pthread_mutex_unlock(&bus->lock);
        return -1;
    }

    index = bus->subscriber_count[type]++;
    bus->subscribers[type][index].handler = handler;
    bus->subscribers[type][index].user_data = user_data;
    pthread_mutex_unlock(&bus->lock);

    atomic_fetch_or(&bus->subscriber_bitmask, 1U << (unsigned)type);
    return 0;
}

void ids_event_bus_publish(ids_event_bus_t *bus, const ids_event_t *event)
{
    ids_event_t owned;
    bool async_enabled;

    if (bus == NULL || event == NULL || event->type < 0 || event->type >= IDS_EVENT_TYPE_COUNT) {
        return;
    }

    /*
     * Fast-path: if no subscriber is registered for this event type, skip all
     * processing. The bitmask is written once per subscription (rare) and
     * read here with relaxed ordering — a just-registered subscriber may miss
     * one event, which is acceptable since this path only fires before the
     * pipeline processes any packets in practice.
     */
    if ((atomic_load_explicit(&bus->subscriber_bitmask, memory_order_relaxed) &
         (1U << (unsigned)event->type)) == 0U) {
        return;
    }

    event_prepare_owned(bus, &owned, event);
    pthread_mutex_lock(&bus->lock);
    async_enabled = bus->async_enabled;
    pthread_mutex_unlock(&bus->lock);

    if (async_enabled) {
        pthread_mutex_lock(&bus->queue.lock);
        if (bus->queue.capacity > 0 && bus->queue.count * 100U >= bus->queue.capacity * 75U) {
            owned.backpressure = true;
        }
        pthread_mutex_unlock(&bus->queue.lock);
        if (owned.queued_monotonic_ns != 0) {
            uint64_t enqueue_ns = event_monotonic_ns();

            if (enqueue_ns >= owned.queued_monotonic_ns) {
                owned.enqueue_latency_ns = enqueue_ns - owned.queued_monotonic_ns;
            }
        }
        if (!event_queue_try_push_owned(&bus->queue, &owned)) {
            pthread_mutex_lock(&bus->lock);
            bus->dropped_events++;
            pthread_mutex_unlock(&bus->lock);
        }
        return;
    }

    event_bus_dispatch(bus, &owned);
}

uint64_t ids_event_bus_dropped(ids_event_bus_t *bus)
{
    uint64_t dropped;

    if (bus == NULL) {
        return 0;
    }

    pthread_mutex_lock(&bus->lock);
    dropped = bus->dropped_events;
    pthread_mutex_unlock(&bus->lock);
    return dropped;
}

void ids_event_bus_snapshot(ids_event_bus_t *bus, ids_event_bus_snapshot_t *snapshot)
{
    if (snapshot == NULL) {
        return;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    if (bus == NULL) {
        return;
    }

    pthread_mutex_lock(&bus->lock);
    snapshot->published_events = bus->published_events;
    snapshot->dispatched_events = bus->dispatched_events;
    snapshot->dropped_events = bus->dropped_events;
    if (bus->async_enabled) {
        pthread_mutex_lock(&bus->queue.lock);
        snapshot->queue_depth = bus->queue.count;
        snapshot->queue_capacity = bus->queue.capacity;
        pthread_mutex_unlock(&bus->queue.lock);
    }
    pthread_mutex_unlock(&bus->lock);
}

const char *ids_event_type_name(ids_event_type_t type)
{
    switch (type) {
    case IDS_EVENT_PACKET_CAPTURED:
        return "PacketCapturedEvent";
    case IDS_EVENT_DATALINK_PARSED:
        return "DatalinkParsedEvent";
    case IDS_EVENT_NETWORK_PACKET_PARSED:
        return "NetworkPacketParsedEvent";
    case IDS_EVENT_PACKET_PARSED:
        return "PacketParsedEvent";
    case IDS_EVENT_DETECTION_COMPLETE:
        return "DetectionEvent";
    case IDS_EVENT_CORRELATION:
        return "CorrelationEvent";
    case IDS_EVENT_ALERT:
        return "AlertEvent";
    case IDS_EVENT_OUTPUT_WRITTEN:
        return "OutputEvent";
    case IDS_EVENT_STORAGE:
        return "StorageEvent";
    case IDS_EVENT_METRICS:
        return "MetricsEvent";
    case IDS_EVENT_RELOAD:
        return "ReloadEvent";
    case IDS_EVENT_HEALTH:
        return "HealthEvent";
    case IDS_EVENT_TYPE_COUNT:
    default:
        return "UnknownEvent";
    }
}

static int event_init_monotonic_cond(pthread_cond_t *cond)
{
    pthread_condattr_t attr;
    int rc;

    if (pthread_condattr_init(&attr) != 0) {
        return -1;
    }
    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc == 0) {
        rc = pthread_cond_init(cond, &attr);
    }
    pthread_condattr_destroy(&attr);
    return rc;
}

int ids_event_queue_init(ids_event_queue_t *queue, size_t capacity)
{
    if (queue == NULL || capacity == 0) {
        return -1;
    }

    memset(queue, 0, sizeof(*queue));
    queue->events = calloc(capacity, sizeof(queue->events[0]));
    if (queue->events == NULL) {
        return -1;
    }
    queue->capacity = capacity;

    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        free(queue->events);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    if (event_init_monotonic_cond(&queue->not_empty) != 0) {
        pthread_mutex_destroy(&queue->lock);
        free(queue->events);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    if (event_init_monotonic_cond(&queue->not_full) != 0) {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->lock);
        free(queue->events);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    return 0;
}

void ids_event_queue_destroy(ids_event_queue_t *queue)
{
    if (queue == NULL) {
        return;
    }

    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->lock);
    free(queue->events);
    memset(queue, 0, sizeof(*queue));
}

void ids_event_queue_close(ids_event_queue_t *queue)
{
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->lock);
    queue->closed = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
}

bool ids_event_queue_push(ids_event_queue_t *queue, const ids_event_t *event)
{
    ids_event_t owned;

    if (queue == NULL || event == NULL) {
        return false;
    }

    event_make_owned(&owned, event);
    pthread_mutex_lock(&queue->lock);
    while (!queue->closed && queue->count == queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    if (queue->closed) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    queue->events[queue->tail] = owned;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool ids_event_queue_pop(ids_event_queue_t *queue, ids_event_t *event)
{
    size_t best_index;
    ids_event_priority_t best_priority;
    size_t offset;

    if (queue == NULL || event == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    while (!queue->closed && queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }
    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }
    best_index = queue->head;
    best_priority = queue->events[queue->head].priority;
    for (offset = 1; offset < queue->count; offset++) {
        size_t index = (queue->head + offset) % queue->capacity;
        if (queue->events[index].priority > best_priority) {
            best_index = index;
            best_priority = queue->events[index].priority;
        }
    }

    /*
     * Swap the highest-priority event to the head, then pop the head.
     * O(1) swap instead of O(n) bubble-shift; ids_event_t is 1232 bytes
     * so the old bubble-shift moved up to n*1232 bytes inside this lock.
     * Strict FIFO within a priority level is intentionally relaxed.
     */
    if (best_index != queue->head) {
        ids_event_t tmp = queue->events[queue->head];
        queue->events[queue->head] = queue->events[best_index];
        queue->events[best_index] = tmp;
    }

    *event = queue->events[queue->head];
    event_rebind(event);
    memset(&queue->events[queue->head], 0, sizeof(queue->events[queue->head]));
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return true;
}
