#include "event.h"

#include <string.h>
#include <stdlib.h>

int ids_event_bus_init(ids_event_bus_t *bus)
{
    if (bus == NULL) {
        return -1;
    }

    memset(bus, 0, sizeof(*bus));
    return pthread_mutex_init(&bus->lock, NULL);
}

void ids_event_bus_destroy(ids_event_bus_t *bus)
{
    if (bus == NULL) {
        return;
    }

    pthread_mutex_destroy(&bus->lock);
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
    return 0;
}

void ids_event_bus_publish(ids_event_bus_t *bus, const ids_event_t *event)
{
    ids_event_subscriber_t subscribers[IDS_EVENT_MAX_SUBSCRIBERS];
    size_t count;
    size_t i;

    if (bus == NULL || event == NULL || event->type < 0 || event->type >= IDS_EVENT_TYPE_COUNT) {
        return;
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
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->lock);
        free(queue->events);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
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
    if (queue == NULL || event == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    while (!queue->closed && queue->count == queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    if (queue->closed) {
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

bool ids_event_queue_pop(ids_event_queue_t *queue, ids_event_t *event)
{
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
    *event = queue->events[queue->head];
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return true;
}
