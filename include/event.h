#ifndef SPECTERIDS_EVENT_H
#define SPECTERIDS_EVENT_H

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "detection.h"
#include "parser.h"

#define IDS_EVENT_MAX_SUBSCRIBERS 16

typedef enum {
    IDS_EVENT_PACKET_CAPTURED = 0,
    IDS_EVENT_PACKET_PARSED,
    IDS_EVENT_DETECTION_COMPLETE,
    IDS_EVENT_ALERT,
    IDS_EVENT_OUTPUT_WRITTEN,
    IDS_EVENT_METRICS,
    IDS_EVENT_RELOAD,
    IDS_EVENT_HEALTH,
    IDS_EVENT_TYPE_COUNT
} ids_event_type_t;

typedef struct {
    ids_event_type_t type;
    const packet_info_t *packet;
    const alert_t *alert;
    size_t alert_count;
    const char *message;
    struct timeval timestamp;
} ids_event_t;

typedef void (*ids_event_handler_t)(const ids_event_t *event, void *user_data);

typedef struct {
    ids_event_handler_t handler;
    void *user_data;
} ids_event_subscriber_t;

typedef struct {
    ids_event_subscriber_t subscribers[IDS_EVENT_TYPE_COUNT][IDS_EVENT_MAX_SUBSCRIBERS];
    size_t subscriber_count[IDS_EVENT_TYPE_COUNT];
    pthread_mutex_t lock;
} ids_event_bus_t;

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

int ids_event_bus_init(ids_event_bus_t *bus);
void ids_event_bus_destroy(ids_event_bus_t *bus);
int ids_event_bus_subscribe(ids_event_bus_t *bus,
                            ids_event_type_t type,
                            ids_event_handler_t handler,
                            void *user_data);
void ids_event_bus_publish(ids_event_bus_t *bus, const ids_event_t *event);

int ids_event_queue_init(ids_event_queue_t *queue, size_t capacity);
void ids_event_queue_destroy(ids_event_queue_t *queue);
void ids_event_queue_close(ids_event_queue_t *queue);
bool ids_event_queue_push(ids_event_queue_t *queue, const ids_event_t *event);
bool ids_event_queue_pop(ids_event_queue_t *queue, ids_event_t *event);

#endif
