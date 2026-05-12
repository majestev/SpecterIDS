#ifndef SPECTERIDS_QUEUE_H
#define SPECTERIDS_QUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

typedef struct {
    void **items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    bool closed;
    uint64_t pushed;
    uint64_t popped;
    uint64_t dropped;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} ids_queue_t;

int ids_queue_init(ids_queue_t *queue, size_t capacity);
void ids_queue_destroy(ids_queue_t *queue);
void ids_queue_close(ids_queue_t *queue);
bool ids_queue_push(ids_queue_t *queue, void *item);
bool ids_queue_try_push(ids_queue_t *queue, void *item);
bool ids_queue_pop(ids_queue_t *queue, void **item);
bool ids_queue_try_pop(ids_queue_t *queue, void **item);
size_t ids_queue_size(ids_queue_t *queue);
uint64_t ids_queue_dropped(ids_queue_t *queue);

#endif
