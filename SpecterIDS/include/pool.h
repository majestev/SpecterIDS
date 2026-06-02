#ifndef SPECTERIDS_POOL_H
#define SPECTERIDS_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "queue.h"

typedef struct {
    void *storage;
    uint8_t *in_use;
    size_t element_size;
    size_t capacity;
    size_t in_use_count;
    uint64_t failed_acquires;
    uint64_t invalid_releases;
    ids_queue_t free_items;
    pthread_mutex_t lock;
} ids_pool_t;

int ids_pool_init(ids_pool_t *pool, size_t capacity, size_t element_size);
void ids_pool_destroy(ids_pool_t *pool);
void *ids_pool_acquire(ids_pool_t *pool);
void *ids_pool_try_acquire(ids_pool_t *pool);
void *ids_pool_acquire_timeout(ids_pool_t *pool, unsigned int timeout_ms);
void ids_pool_release(ids_pool_t *pool, void *item);
size_t ids_pool_available(ids_pool_t *pool);
size_t ids_pool_capacity(ids_pool_t *pool);
size_t ids_pool_in_use(ids_pool_t *pool);
uint64_t ids_pool_failed_acquires(ids_pool_t *pool);
uint64_t ids_pool_invalid_releases(ids_pool_t *pool);

#endif
