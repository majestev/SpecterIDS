#ifndef SPECTERIDS_POOL_H
#define SPECTERIDS_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "queue.h"

typedef struct {
    void *storage;
    size_t element_size;
    size_t capacity;
    ids_queue_t free_items;
} ids_pool_t;

int ids_pool_init(ids_pool_t *pool, size_t capacity, size_t element_size);
void ids_pool_destroy(ids_pool_t *pool);
void *ids_pool_acquire(ids_pool_t *pool);
void *ids_pool_try_acquire(ids_pool_t *pool);
void ids_pool_release(ids_pool_t *pool, void *item);
size_t ids_pool_available(ids_pool_t *pool);

#endif
