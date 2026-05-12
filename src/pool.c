#include "pool.h"

#include <stdlib.h>
#include <string.h>

int ids_pool_init(ids_pool_t *pool, size_t capacity, size_t element_size)
{
    size_t i;

    if (pool == NULL || capacity == 0 || element_size == 0) {
        return -1;
    }

    memset(pool, 0, sizeof(*pool));
    pool->storage = calloc(capacity, element_size);
    if (pool->storage == NULL) {
        return -1;
    }

    if (ids_queue_init(&pool->free_items, capacity) != 0) {
        free(pool->storage);
        memset(pool, 0, sizeof(*pool));
        return -1;
    }

    pool->capacity = capacity;
    pool->element_size = element_size;

    for (i = 0; i < capacity; i++) {
        void *item = (unsigned char *)pool->storage + (i * element_size);
        (void)ids_queue_try_push(&pool->free_items, item);
    }

    return 0;
}

void ids_pool_destroy(ids_pool_t *pool)
{
    if (pool == NULL) {
        return;
    }

    ids_queue_destroy(&pool->free_items);
    free(pool->storage);
    memset(pool, 0, sizeof(*pool));
}

void *ids_pool_acquire(ids_pool_t *pool)
{
    void *item = NULL;

    if (pool == NULL) {
        return NULL;
    }

    if (!ids_queue_try_pop(&pool->free_items, &item)) {
        return NULL;
    }

    memset(item, 0, pool->element_size);
    return item;
}

void *ids_pool_try_acquire(ids_pool_t *pool)
{
    void *item = NULL;

    if (pool == NULL) {
        return NULL;
    }

    if (!ids_queue_pop(&pool->free_items, &item)) {
        return NULL;
    }

    memset(item, 0, pool->element_size);
    return item;
}

void ids_pool_release(ids_pool_t *pool, void *item)
{
    if (pool == NULL || item == NULL) {
        return;
    }

    (void)ids_queue_push(&pool->free_items, item);
}

size_t ids_pool_available(ids_pool_t *pool)
{
    if (pool == NULL) {
        return 0;
    }

    return ids_queue_size(&pool->free_items);
}
