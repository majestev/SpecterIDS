#include "pool.h"

#include <stdlib.h>
#include <string.h>

static bool pool_index_for(const ids_pool_t *pool, const void *item, size_t *index)
{
    const unsigned char *base;
    const unsigned char *cursor;
    size_t offset;
    size_t total_size;

    if (pool == NULL || pool->storage == NULL || item == NULL ||
        pool->element_size == 0 || pool->capacity == 0) {
        return false;
    }
    if (pool->capacity > ((size_t)-1) / pool->element_size) {
        return false;
    }

    base = (const unsigned char *)pool->storage;
    cursor = (const unsigned char *)item;
    total_size = pool->capacity * pool->element_size;
    if (cursor < base || cursor >= base + total_size) {
        return false;
    }

    offset = (size_t)(cursor - base);
    if ((offset % pool->element_size) != 0) {
        return false;
    }
    if (index != NULL) {
        *index = offset / pool->element_size;
    }
    return true;
}

static void *pool_take_owned(ids_pool_t *pool, bool popped, void *item)
{
    size_t index;

    if (!popped || item == NULL) {
        pthread_mutex_lock(&pool->lock);
        pool->failed_acquires++;
        pthread_mutex_unlock(&pool->lock);
        return NULL;
    }

    pthread_mutex_lock(&pool->lock);
    if (!pool_index_for(pool, item, &index) || pool->in_use[index] != 0U) {
        pool->failed_acquires++;
        pthread_mutex_unlock(&pool->lock);
        return NULL;
    }
    pool->in_use[index] = 1U;
    pool->in_use_count++;
    pthread_mutex_unlock(&pool->lock);

    memset(item, 0, pool->element_size);
    return item;
}

int ids_pool_init(ids_pool_t *pool, size_t capacity, size_t element_size)
{
    size_t i;

    if (pool == NULL || capacity == 0 || element_size == 0 ||
        capacity > ((size_t)-1) / element_size) {
        return -1;
    }

    memset(pool, 0, sizeof(*pool));
    pool->storage = calloc(capacity, element_size);
    if (pool->storage == NULL) {
        return -1;
    }
    pool->in_use = calloc(capacity, sizeof(pool->in_use[0]));
    if (pool->in_use == NULL) {
        free(pool->storage);
        memset(pool, 0, sizeof(*pool));
        return -1;
    }
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool->in_use);
        free(pool->storage);
        memset(pool, 0, sizeof(*pool));
        return -1;
    }

    if (ids_queue_init(&pool->free_items, capacity) != 0) {
        pthread_mutex_destroy(&pool->lock);
        free(pool->in_use);
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
    pthread_mutex_destroy(&pool->lock);
    free(pool->in_use);
    free(pool->storage);
    memset(pool, 0, sizeof(*pool));
}

void *ids_pool_acquire(ids_pool_t *pool)
{
    void *item = NULL;
    bool popped;

    if (pool == NULL) {
        return NULL;
    }

    popped = ids_queue_pop(&pool->free_items, &item);
    return pool_take_owned(pool, popped, item);
}

void *ids_pool_try_acquire(ids_pool_t *pool)
{
    void *item = NULL;
    bool popped;

    if (pool == NULL) {
        return NULL;
    }

    popped = ids_queue_try_pop(&pool->free_items, &item);
    return pool_take_owned(pool, popped, item);
}

void *ids_pool_acquire_timeout(ids_pool_t *pool, unsigned int timeout_ms)
{
    void *item = NULL;
    bool popped;

    if (pool == NULL) {
        return NULL;
    }

    popped = ids_queue_pop_timeout(&pool->free_items, &item, timeout_ms);
    return pool_take_owned(pool, popped, item);
}

void ids_pool_release(ids_pool_t *pool, void *item)
{
    size_t index;

    if (pool == NULL || item == NULL) {
        return;
    }

    pthread_mutex_lock(&pool->lock);
    if (!pool_index_for(pool, item, &index) || pool->in_use[index] == 0U) {
        pool->invalid_releases++;
        pthread_mutex_unlock(&pool->lock);
        return;
    }
    /*
     * Clear in_use ONLY after the push succeeds. Clearing it first and then
     * dropping the lock before pushing creates a window where the slot is
     * marked free in the bitmap but not yet reachable via the free queue —
     * if the push fails (queue closed), the slot is permanently lost.
     */
    pthread_mutex_unlock(&pool->lock);

    if (ids_queue_try_push(&pool->free_items, item)) {
        pthread_mutex_lock(&pool->lock);
        pool->in_use[index] = 0U;
        if (pool->in_use_count > 0) {
            pool->in_use_count--;
        }
        pthread_mutex_unlock(&pool->lock);
    } else {
        pthread_mutex_lock(&pool->lock);
        pool->invalid_releases++;
        pthread_mutex_unlock(&pool->lock);
    }
}

size_t ids_pool_available(ids_pool_t *pool)
{
    if (pool == NULL) {
        return 0;
    }

    return ids_queue_size(&pool->free_items);
}

size_t ids_pool_capacity(ids_pool_t *pool)
{
    if (pool == NULL) {
        return 0;
    }

    return pool->capacity;
}

size_t ids_pool_in_use(ids_pool_t *pool)
{
    size_t in_use;

    if (pool == NULL) {
        return 0;
    }

    pthread_mutex_lock(&pool->lock);
    in_use = pool->in_use_count;
    pthread_mutex_unlock(&pool->lock);
    return in_use;
}

uint64_t ids_pool_failed_acquires(ids_pool_t *pool)
{
    uint64_t failed;

    if (pool == NULL) {
        return 0;
    }

    pthread_mutex_lock(&pool->lock);
    failed = pool->failed_acquires;
    pthread_mutex_unlock(&pool->lock);
    return failed;
}

uint64_t ids_pool_invalid_releases(ids_pool_t *pool)
{
    uint64_t invalid;

    if (pool == NULL) {
        return 0;
    }

    pthread_mutex_lock(&pool->lock);
    invalid = pool->invalid_releases;
    pthread_mutex_unlock(&pool->lock);
    return invalid;
}
