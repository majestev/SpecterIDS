#include "queue.h"

#include <stdlib.h>
#include <string.h>

int ids_queue_init(ids_queue_t *queue, size_t capacity)
{
    if (queue == NULL || capacity == 0) {
        return -1;
    }

    memset(queue, 0, sizeof(*queue));
    queue->items = calloc(capacity, sizeof(queue->items[0]));
    if (queue->items == NULL) {
        return -1;
    }

    queue->capacity = capacity;
    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        free(queue->items);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->lock);
        free(queue->items);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }
    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->lock);
        free(queue->items);
        memset(queue, 0, sizeof(*queue));
        return -1;
    }

    return 0;
}

void ids_queue_destroy(ids_queue_t *queue)
{
    if (queue == NULL) {
        return;
    }

    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->lock);
    free(queue->items);
    memset(queue, 0, sizeof(*queue));
}

void ids_queue_close(ids_queue_t *queue)
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

static bool push_locked(ids_queue_t *queue, void *item)
{
    if (queue->closed || queue->count == queue->capacity) {
        return false;
    }

    queue->items[queue->tail] = item;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    queue->pushed++;
    pthread_cond_signal(&queue->not_empty);
    return true;
}

bool ids_queue_push(ids_queue_t *queue, void *item)
{
    bool pushed;

    if (queue == NULL || item == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    while (!queue->closed && queue->count == queue->capacity) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    pushed = push_locked(queue, item);
    if (!pushed) {
        queue->dropped++;
    }
    pthread_mutex_unlock(&queue->lock);
    return pushed;
}

bool ids_queue_try_push(ids_queue_t *queue, void *item)
{
    bool pushed;

    if (queue == NULL || item == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    pushed = push_locked(queue, item);
    if (!pushed) {
        queue->dropped++;
    }
    pthread_mutex_unlock(&queue->lock);
    return pushed;
}

bool ids_queue_pop(ids_queue_t *queue, void **item)
{
    if (queue == NULL || item == NULL) {
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

    *item = queue->items[queue->head];
    queue->items[queue->head] = NULL;
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    queue->popped++;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

bool ids_queue_try_pop(ids_queue_t *queue, void **item)
{
    if (queue == NULL || item == NULL) {
        return false;
    }

    pthread_mutex_lock(&queue->lock);
    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->lock);
        return false;
    }

    *item = queue->items[queue->head];
    queue->items[queue->head] = NULL;
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    queue->popped++;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return true;
}

size_t ids_queue_size(ids_queue_t *queue)
{
    size_t count;

    if (queue == NULL) {
        return 0;
    }

    pthread_mutex_lock(&queue->lock);
    count = queue->count;
    pthread_mutex_unlock(&queue->lock);
    return count;
}

uint64_t ids_queue_dropped(ids_queue_t *queue)
{
    uint64_t dropped;

    if (queue == NULL) {
        return 0;
    }

    pthread_mutex_lock(&queue->lock);
    dropped = queue->dropped;
    pthread_mutex_unlock(&queue->lock);
    return dropped;
}
