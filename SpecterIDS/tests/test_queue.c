#include "queue.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

#define ITEMS 1000

typedef struct {
    ids_queue_t *queue;
    intptr_t sum;
} worker_arg_t;

static void *producer(void *arg)
{
    worker_arg_t *worker = (worker_arg_t *)arg;
    intptr_t i;

    for (i = 1; i <= ITEMS; i++) {
        assert(ids_queue_push(worker->queue, (void *)i));
    }
    ids_queue_close(worker->queue);
    return NULL;
}

static void *consumer(void *arg)
{
    worker_arg_t *worker = (worker_arg_t *)arg;
    void *item = NULL;

    while (ids_queue_pop(worker->queue, &item)) {
        worker->sum += (intptr_t)item;
    }
    return NULL;
}

int main(void)
{
    ids_queue_t queue;
    pthread_t producer_thread;
    pthread_t consumer_thread;
    worker_arg_t producer_arg;
    worker_arg_t consumer_arg;
    void *item = NULL;
    intptr_t expected = ((intptr_t)ITEMS * (ITEMS + 1)) / 2;

    assert(ids_queue_init(&queue, 64) == 0);
    producer_arg.queue = &queue;
    producer_arg.sum = 0;
    consumer_arg.queue = &queue;
    consumer_arg.sum = 0;

    assert(pthread_create(&producer_thread, NULL, producer, &producer_arg) == 0);
    assert(pthread_create(&consumer_thread, NULL, consumer, &consumer_arg) == 0);
    assert(pthread_join(producer_thread, NULL) == 0);
    assert(pthread_join(consumer_thread, NULL) == 0);
    assert(consumer_arg.sum == expected);

    ids_queue_destroy(&queue);

    assert(ids_queue_init(&queue, 1) == 0);
    assert(ids_queue_try_push(&queue, (void *)1));
    assert(!ids_queue_push_timeout(&queue, (void *)2, 1));
    assert(ids_queue_dropped(&queue) == 1);
    assert(ids_queue_pop_timeout(&queue, &item, 1));
    assert((intptr_t)item == 1);
    assert(!ids_queue_pop_timeout(&queue, &item, 1));
    ids_queue_close(&queue);
    ids_queue_destroy(&queue);

    puts("test_queue: ok");
    return 0;
}
