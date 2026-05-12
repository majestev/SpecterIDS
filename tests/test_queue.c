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
    puts("test_queue: ok");
    return 0;
}
