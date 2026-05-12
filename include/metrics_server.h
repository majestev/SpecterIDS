#ifndef SPECTERIDS_METRICS_SERVER_H
#define SPECTERIDS_METRICS_SERVER_H

#include <stdbool.h>
#include <signal.h>
#include <pthread.h>

#include "stats.h"

typedef struct {
    bool enabled;
    int port;
    ids_stats_t *stats;
    volatile sig_atomic_t *stop_requested;
    pthread_t thread;
    bool running;
} metrics_server_t;

int metrics_server_start(metrics_server_t *server,
                         bool enabled,
                         int port,
                         ids_stats_t *stats,
                         volatile sig_atomic_t *stop_requested);
void metrics_server_stop(metrics_server_t *server);

#endif
