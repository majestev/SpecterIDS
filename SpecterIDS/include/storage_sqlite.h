#ifndef SPECTERIDS_STORAGE_SQLITE_H
#define SPECTERIDS_STORAGE_SQLITE_H

#include <stdbool.h>

#include "event.h"
#include "stats.h"

typedef struct storage_sqlite storage_sqlite_t;

storage_sqlite_t *storage_sqlite_create(void);
void storage_sqlite_destroy(storage_sqlite_t *storage);
bool storage_sqlite_compiled(void);
int storage_sqlite_open(storage_sqlite_t *storage,
                        bool enabled,
                        const char *path,
                        const char *input_mode,
                        const char *input_target);
void storage_sqlite_attach_stats(storage_sqlite_t *storage, ids_stats_t *stats);
void storage_sqlite_event_handler(const ids_event_t *event, void *user_data);
void storage_sqlite_record_metrics(storage_sqlite_t *storage, ids_stats_t *stats);
void storage_sqlite_finish_session(storage_sqlite_t *storage, ids_stats_t *stats);

#endif
