#ifndef SPECTERIDS_STORAGE_H
#define SPECTERIDS_STORAGE_H

#include <stdbool.h>

#include "common.h"

typedef struct {
    char log_dir[SPECTERIDS_PATH_LEN];
    char capture_dir[SPECTERIDS_PATH_LEN];
    char reports_dir[SPECTERIDS_PATH_LEN];
} storage_t;

int storage_init(storage_t *storage,
                 const char *log_dir,
                 const char *capture_dir,
                 const char *reports_dir);
const char *storage_log_dir(const storage_t *storage);
const char *storage_capture_dir(const storage_t *storage);
const char *storage_reports_dir(const storage_t *storage);

#endif
