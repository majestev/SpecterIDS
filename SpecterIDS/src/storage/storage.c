#include "storage.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int ensure_dir(const char *path)
{
    struct stat statbuf;

    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    if (mkdir(path, 0755) == 0) {
        return 0;
    }

    if (errno == EEXIST && stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
        return 0;
    }

    return -1;
}

int storage_init(storage_t *storage,
                 const char *log_dir,
                 const char *capture_dir,
                 const char *reports_dir)
{
    if (storage == NULL) {
        return -1;
    }

    ids_copy_string(storage->log_dir, sizeof(storage->log_dir), log_dir != NULL ? log_dir : "logs");
    ids_copy_string(storage->capture_dir, sizeof(storage->capture_dir), capture_dir != NULL ? capture_dir : "captures");
    ids_copy_string(storage->reports_dir, sizeof(storage->reports_dir), reports_dir != NULL ? reports_dir : "reports");

    if (ensure_dir(storage->log_dir) != 0 ||
        ensure_dir(storage->capture_dir) != 0 ||
        ensure_dir(storage->reports_dir) != 0) {
        fprintf(stderr, "Failed to initialize storage directories: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

const char *storage_log_dir(const storage_t *storage)
{
    return storage != NULL ? storage->log_dir : "logs";
}

const char *storage_capture_dir(const storage_t *storage)
{
    return storage != NULL ? storage->capture_dir : "captures";
}

const char *storage_reports_dir(const storage_t *storage)
{
    return storage != NULL ? storage->reports_dir : "reports";
}
