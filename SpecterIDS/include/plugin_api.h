#ifndef SPECTERIDS_PLUGIN_API_H
#define SPECTERIDS_PLUGIN_API_H

#include <stddef.h>
#include <stdint.h>

#include "detection.h"
#include "parser.h"

#define SPECTERIDS_PLUGIN_ABI_VERSION 2U
#define SPECTERIDS_PLUGIN_ENTRYPOINT "specterids_plugin_descriptor"
#define SPECTERIDS_PLUGIN_NAME_LEN 64

#define SPECTERIDS_PLUGIN_CAP_PACKET 0x00000001U
#define SPECTERIDS_PLUGIN_CAP_ALERT 0x00000002U
#define SPECTERIDS_PLUGIN_CAP_MASK \
    (SPECTERIDS_PLUGIN_CAP_PACKET | SPECTERIDS_PLUGIN_CAP_ALERT)

typedef struct {
    uint32_t abi_version;
    uint32_t min_core_abi;
    uint32_t capabilities;
    const char *name;
    const char *description;
    int (*init)(void **state);
    int (*start)(void *state);
    size_t (*packet_handler)(void *state,
                             const packet_info_t *packet,
                             alert_t *alerts,
                             size_t max_alerts);
    void (*alert_handler)(void *state, const alert_t *alert);
    void (*stop)(void *state);
    void (*unload)(void *state);
} specterids_plugin_descriptor_t;

typedef const specterids_plugin_descriptor_t *(*specterids_plugin_descriptor_fn)(void);

const specterids_plugin_descriptor_t *specterids_plugin_descriptor(void);

#endif
