#ifndef SPECTERIDS_MODULES_H
#define SPECTERIDS_MODULES_H

#include <stddef.h>

#include "detection.h"
#include "event.h"
#include "logger.h"
#include "parser.h"
#include "rules.h"

typedef struct detection_module {
    const char *name;
    int (*init)(struct detection_module *module, const ids_rules_t *rules);
    size_t (*process)(struct detection_module *module,
                      const packet_info_t *packet,
                      alert_t *alerts,
                      size_t max_alerts);
    void (*cleanup)(struct detection_module *module);
    void *state;
} detection_module_t;

typedef struct output_module {
    const char *name;
    int (*init)(struct output_module *module, logger_t *logger);
    int (*process)(struct output_module *module, const ids_event_t *event);
    void (*cleanup)(struct output_module *module);
    void *state;
} output_module_t;

typedef struct parser_module {
    const char *name;
    int (*init)(struct parser_module *module);
    bool (*process)(struct parser_module *module,
                    const packet_header_t *header,
                    const unsigned char *data,
                    packet_info_t *packet,
                    char *error,
                    size_t error_size);
    void (*cleanup)(struct parser_module *module);
    void *state;
} parser_module_t;

typedef struct enrichment_module {
    const char *name;
    int (*init)(struct enrichment_module *module);
    void (*process)(struct enrichment_module *module, packet_info_t *packet);
    void (*cleanup)(struct enrichment_module *module);
    void *state;
} enrichment_module_t;

void modules_print_builtin(void);

#endif
