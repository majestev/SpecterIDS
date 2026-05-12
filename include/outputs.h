#ifndef SPECTERIDS_OUTPUTS_H
#define SPECTERIDS_OUTPUTS_H

#include "event.h"
#include "logger.h"
#include "modules.h"

typedef struct {
    output_module_t console;
    output_module_t file;
    output_module_t jsonl;
    output_module_t pcap;
} output_registry_t;

void output_registry_init(output_registry_t *registry, logger_t *logger);
void output_registry_cleanup(output_registry_t *registry);
int output_registry_process(output_registry_t *registry, const ids_event_t *event);

#endif
