#include "outputs.h"

#include <string.h>

static int noop_init(output_module_t *module, logger_t *logger)
{
    module->state = logger;
    return 0;
}

static int noop_process(output_module_t *module, const ids_event_t *event)
{
    (void)module;
    (void)event;
    return 0;
}

static void noop_cleanup(output_module_t *module)
{
    if (module != NULL) {
        module->state = NULL;
    }
}

void output_registry_init(output_registry_t *registry, logger_t *logger)
{
    if (registry == NULL) {
        return;
    }

    memset(registry, 0, sizeof(*registry));
    registry->console.name = "console";
    registry->file.name = "file";
    registry->jsonl.name = "jsonl";
    registry->pcap.name = "pcap";

    registry->console.init = noop_init;
    registry->file.init = noop_init;
    registry->jsonl.init = noop_init;
    registry->pcap.init = noop_init;

    registry->console.process = noop_process;
    registry->file.process = noop_process;
    registry->jsonl.process = noop_process;
    registry->pcap.process = noop_process;

    registry->console.cleanup = noop_cleanup;
    registry->file.cleanup = noop_cleanup;
    registry->jsonl.cleanup = noop_cleanup;
    registry->pcap.cleanup = noop_cleanup;

    (void)registry->console.init(&registry->console, logger);
    (void)registry->file.init(&registry->file, logger);
    (void)registry->jsonl.init(&registry->jsonl, logger);
    (void)registry->pcap.init(&registry->pcap, logger);
}

void output_registry_cleanup(output_registry_t *registry)
{
    if (registry == NULL) {
        return;
    }

    registry->console.cleanup(&registry->console);
    registry->file.cleanup(&registry->file);
    registry->jsonl.cleanup(&registry->jsonl);
    registry->pcap.cleanup(&registry->pcap);
}

int output_registry_process(output_registry_t *registry, const ids_event_t *event)
{
    if (registry == NULL || event == NULL) {
        return -1;
    }

    (void)registry->console.process(&registry->console, event);
    (void)registry->file.process(&registry->file, event);
    (void)registry->jsonl.process(&registry->jsonl, event);
    (void)registry->pcap.process(&registry->pcap, event);
    return 0;
}
