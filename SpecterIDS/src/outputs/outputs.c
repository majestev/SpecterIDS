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

static int noop_flush(output_module_t *module)
{
    (void)module;
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
    registry->sqlite.name = "sqlite";
    registry->pcap.name = "pcap";
    registry->metrics.name = "metrics";

    registry->console.init = noop_init;
    registry->file.init = noop_init;
    registry->jsonl.init = noop_init;
    registry->sqlite.init = noop_init;
    registry->pcap.init = noop_init;
    registry->metrics.init = noop_init;

    registry->console.process = noop_process;
    registry->file.process = noop_process;
    registry->jsonl.process = noop_process;
    registry->sqlite.process = noop_process;
    registry->pcap.process = noop_process;
    registry->metrics.process = noop_process;

    registry->console.flush = noop_flush;
    registry->file.flush = noop_flush;
    registry->jsonl.flush = noop_flush;
    registry->sqlite.flush = noop_flush;
    registry->pcap.flush = noop_flush;
    registry->metrics.flush = noop_flush;

    registry->console.cleanup = noop_cleanup;
    registry->file.cleanup = noop_cleanup;
    registry->jsonl.cleanup = noop_cleanup;
    registry->sqlite.cleanup = noop_cleanup;
    registry->pcap.cleanup = noop_cleanup;
    registry->metrics.cleanup = noop_cleanup;

    (void)registry->console.init(&registry->console, logger);
    (void)registry->file.init(&registry->file, logger);
    (void)registry->jsonl.init(&registry->jsonl, logger);
    (void)registry->sqlite.init(&registry->sqlite, logger);
    (void)registry->pcap.init(&registry->pcap, logger);
    (void)registry->metrics.init(&registry->metrics, logger);
}

void output_registry_cleanup(output_registry_t *registry)
{
    if (registry == NULL) {
        return;
    }

    registry->console.cleanup(&registry->console);
    registry->file.cleanup(&registry->file);
    registry->jsonl.cleanup(&registry->jsonl);
    registry->sqlite.cleanup(&registry->sqlite);
    registry->pcap.cleanup(&registry->pcap);
    registry->metrics.cleanup(&registry->metrics);
}

int output_registry_process(output_registry_t *registry, const ids_event_t *event)
{
    if (registry == NULL || event == NULL) {
        return -1;
    }

    (void)registry->console.process(&registry->console, event);
    (void)registry->file.process(&registry->file, event);
    (void)registry->jsonl.process(&registry->jsonl, event);
    (void)registry->sqlite.process(&registry->sqlite, event);
    (void)registry->pcap.process(&registry->pcap, event);
    (void)registry->metrics.process(&registry->metrics, event);
    return 0;
}

int output_registry_flush(output_registry_t *registry)
{
    if (registry == NULL) {
        return -1;
    }

    (void)registry->console.flush(&registry->console);
    (void)registry->file.flush(&registry->file);
    (void)registry->jsonl.flush(&registry->jsonl);
    (void)registry->sqlite.flush(&registry->sqlite);
    (void)registry->pcap.flush(&registry->pcap);
    (void)registry->metrics.flush(&registry->metrics);
    return 0;
}
