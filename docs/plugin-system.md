# Plugin System

SpecterIDS defines internal module interfaces in `include/modules.h`.

## Detection Module

```c
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
```

## Output Module

Output modules receive events and can write to a destination such as console, file, JSONL, PCAP or metrics.

## Parser Module

Parser modules expose `process()` around a packet header and byte buffer. The built-in parser handles Ethernet, ARP and IPv4 metadata.

## Enrichment Module

Reserved for future metadata enrichment such as asset labels or lab-owned IP tags.

## Design Rule

Modules must remain defensive and passive. They may inspect local metadata, emit events and write local outputs. They must not exploit, inject traffic, evade controls or collect secrets.
