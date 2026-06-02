
---

# Architecture

SpecterIDS is organized as small C modules with clear ownership. The program captures packets, moves them through a bounded threaded pipeline, converts them to safe metadata, applies rule-driven detection and emits logs/dashboard/forensic data.

## Runtime Flow

```text
src/main.c
  |
  +-- src/config/config.c      loads optional key=value runtime configuration
  +-- src/rules/rules.c        loads detection thresholds and severities
  +-- src/utils/logger.c       opens text/JSONL logs
  +-- src/dashboard/dashboard.c tracks runtime counters
  |
  v
src/capture/capture.c -> src/queues/queue.c + src/memory/pool.c
  -> src/datalink/datalink.c -> src/parser/parser.c
  -> src/detection/detection.c -> src/correlation/correlation.c
  -> src/utils/logger.c
       \-> src/utils/stats.c -> src/dashboard/dashboard.c + src/metrics/metrics_server.c
       \-> src/events/event.c -> src/plugins/modules.c + src/outputs/outputs.c + src/storage/storage_sqlite.c
```

## Modules

- `src/main.c`: CLI parsing, config precedence, signal handling and lifecycle cleanup.
- `src/config/`: safe `key=value` parser for `config/specterids.conf`.
- `src/capture/`: `libpcap` live capture, offline PCAP replay, BPF setup and dispatch loop.
- `src/datalink/`: layer-2 abstraction for Ethernet, Linux cooked capture and RAW IP.
- `src/parser/`: bounds-checked parser for ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6.
- `src/packet/`: reserved boundary for the normalized packet model.
- `src/events/`: internal synchronous/asynchronous event dispatcher with typed events, IDs, priorities and counters.
- `src/queues/`: bounded multi-producer/multi-consumer queues.
- `src/threading/`: reserved boundary for shared lifecycle/thread-pool helpers.
- `src/memory/`: reusable object pools for packet-path allocations.
- `src/detection/`: sharded per-source state machines and detection modules.
- `src/correlation/`: temporal correlation over alert streams.
- `src/rules/`: tolerant rule parser with defaults, groups, targets and warnings.
- `src/plugins/`: built-in module interface registry.
- `src/outputs/`: output registry.
- `src/storage/`: directory/storage abstraction and optional SQLite metadata store.
- `src/metrics/`: localhost read-only metrics endpoint.
- `src/dashboard/`: terminal counters, top source IPs and recent alerts.
- `src/benchmark/`: reserved boundary for benchmark helpers.
- `src/utils/`: common string helpers, telemetry counters and logger.
- `plugin_api.h`: stable opt-in ABI for defensive dynamic detection plugins.

See `docs/contracts.md` for the module-by-module engineering contracts,
ownership rules and failure modes that these boundaries are expected to keep.

## Safety Boundaries

The parser validates captured length before reading every header field. Truncated packets are either rejected or returned with `truncated=true` when enough metadata is available. Detection only uses metadata and never sends packets.

Dynamic plugins are deliberately narrow: the core validates ABI version,
entrypoint and capabilities, calls `init/start/packet_handler/stop/unload`, and
exposes only parsed metadata plus an alert buffer. Plugins remain optional and
are never loaded unless configured with `--plugin`, `--plugin-dir` or
`plugins_enabled=true`.

## State Model

Detection state is keyed by source IP and split into configurable shards selected by a stable hash of the source address. Each shard owns its lock and source table, reducing contention between detection workers. Each source has bounded event windows:

- destination ports for port scan detection
- TCP SYN timestamps
- SSH SYN timestamps
- ICMP timestamps
- UDP timestamps
- repeated destination observations for beaconing

The fixed limits prevent unbounded memory growth during noisy lab sessions.

## Threading

Current threaded model:

```text
capture thread -> raw queue -> parser workers -> parsed queue -> detection workers -> log queue -> logger thread
                                                             |
                                                             v
                                                        stats/dashboard
```

In implementation this is capture thread, parser workers, detection workers and logger thread. The dashboard is refreshed from the capture loop using stats snapshots.

---

# Usage

## Build

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
make
```

SQLite support is optional:

```bash
sudo apt install sqlite3 libsqlite3-dev
make sqlite
```

## Help

```bash
./specterids --help
./specterids --version
```

## Live Capture

```bash
sudo ./specterids -i eth0
sudo ./specterids -i wlan0 --verbose
sudo ./specterids -i eth0 --quiet
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
sudo ./specterids -i eth0 --dashboard-verbose --dashboard-interval 2 --no-color
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --metrics
sudo ./specterids -i eth0 --metrics 9090
sudo ./specterids -i eth0 --bpf "tcp or udp"
sudo ./specterids -i eth0 --detection-shards 16
```

## Offline PCAP Replay

Offline mode reuses the same parser, detection, logging, dashboard and metrics pipeline as live capture. It does not require root.

```bash
make fixtures
./specterids --pcap samples/example.pcap
./specterids --pcap samples/example.pcap --json
./specterids --pcap samples/example.pcap --rules rules/default.rules
./specterids --pcap samples/example.pcap --dashboard
./specterids --pcap samples/example.pcap --sqlite data/lab.db
./specterids --pcap samples/example.pcap --speed 10x
./specterids --pcap samples/example.pcap --benchmark
```

Invalid or missing PCAP files fail with a clear `pcap_open_offline` error.

## Config File

```bash
sudo ./specterids --config config/specterids.conf
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard
```

CLI arguments override the config file.

## Logs

- `logs/specterids.log`: packet metadata and status messages.
- `logs/alerts.log`: one-line text alerts.
- `logs/alerts.jsonl`: JSON Lines alerts when `--json` or `json_logs=true` is enabled.
- `captures/suspicious.pcap`: context packets around alerts when `--pcap-export` or `pcap_export=true` is enabled.
- `data/specterids.db`: optional SQLite export when built with `make sqlite`.

## Supported Datalinks

- `DLT_EN10MB`: Ethernet, including basic VLAN tags.
- `DLT_LINUX_SLL`: Linux cooked capture.
- `DLT_LINUX_SLL2`: Linux cooked capture v2.
- `DLT_RAW`: raw IPv4/IPv6 payload.

Unsupported datalink types are rejected before packet parsing.

## Safe Lab Validation

Prefer deterministic PCAP replay for detection demonstrations and regression:

```bash
make fixtures
./specterids --pcap tests/pcaps/portscan.pcap --rules rules/default.rules
./specterids --pcap tests/pcaps/bruteforce.pcap --rules rules/default.rules
./specterids --pcap tests/pcaps/synflood.pcap --rules rules/default.rules
./specterids --pcap tests/pcaps/ipv6.pcap --json
```

For harmless local smoke traffic only, use the safe helper against a host you
own or `127.0.0.1`:

```bash
./scripts/fake-traffic-safe.sh 127.0.0.1
```

Stop with `Ctrl+C`. SpecterIDS closes capture/log handles and prints a session summary.

---

# Configuration

SpecterIDS uses safe built-in defaults, then applies an optional `key=value`
configuration file, then applies CLI overrides.

## Load Order

```text
built-in defaults -> --config file -> CLI arguments
```

Example:

```bash
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard --bpf "tcp"
```

## Common Options

| Key | Default | Notes |
| --- | --- | --- |
| `interface` | unset | Live capture interface. |
| `pcap_file` | unset | Offline replay input; enables offline mode. |
| `pcap_replay` | `false` | Preserve PCAP timing in offline mode. |
| `pcap_speed` | `1x` | Replay multiplier for `pcap_replay`, range `0.1x..100x`. |
| `benchmark_mode` | `false` | Print deterministic offline replay benchmark summary. |
| `log_dir` | `logs` | Text and JSONL logs. |
| `rules_file` | `rules/default.rules` | Detection rules. |
| `bpf_filter` | `ip or ip6 or arp` | libpcap capture filter. |
| `workers` | `2` | Sets parser and detection workers together. |
| `parser_workers` | `2` | Parser worker count, range `1..32`. |
| `detection_workers` | `2` | Detection worker count, range `1..32`. |
| `detection_shards` | `16` | Detection state shards, range `1..256`. |
| `queue_size` | `1024` | Bounded queue/pool size, range `64..65536`. |
| `rotation_size_mb` | `32` | Text/JSONL rotation threshold. |
| `dashboard_mode` | `detailed` | `compact`, `detailed` or `advanced`. |
| `dashboard_refresh_ms` | `1000` | Dashboard refresh interval in milliseconds. |
| `no_color` | `false` | Disable ANSI colors and screen clearing. |
| `metrics_enabled` | `false` | Local read-only metrics endpoint. |
| `metrics_port` | `9090` | Local metrics port, range `1024..65535`. |
| `sqlite_enabled` | `false` | Requires `make sqlite`. |
| `sqlite_path` | `data/specterids.db` | SQLite database path. |
| `plugins_enabled` | `false` | Enables configured defensive `.so` plugins. |
| `plugin_dir` | `plugins` | Directory scanned by `--plugin-dir`/config. |
| `plugin` / `plugin_paths` | unset | Comma-separated plugin paths or repeated `plugin=` entries. |

## Beaconing Tuning

```ini
beaconing_min_hits=8
beaconing_interval=30
beaconing_tolerance=3
beaconing_ignore_private=true
beaconing_whitelist=8.8.8.8,1.1.1.1
```

Beaconing remains a heuristic. In noisy labs, increase `min_hits` or use a
whitelist for benign recurring destinations.

## Validation Behavior

Invalid values generate warnings and keep the previous safe value. Unknown keys
are ignored. Configuration errors do not enable offensive behavior and do not
modify traffic.

---

# Detection Rules

Rules are loaded from `rules/default.rules` by default or from a custom file with `--rules`.

## Format

```text
[group default]
RULE_NAME key=value key=value ...

[group optional_name]
targets=192.0.2.10,2001:db8::10
RULE_NAME key=value key=value ...
```

Comments start with `#`. Empty lines are ignored. Invalid options produce warnings and leave safe defaults in place.

## Default Rules

```text
[group default]
PORT_SCAN threshold=20 window=10 severity=HIGH enabled=true
SSH_BRUTE_FORCE port=22 threshold=10 window=60 severity=HIGH enabled=true
SYN_FLOOD threshold=100 window=5 severity=CRITICAL enabled=true
ICMP_FLOOD threshold=100 window=5 severity=MEDIUM enabled=true
UDP_FLOOD threshold=200 window=10 severity=MEDIUM enabled=true
BEACONING min_hits=8 interval=30 tolerance=3 ignore_private=true severity=LOW enabled=true
ARP_SPOOFING severity=HIGH enabled=true
DNS_FLOOD threshold=150 window=10 severity=MEDIUM enabled=true
HTTP_FLOOD ports=80,443 threshold=300 window=10 severity=HIGH enabled=true
RATE_ANOMALY threshold=500 window=10 severity=MEDIUM enabled=true
SLOW_SCAN threshold=15 window=300 severity=MEDIUM enabled=true
SENSITIVE_PORTS ports=22,23,445,3389 threshold=1 window=60 severity=MEDIUM enabled=true
CONNECTION_EXCESS threshold=200 window=60 severity=HIGH enabled=true
LARGE_PAYLOAD threshold=1400 window=60 severity=MEDIUM enabled=true
VOLUME_ANOMALY threshold=10000000 window=60 severity=HIGH enabled=true
HEURISTIC_RISK threshold=80 window=300 severity=HIGH enabled=true
```

## Supported Options

- `enabled=true|false`
- `severity=LOW|MEDIUM|HIGH|CRITICAL`
- `threshold=<positive integer>`
- `window=<seconds>`
- `port=<1-65535>` for `SSH_BRUTE_FORCE`
- `ports=<p1,p2,...>` for `HTTP_FLOOD` and `SENSITIVE_PORTS`
- `min_hits=<positive integer>` for `BEACONING`
- `interval=<seconds>` for `BEACONING`
- `tolerance=<seconds>` for `BEACONING`
- `ignore_private=true|false` for `BEACONING`
- `whitelist=<ip1,ip2,...>` for `BEACONING`

## Groups and Destination Thresholds

Groups apply when the packet destination matches one of the exact `targets`.
Targets must be valid IPv4 or IPv6 textual addresses. Invalid target tokens are
ignored with warnings. If no group matches, the `default` group is used.

```text
[group web_servers]
targets=192.168.1.10,192.168.1.11,2001:db8::10
HTTP_FLOOD ports=80,443 threshold=300 window=10 severity=HIGH enabled=true
PORT_SCAN threshold=50 window=20 severity=MEDIUM enabled=true

[group lab_sensitive]
targets=10.0.0.5,10.0.0.6
SENSITIVE_PORTS ports=22,3389,5432 threshold=5 window=60 severity=CRITICAL enabled=true
```

## Rule Semantics

`PORT_SCAN`: same source touches more than `threshold` distinct TCP destination ports within `window` seconds.

`SSH_BRUTE_FORCE`: same source sends more than `threshold` TCP SYN packets to `port` within `window` seconds.

`SYN_FLOOD`: same source sends more than `threshold` TCP SYN packets without ACK within `window` seconds.

`ICMP_FLOOD`: same source sends more than `threshold` ICMP packets within `window` seconds.

`UDP_FLOOD`: same source sends more than `threshold` UDP packets within `window` seconds.

`BEACONING`: same source repeatedly contacts the same destination/protocol/port at approximately `interval` seconds, allowing `tolerance` seconds of drift, for at least `min_hits` observations.

`ARP_SPOOFING`: ARP sender IP is observed with a changed MAC address.

`DNS_FLOOD`: source exceeds DNS packet thresholds.

`HTTP_FLOOD`: source exceeds packet thresholds to configured HTTP-family ports.

`RATE_ANOMALY`: source exceeds generic packet-rate thresholds.

`SLOW_SCAN`: source touches many ports over a longer window.

`SENSITIVE_PORT`: source touches configured sensitive ports from `specterids.conf`.

`CONNECTION_EXCESS`: source creates too many TCP connection attempts.

`LARGE_PAYLOAD`: single packet metadata indicates an unusually large payload.

`VOLUME_ANOMALY`: source transfers excessive bytes in a window.

`HEURISTIC_RISK`: source risk score crosses the configured threshold.

## Tuning Notes

Small lab networks can use lower thresholds to demonstrate alerting quickly. Larger or noisy networks should increase thresholds and windows to reduce false positives. Beaconing now uses repeated `src -> dst/protocol/port`, average interval, tolerance, minimum hit count, private-address suppression and destination whitelist, but it is still a heuristic investigation signal rather than proof of compromise.

---

# Detection Engine

The detection engine maintains bounded per-source state and emits alert objects.
It is metadata-only and defensive.

## Sharding

Source state is split by hash of source IP:

```text
source_ip -> hash -> shard -> bucket -> source_state
```

Each shard owns:

- its own mutex
- hash buckets of source state
- ARP bindings
- bounded event windows

This reduces contention between detection workers while keeping ownership clear.
`specter_shard_pressure` reports whether state is balanced across configured
shards.

## Built-In Detection Modules

Detection stages are registered in a module table:

- `rate_anomaly`
- `arp_spoofing`
- `port_scan`
- `slow_scan`
- `sensitive_port`
- `connection_excess`
- `ssh_bruteforce`
- `syn_flood`
- `icmp_flood`
- `udp_flood`
- `dns_flood`
- `http_flood`
- `large_payload`
- `volume_anomaly`
- `beaconing`
- `heuristic_risk`

Adding a new built-in detection requires a bounded state model, a stage handler
and one module-table entry.

## Dynamic Plugins

Dynamic `.so` detection plugins run after built-in stages. They use
`include/plugin_api.h`, receive parsed metadata only and can emit alerts without
accessing internal shard state. The core validates ABI compatibility before
registration and exposes plugin packet/alert counters through metrics.

## State

Each source IP tracks fixed-size windows for:

- port touches
- SYN attempts
- SSH attempts
- ICMP/ICMPv6 packets
- UDP packets
- DNS packets
- generic packet rate
- connection attempts
- HTTP-family packet rate
- byte volume
- beaconing tuples

## Risk

Alerts increase a temporary risk score. Risk decays over time. High scores can
raise severity dynamically and can trigger `HEURISTIC_RISK`.

## Correlation

The correlation engine consumes alerts and can emit `THREAT_CORRELATION` when
multiple stages of suspicious behavior appear in the same window.

---

# Packet Flow

SpecterIDS now uses a bounded threaded pipeline.

```text
libpcap live or pcap_open_offline
  |
  v
capture thread
  |
  v
raw packet queue
  |
  v
parser workers
  |
  v
parsed packet queue
  |
  v
detection workers
  |
  v
log event queue
  |
  v
logger thread -> text logs / JSONL / suspicious PCAP
```

## Hot Path

The capture callback copies at most `snaplen` bytes into a pooled raw packet object. If the queue or pool is exhausted, the packet is dropped and the drop counter increases instead of blocking the capture path indefinitely.

Parser workers convert raw bytes into `packet_info_t` metadata. Detection workers apply stateful rules and emit alert objects. The logger thread is the only thread that writes log files, which avoids log-file lock contention in the detection path.

Offline PCAP mode uses the same queues and workers as live capture. Normal
offline mode drains as fast as possible; `--pcap-replay` preserves packet
timing, and `--pcap-speed Nx` scales that timing.

IPv6 parsing covers EtherType IPv6, TCP, UDP, ICMPv6 and common extension
headers including hop-by-hop, routing, destination options, AH and fragment
headers. Truncated or unsupported packets are counted as parser failures
instead of reaching detection with partial metadata.

## Backpressure

Queues are bounded. The capture side uses non-blocking enqueue to prefer controlled drops over unbounded memory growth. Parser and detection stages use bounded pool acquisition and bounded queue push timeouts, so downstream stalls become visible drops instead of indefinite worker starvation.

Queue depths, drops, average parser/detection/logging latency, IPv4/IPv6
counts, shard pressure and plugin counters are exposed through dashboard
snapshots and the localhost metrics endpoint.

## Forensics

When suspicious PCAP export is enabled, the logger keeps a small ring of recent packets and writes context packets to `captures/suspicious.pcap` when alerts occur.

---

# Threading Model

## Threads

- Capture thread: owns the `pcap_t` handle and pushes raw packet objects.
- Parser workers: parse raw packet objects into metadata.
- Detection workers: run the detection engine and create log events.
- Logger thread: writes packet logs, alert logs, JSONL and suspicious PCAP exports.
- Event dispatcher thread: optional asynchronous delivery for alert/storage/output subscribers.
- Metrics thread: optional localhost HTTP endpoint for `/metrics`.

## Synchronization

- `ids_queue_t` uses one mutex and two condition variables per queue.
- `ids_pool_t` reuses `ids_queue_t` as a free-object list.
- Detection state is sharded by source-IP hash. Each shard has its own mutex and bounded source table.
- Dynamic plugins are invoked after built-in shard processing. The core serializes plugin calls with a plugin mutex so plugin-local state is safe by default.
- Logger writes are serialized by the logger mutex.
- Stats use a small mutex-protected aggregate.
- Event bus copies subscriber lists under lock and invokes handlers outside the lock.
- The asynchronous event bus uses owned packet/alert/message snapshots so subscribers never depend on worker stack lifetime.
- Parser and detection handoff operations use timeout-capable queue/pool calls.
  Under sustained pressure they drop and count work instead of waiting forever.

## Shutdown

`SIGINT` and `SIGTERM` set a `sig_atomic_t` stop flag. The capture thread stops after the next `pcap_dispatch()` timeout, closes the raw queue, workers drain queued items, then downstream queues close in order. The async event bus is stopped after capture completes so queued storage/output events are drained before log and storage backends are destroyed.

## Design Tradeoffs

Detection sharding keeps the simple per-source state model while avoiding one global hot lock across all detection workers. A single busy source can still serialize inside its shard, but unrelated sources proceed independently.

`detection_shards` and `--detection-shards` accept 1-256 shards. Runtime
metrics expose shard count and shard pressure so operators can see whether one
shard is carrying disproportionate source state.

The event bus supports synchronous fallback and asynchronous delivery. The async mode is bounded by `queue_size`; if it cannot start, SpecterIDS continues with synchronous delivery and emits a warning.

The pipeline also has a lightweight watchdog: when queue pressure stays above
90%, it emits a bounded warning instead of allocating more memory. A heartbeat
event is also published periodically from the pipeline loop so health subscribers
can distinguish idle operation from a stuck runtime.

---

# Memory Management

SpecterIDS avoids packet-path allocation by using fixed-size object pools.

## Pools

- raw packet pool: stores bounded packet bytes plus capture metadata.
- parsed packet pool: stores `packet_info_t` and ownership of a raw object.
- log event pool: stores parsed packet ownership and alert arrays.
- event bus queue: stores owned snapshots of packet, alert and short message payloads for asynchronous subscribers.

Pool capacity follows `queue_size`. The default is 1024.

## Limits

- `SPECTERIDS_MAX_PACKET_BYTES`: maximum copied bytes per packet.
- `SPECTERIDS_MAX_ALERTS_PER_PACKET`: alert burst cap per packet.
- `SPECTERIDS_MAX_SENSITIVE_PORTS`: bounded sensitive-port config.
- fixed event windows in detection state to avoid unbounded per-IP growth.
- event queues are bounded by `queue_size` and never grow without limit.

## Failure Behavior

When pools or queues are exhausted, SpecterIDS drops packets or events and increments drop counters. It does not allocate unbounded memory to catch up.

Pool ownership is tracked per slot. `ids_pool_release()` validates that the
pointer belongs to the pool and is currently checked out. Invalid releases and
double releases are counted and ignored; release never blocks on a full free
list. Parser and detection workers use bounded pool-acquire timeouts so overload
becomes visible drops rather than hidden starvation.

## Ownership

Raw packet ownership moves from capture to parser, then to detection/log events, and finally back to the raw pool after the logger thread finishes. Parsed and log event objects follow the same acquire/use/release lifecycle. This keeps ownership explicit and avoids hidden frees across modules.

Asynchronous events use value copies. When a worker publishes an alert, the event bus copies the alert structure and any packet metadata needed by subscribers before enqueueing it. This avoids dangling pointers when the publishing worker returns packet objects to their pools.

Detection state is owned by shards. Each shard owns its source records, rolling timestamp windows and beaconing history, and releases them during `detection_destroy()`.

---

# Event System

SpecterIDS uses an in-process event bus to decouple packet capture, parsing,
detection, outputs, storage and metrics.

## Flow

```text
PacketCapturedEvent
  -> DatalinkParsedEvent
  -> NetworkPacketParsedEvent
  -> PacketParsedEvent
  -> DetectionEvent
  -> CorrelationEvent
  -> AlertEvent
  -> OutputEvent
  -> StorageEvent
  -> MetricsEvent
```

## Event Types

- `IDS_EVENT_PACKET_CAPTURED`
- `IDS_EVENT_DATALINK_PARSED`
- `IDS_EVENT_NETWORK_PACKET_PARSED`
- `IDS_EVENT_PACKET_PARSED`
- `IDS_EVENT_DETECTION_COMPLETE`
- `IDS_EVENT_CORRELATION`
- `IDS_EVENT_ALERT`
- `IDS_EVENT_OUTPUT_WRITTEN`
- `IDS_EVENT_STORAGE`
- `IDS_EVENT_METRICS`
- `IDS_EVENT_RELOAD`
- `IDS_EVENT_HEALTH`

Events carry:

- monotonic `event_id`
- internal UUID string
- type
- priority
- event timestamp
- monotonic timestamp
- queue timestamp
- dispatch timestamp
- per-stage timestamp slot
- enqueue and dispatch latency metadata
- source metadata
- backpressure signal
- drop counter snapshot
- retry counter field reserved for retry-capable sinks
- owned packet/alert snapshots when applicable

## Dispatch Model

The bus supports synchronous delivery and an optional asynchronous dispatcher.
The application enables the asynchronous dispatcher at startup, backed by a
bounded `ids_event_queue_t`.

Important ownership rule: packet and alert payloads are copied into the event
object before async enqueue. Handlers receive stable event-owned snapshots, not
borrowed packet-pipeline pointers.

The async publish path is non-blocking. If the event queue is full, the event is
dropped and the bus increments its internal drop counter rather than stalling
packet parsing or detection workers. Events published while the async queue is
above 75% capacity carry `backpressure=true`. The queue pops higher priority
events first, which lets health/reload/alert events move ahead of low-priority
output or metrics events during pressure.

## Metrics

The bus exposes a snapshot with:

- events published
- events dispatched
- events dropped
- async event queue depth
- async event queue capacity

These counters are folded into runtime stats and the Prometheus-style metrics
endpoint.

## Subscribers

Subscribers register one handler per event type:

```c
ids_event_bus_subscribe(&bus, IDS_EVENT_ALERT, handler, user_data);
```

Current subscribers include:

- output registry
- SQLite storage backend
- future metrics/enrichment hooks

## Safety

- Subscriber lists are protected by a mutex.
- Handlers run outside the subscriber-list lock.
- Async shutdown closes the queue and drains pending events before storage and
  logger cleanup.
- Event queue capacity is bounded to avoid unbounded memory growth.
- Overload favors graceful degradation over unbounded memory or worker stalls.

---

# Correlation Engine

The correlation engine raises confidence when multiple alert types appear from the same source within a temporal window.

## Example Pattern

```text
PORT_SCAN or SLOW_SCAN
  +
SSH_BRUTE_FORCE / SENSITIVE_PORT / CONNECTION_EXCESS
  +
BEACONING
  =
THREAT_CORRELATION
```

## Scoring

Each source accumulates an attack score. When scan, access and beaconing signals occur within the configured correlation window, SpecterIDS emits a `THREAT_CORRELATION` alert with `CRITICAL` severity.

## Scope

This is a lightweight educational correlation model. It is intentionally deterministic and explainable.

---

# Plugin System

SpecterIDS has two module layers:

- internal module interfaces in `include/modules.h`
- optional dynamic detection plugins through `include/plugin_api.h`

Dynamic plugins are passive and defensive. They inspect `packet_info_t`
metadata and may emit `alert_t` records. They do not receive raw packet
payloads, packet injection APIs, credentials or control over the capture loop.

## Build Example Plugin

```bash
make plugins
```

This builds:

```text
plugins/libspecter_portscan.so
```

Load it explicitly:

```bash
./specterids --pcap samples/example.pcap --plugin plugins/libspecter_portscan.so
sudo ./specterids -i eth0 --plugin-dir plugins
```

Config:

```ini
plugins_enabled=true
plugin_dir=plugins
plugin=plugins/libspecter_portscan.so
```

## Dynamic Detection ABI

Plugins export `specterids_plugin_descriptor()` and return a
`specterids_plugin_descriptor_t`. The current ABI is version 2 and includes an
explicit lifecycle plus a small defensive capability model:

```c
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
```

The core validates ABI version, minimum core ABI, plugin name, declared
capabilities and required handlers before registration. Plugins are loaded with
`dlopen(..., RTLD_NOW | RTLD_LOCAL)`, started before activation, stopped during
engine shutdown and unloaded after their state has been released.

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

Parser modules expose `process()` around a packet header and byte buffer. The built-in parser handles Ethernet, Linux cooked capture, RAW IP, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 metadata.

## Enrichment Module

Reserved for future metadata enrichment such as asset labels or lab-owned IP tags.

## Design Rule

Modules must remain defensive and passive. They may inspect local metadata, emit events and write local outputs. They must not exploit, inject traffic, evade controls or collect secrets.

---

# Modules

SpecterIDS exposes internal module interfaces for parser, detection, output and
enrichment extensions, plus a stable dynamic detection plugin ABI in
`include/plugin_api.h`.

## Detection Module Shape

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

The production detection engine uses a built-in stage table for performance and
clear state ownership. Optional `.so` detection plugins can be loaded with
`--plugin` or `--plugin-dir`; they receive parsed metadata and an alert buffer.

## Output Module Shape

```c
init -> process/write -> flush -> cleanup
```

Current outputs are console, file logs, JSONL, SQLite, PCAP and metrics.

## Listing Modules

```bash
./specterids --list-modules
```

This prints parser, detection, output, dynamic plugin ABI and enrichment
extension points.

---

# Outputs

Outputs are organized behind an event-driven registry. Each output module has
the same lifecycle:

```c
init -> write/process -> flush -> cleanup
```

## Built-In Outputs

- console summaries and alerts
- packet/status text log
- alert text log
- alert JSONL log
- optional SQLite metadata storage
- suspicious PCAP context export
- localhost metrics endpoint

## Files

- `logs/specterids.log`
- `logs/alerts.log`
- `logs/alerts.jsonl`
- `captures/suspicious.pcap`
- `data/specterids.db` when SQLite is enabled

## Rotation

Text and JSONL logs support simple size-based rotation to `.1`. Compression is
intentionally left to external log rotation tooling for reliability.

## Design

The logger remains the packet-path writer for text/JSONL/PCAP outputs. The
output registry provides a stable module interface for future sinks without
coupling new outputs to capture or detection internals.

---

# Storage

SpecterIDS always writes text logs and can optionally export structured lab
sessions to SQLite.

## Build

The default build has no SQLite dependency:

```bash
make
```

Enable SQLite explicitly:

```bash
sudo apt install sqlite3 libsqlite3-dev
make sqlite
```

If `--sqlite` is used with a binary built without SQLite support, SpecterIDS
prints a warning and continues without database export.

## Usage

```bash
./specterids --pcap samples/example.pcap --sqlite data/lab.db
sudo ./specterids -i eth0 --sqlite data/live-lab.db
```

## Schema

- `sessions`: session start/end metadata and input mode.
- `packet_summary`: packet-level metadata only, not payload storage.
- `alerts`: alert type, severity, IPs, reason, risk score and correlation ID.
- `detections`: per-packet detection completion summary.
- `metrics`: final runtime counters, throughput, queue, plugin, IPv6, event-bus and storage snapshot.

The SQLite layer uses prepared statements, WAL mode, a short busy timeout and a
single retry for transient lock pressure. Database errors are counted as
storage failures and do not stop packet processing.

---

# Observability

SpecterIDS exposes runtime visibility through three surfaces:

- terminal dashboard
- text/JSONL logs
- local `/metrics` endpoint

## Runtime Counters

- captured packets
- parsed packets
- parse errors
- drops
- dropped alerts
- IPv4, IPv6 and ARP packet ratios
- malformed packet count
- alerts by severity
- alerts by type
- protocol counters
- top source IPs
- top destination ports
- queue depths
- queue drops
- shard pressure
- plugin packet and alert counters
- storage write and error counters

## Latency Metrics

SpecterIDS tracks average stage latency:

- parser latency
- detection latency
- logging latency

These values are visible in the dashboard and metrics endpoint.

## Health Signals

Operational health is inferred from:

- queue pressure
- queue drops
- parse error rate
- dropped alert rate
- IPv6/IPv4 mix
- shard imbalance
- storage degradation
- plugin activity
- memory usage
- CPU seconds
- alerts per minute

High queue pressure or drops means the operator should tune workers, queue size or BPF filters.

---

# Metrics

SpecterIDS can expose a local Prometheus-style endpoint.

## Enable

```bash
sudo ./specterids -i eth0 --metrics
sudo ./specterids -i eth0 --metrics 9090
./specterids --pcap samples/example.pcap --metrics --metrics-port 9090
```

Config:

```ini
metrics_enabled=true
metrics_port=9090
```

## Endpoint

The server binds to localhost only:

```text
http://127.0.0.1:9090/metrics
```

## Example Metrics

```text
parser_latency_us{proto="all"} 3.210
detection_latency_us{module="all"} 15.420
correlation_latency_us 1.100
queue_depth{name="raw"} 0
queue_depth{name="parsed"} 1
queue_depth{name="log"} 0
queue_depth{name="events"} 0
queue_drops_total{name="pipeline"} 2
queue_drops_total{name="events"} 0
packets_malformed_total{proto="all"} 4
packets_dropped_total 2
storage_write_latency_us 42.000
storage_errors_total 0
memory_pool_utilization 0.125000
memory_pool_failed_acquires_total 0
memory_pool_invalid_releases_total 0
plugin_latency_us{name="all"} 2.500
plugin_errors_total{name="all"} 0
uptime_seconds 12.500
heartbeat_total 2
throughput_pps 1234.000
shard_utilization{id="aggregate"} 1.125
packets_total 1000
packets_parsed_total 998
alerts_total 12
ipv4_packets_total 900
ipv6_packets_total 98
plugin_packets_total 1000
plugin_alerts_total 1
events_published_total 1200
events_dispatched_total 1198
```

## Security

The endpoint is read-only and local-only. It exposes defensive runtime counters,
not packet payloads, configuration mutation or remote control.

---

# Performance

SpecterIDS uses a bounded pipeline with object reuse.

## Performance Features

- capture callback does bounded copy into pooled objects
- parser and detection stages run on worker threads
- detection state is sharded by source-IP hash to reduce lock contention
- async event delivery decouples storage/output subscribers from detection workers
- logger is isolated from detection workers
- queue pressure and drops are visible in metrics
- parser/detection/logging average latencies and IP-family counters are tracked

## Benchmark

Run:

```bash
make benchmark
```

The benchmark writes `docs/benchmarks.md`.

## Tuning

- Increase `queue_size` for bursts.
- Increase `parser_workers` if parsing is hot.
- Increase `detection_workers` if detection latency dominates.
- Increase `detection_shards` when many sources are active and detection workers contend.
- Use BPF filters to reduce unnecessary traffic.
- Watch `queue_drops_total{name="pipeline"}`, `queue_depth{name=...}`,
  `memory_pool_utilization`, `plugin_latency_us{name="all"}` and
  `storage_write_latency_us` in `/metrics`.

---

# Benchmarking

Run the synthetic detection benchmark with:

```bash
make benchmark
```

Run an end-to-end offline replay benchmark with:

```bash
./specterids --pcap samples/example.pcap --benchmark
```

The benchmark processes deterministic synthetic packet metadata through the
detection engine and writes the report to `docs/benchmarks.md`.

Current metrics include:

- packets processed
- runtime seconds
- packets per second
- alerts generated
- average latency per packet

Offline replay benchmark output includes parsed packets, runtime, packets/sec,
Mbps, alerts, stage latency, queue drops, malformed packets and IPv6 ratio.

The benchmark is intentionally local and deterministic. It does not generate
network traffic and does not require privileges.

---

# SpecterIDS Benchmark

| Metric | Value |
| --- | ---: |
| Packets processed | 200000 |
| Runtime seconds | 0.930991 |
| Packets/sec | 214824.85 |
| Alerts generated | 304 |
| Average latency (microseconds/packet) | 4.655 |

---

# Hardening

## Compiler Flags

Release builds include:

```text
-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
-Wnull-dereference -Wdouble-promotion
-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
```

Debug builds include sanitizers:

```text
-Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
-Wnull-dereference -Wdouble-promotion
-g -O0 -fsanitize=address,undefined
-fstack-protector-strong -D_FORTIFY_SOURCE=2
```

## Runtime Limits

- bounded queues
- bounded pools
- bounded parser copies
- fixed detection windows
- defensive config range checks
- safe fallbacks for invalid rule lines
- local-only metrics endpoint
- SIGHUP reload keeps previous rules on failure
- non-blocking async event dispatch with bounded queue capacity
- offline PCAP replay validates datalink type before parsing
- dynamic plugins require ABI validation and `.so` suffix
- queue-pressure watchdog warns when bounded queues approach saturation

## Safe Failure Modes

When overloaded, SpecterIDS drops packets or async subscriber events and reports
counters instead of growing memory without limit. Parser failures are counted
and discarded. SQLite write failures are counted and treated as storage
degradation, not capture failure.

## Operational Recommendation

Prefer Linux capabilities over full root where possible:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./specterids
```

---

# Threat Model

SpecterIDS is a defensive educational IDS. Its purpose is to observe network metadata in an authorized environment and raise transparent alerts.

## In Scope

- Packet metadata capture from a local Linux interface.
- Parsing Ethernet, IPv4, TCP, UDP and ICMP headers.
- Rule-based anomaly detection for scans, floods, SSH attempts and simple beaconing.
- Local logs and terminal dashboard.

## Out of Scope

- Exploitation or vulnerability validation.
- Packet injection or traffic modification.
- Credential capture or payload extraction.
- Persistence, stealth, evasion or privilege escalation.
- Automated blocking or retaliation.

## Security Assumptions

- The operator has authorization to monitor the selected interface.
- Logs are stored on a trusted local filesystem.
- Detection results are advisory and require human interpretation.
- Root privileges may be needed for capture; users should prefer Linux capabilities where possible.

## Risks and Mitigations

- High packet rates can produce large logs. Mitigation: use BPF filters and log rotation outside the app.
- Heuristic rules can produce false positives. Mitigation: tune `rules/default.rules` for the lab.
- Running as root expands blast radius. Mitigation: use `setcap cap_net_raw,cap_net_admin=eip ./specterids` where appropriate.
- IPv6 traffic is not parsed in the current version. Mitigation: document parser scope and use BPF filters when needed.

---

# Offline PCAP Mode

SpecterIDS can read PCAP files without root and reuse the same parser,
detection, event, logging, dashboard, metrics and SQLite pipeline used for
live capture.

## Commands

```bash
./specterids --pcap samples/example.pcap
./specterids --pcap samples/example.pcap --json
./specterids --pcap samples/example.pcap --dashboard
./specterids --pcap samples/example.pcap --sqlite data/lab.db
./specterids --pcap samples/example.pcap --benchmark
```

By default, offline mode reads packets as fast as the bounded pipeline can
drain them. To preserve PCAP timing, enable replay mode:

```bash
./specterids --pcap samples/example.pcap --pcap-replay
./specterids --pcap samples/example.pcap --pcap-replay --pcap-speed 5x
./specterids --pcap samples/example.pcap --speed 10x
```

`--pcap-speed` accepts values from `0.1x` to `100x`. It only affects
`--pcap-replay`; normal offline mode still runs as fast as possible.

## Error Handling

- missing files fail cleanly before the pipeline starts
- invalid PCAP files return the libpcap error
- unsupported datalink types are rejected with a clear message
- malformed packets are counted as parser failures and do not crash workers

## Notes

Offline mode applies the configured BPF filter, if any, through libpcap. It is
best for deterministic regression, training labs and reviewing authorized
captures.

---

# Dashboard

The dashboard is an optional terminal view for live capture or offline replay.

## Usage

```bash
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
sudo ./specterids -i eth0 --dashboard-verbose
sudo ./specterids -i eth0 --dashboard --dashboard-interval 2
sudo ./specterids -i eth0 --dashboard --no-color
./specterids --pcap samples/example.pcap --dashboard
```

Modes:

- `compact`: one-screen operational summary.
- `detailed`: summary plus protocols, IP-family counters, top sources and top ports.
- `advanced`: detailed view plus shard, plugin, storage and event-bus health.

## Displayed Signals

- total captured and parsed packets
- drops and parser errors
- dropped alert bursts
- packets per second and Mbps
- queue depths and queue pressure
- average parse/detection/logging latency
- alerts by severity
- IPv4, IPv6, ARP and malformed counters
- top source IPs and destination ports
- top alert types
- shard pressure
- plugin packet and alert counters
- SQLite/storage writes and errors
- event-bus published, dispatched and dropped counters

## Operational Notes

`--quiet` suppresses live dashboard output and keeps only the final summary.
Dashboard output is terminal-only; logs are written through the logger and are
not mixed into dashboard state.

---

# Testing

## Unit Tests

```bash
make test
```

Coverage includes:

- valid and invalid rule parsing
- rule groups with IPv4 and IPv6 targets
- port scan, SSH brute force and SYN flood detections
- sharded IPv6 detection state
- parser fixtures for IPv4, IPv6, TCP, UDP, ICMP and ICMPv6
- safe behavior for truncated and unknown EtherType packets
- Linux cooked and RAW datalink parsing
- config parser range validation
- dynamic plugin ABI loading
- object-pool nonblocking acquire behavior

## Fixtures

Parser fixtures are text hex files in `tests/fixtures/`, so they are portable
and reviewable in Git.

Regenerate the sample PCAP and regression PCAP suite:

```bash
make fixtures
```

This creates:

- `samples/example.pcap`: a benign deterministic Ethernet/IPv4/TCP packet for quick offline runs.
- `tests/pcaps/portscan.pcap`
- `tests/pcaps/bruteforce.pcap`
- `tests/pcaps/synflood.pcap`
- `tests/pcaps/ipv6.pcap`
- `tests/pcaps/malformed.pcap`
- `tests/pcaps/beaconing.pcap`

The generated PCAPs are deterministic and do not depend on a real network interface.

```bash
./specterids --pcap samples/example.pcap
```

`make test` regenerates these fixtures before running parser and PCAP regression tests.

## Fuzz and Benchmark

```bash
make fuzz
make benchmark
make integration-test
make regression-test
```

`make regression-test` runs the unit suite and exercises offline PCAP replay
through the compiled `specterids` binary.

---

# Development

## Build Targets

```bash
make
make release
make debug
make test
make fuzz
make benchmark
make regression-test
make analyze
make format
make clean
```

Debug builds use:

```text
-g -O0 -fsanitize=address,undefined
```

Release builds use:

```text
-O2 -DNDEBUG
```

All builds use:

```text
-std=c11
-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2
-Wnull-dereference -Wdouble-promotion -Wstrict-prototypes -Wmissing-prototypes
-fstack-protector-strong -D_FORTIFY_SOURCE=2
```

## Tests

Tests are plain C programs in `tests/`.

- `test_rules.c`: rule parser defaults, valid parsing and invalid-line handling.
- `test_detection.c`: port scan, SSH brute force and SYN flood alerts.
- `test_parser.c`: TCP metadata extraction and truncated-packet safety.
- `test_queue.c`: queue producer/consumer behavior.
- `test_pool.c`: object-pool acquire and try-acquire behavior.
- `test_event.c`: synchronous/asynchronous event bus behavior.
- `test_correlation.c`: temporal alert correlation behavior.
- `test_config.c`: config parser ranges, booleans and safe defaults.
- `test_pcap_regression.c`: offline PCAP regression fixtures.
- `fuzz_parser.c`: deterministic parser fuzz smoke test.
- `benchmark.c`: synthetic detection throughput benchmark.
- `test_plugin_loading.c`: dynamic plugin ABI loading and counters.

Run:

```bash
make test
make fuzz
make benchmark
make regression-test
```

## Style

- File names use lower snake case, for example `metrics_server.c`.
- Public types use clear suffixes such as `_t`; internal helper structs stay `static` to the C file.
- Public functions use module prefixes: `parser_`, `detection_`, `logger_`, `ids_queue_`.
- Return `0` on success and negative values on recoverable errors.
- Validate pointers, lengths and enum ranges before use.
- Use `snprintf` and `ids_copy_string`; do not use unbounded string APIs.
- Keep packet parsing metadata-only and passive.
- Do not add exploitation, traffic injection, credential capture, evasion or persistence.
- Add tests for parser, config, rules, queue/pool or detection edge cases before changing behavior.

## Logging and Errors

- User-facing runtime failures should name the option, file or interface involved.
- Parser errors are short and safe to expose; they must not assume packet data is trusted.
- Output and storage failures should be non-fatal when possible.
- Config and rule invalid lines should warn and preserve safe defaults.

## Adding Built-In Modules

1. Keep module state bounded.
2. Add the module name to the detection/module registry.
3. Expose only the minimum required prototype in headers.
4. Add unit tests and update `docs/detection-rules.md` or `docs/modules.md`.
5. Document false-positive expectations for defensive detections.

## Dependency Notes

Production builds require `libpcap-dev` or the equivalent distribution package. Unit tests for parser/rules/detection do not require libpcap because `parser.h` is intentionally independent from pcap types.

---

# Contributing

SpecterIDS accepts defensive, educational improvements.

## Before Opening a PR

```bash
make
make test
make fuzz
make analyze
```

## Rules

- Do not add offensive behavior.
- Do not add exploitation, persistence, evasion or credential capture.
- Keep parser changes bounds-checked.
- Keep queues and pools bounded.
- Add tests for new detection rules.
- Document operational limitations.

## Good First Areas

- More parser fixtures.
- IPv6 metadata parsing.
- Sharded detection state.
- Offline PCAP replay.
- Better benchmark scenarios.

---

# Troubleshooting

## Permission Denied

Live capture requires root or packet-capture capabilities.

```bash
sudo ./specterids -i eth0
```

or:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./specterids
```

## No Packets

Check the interface name:

```bash
ip link
```

Check your BPF filter. `bpf_filter=ip` excludes ARP and IPv6; use `ip or ip6 or arp` for the default broad defensive view.

## High Drops

Increase `queue_size`, reduce `dashboard_refresh_ms`, use a narrower `--bpf` filter, or lower packet logging volume.

## Large Logs

Use `rotation_size_mb` and external log rotation/compression for long sessions.

## Unsupported Datalink

Supported datalinks are Ethernet (`DLT_EN10MB`), Linux cooked capture (`DLT_LINUX_SLL`/`DLT_LINUX_SLL2`) and raw IP (`DLT_RAW`). Unsupported PCAPs fail before parsing with a clear error.

---

# Limitations

SpecterIDS remains an educational defensive IDS. Current limits are explicit:

- IPv6 extension header support is intentionally conservative and metadata-only.
- Rule group targets are exact IP matches, not CIDR ranges.
- Beaconing detection is improved but still heuristic and may require tuning.
- SQLite stores metadata summaries, not full packet payloads.
- Dynamic plugin ABI v2 is intentionally small and detection-only.
- Plugin processing is serialized by the core for safety; very expensive
  plugins can reduce throughput.
- Suspicious PCAP export writes packets in the current simple PCAP path and is
  best suited for Ethernet lab captures.
- The parser does not validate checksums.
- Detection logic is transparent and lightweight rather than ML-based.

Recommended next steps are CIDR matching for rule groups, richer IPv6 extension
coverage, optional checksum validation, plugin sandboxing beyond ABI checks and
more PCAP regression fixtures from authorized lab traffic.

---

# Roadmap

SpecterIDS is intentionally defensive, transparent and educational. The next
steps should improve reliability and analysis depth without adding offensive
capabilities.

## Near Term

- CIDR matching for rule-group targets.
- Metrics tests that exercise the localhost HTTP endpoint in CI.
- SQLite schema migration/version table.
- Per-shard metrics export instead of aggregate shard pressure only.
- Larger authorized-lab PCAP regression corpus.

## Medium Term

- Optional checksum validation for IPv4, TCP, UDP and ICMP.
- Rule diagnostics report at startup with enabled detections and overrides.
- Plugin capability declarations enforced by the loader.
- Storage batching for long offline replays.
- Dashboard trend sparklines for throughput and alerts.

## Long Term

- Optional plugin sandboxing beyond ABI validation.
- Asset labels for owned lab networks.
- More protocol metadata parsers for defensive observability.
- Release packaging for common Linux distributions.

## Non-Goals

- Exploitation.
- Packet injection.
- Credential collection.
- Evasion.
- Persistence.
- C2 or automation of offensive activity.

---

# Detections

SpecterIDS uses transparent defensive heuristics.

## Network Behavior

- `PORT_SCAN`: many distinct destination ports in a short window.
- `SLOW_SCAN`: distinct ports over a longer window.
- `SSH_BRUTE_FORCE`: repeated TCP SYN packets to SSH or configured SSH port.
- `SYN_FLOOD`: many SYN packets without ACK.
- `ICMP_FLOOD`: many ICMP packets.
- `UDP_FLOOD`: many UDP packets.
- `DNS_FLOOD`: many DNS packets over UDP/TCP port 53 metadata.
- `BEACONING`: repeated contact with the same destination at regular intervals.

## Defensive Heuristics

- `ARP_SPOOFING`: same ARP sender IP observed with a different MAC.
- `SENSITIVE_PORT`: access to configured sensitive TCP ports.
- `CONNECTION_EXCESS`: excessive TCP connection attempts.
- `LARGE_PAYLOAD`: unusually large payload metadata.
- `VOLUME_ANOMALY`: high byte volume from one source in a time window.
- `HEURISTIC_RISK`: temporary risk score crossing a threshold.

## Risk Score

Each source IP accumulates score when alerts fire. Scores decay over time. Severity can be raised dynamically when the score is high.

This is an educational signal, not proof of malicious activity.

---

# Engineering Contracts

This document records the runtime contracts SpecterIDS relies on. Code changes
that alter these guarantees should update this file in the same change.

## Global Safety Contract

SpecterIDS is a defensive network monitoring program. It reads packets from an
authorized interface or PCAP, derives metadata, emits alerts and writes local
observability data. It never exploits targets, modifies traffic, persists on
hosts, evades controls, exfiltrates data or performs offensive actions.

All hot-path growth is bounded by configuration or compile-time constants.
Under overload the system drops packets/events and increments counters instead
of allocating unbounded memory.

## Module Contracts

### `src/main.c`

- Responsibilities: parse CLI, load config/rules, initialize modules, install
  signals and run ordered shutdown.
- Inputs: CLI args, optional config, optional rules file.
- Outputs: initialized runtime graph and final process exit status.
- Invariants: CLI overrides config; `--benchmark` requires `--pcap`; live mode
  requires an interface.
- Failure modes: invalid config exits early; optional SQLite/plugins degrade
  with warnings where safe.

### `src/capture/`

- Responsibilities: own `pcap_t`, apply BPF, copy packet bytes into raw pools,
  drive live/offline replay and coordinate pipeline threads.
- Inputs: `capture_options_t`, `detection_engine_t`, logger, dashboard, stats.
- Outputs: raw packets, parsed packets, log events, typed events and metrics.
- Invariants: capture callback never allocates unbounded memory; copied packet
  data is capped by `SPECTERIDS_MAX_PACKET_BYTES`; replay timing is derived from
  PCAP timestamps and speed multiplier.
- Failure modes: unsupported datalink, BPF failure or PCAP open failure stop the
  capture run with an explicit error.

### `src/datalink/`

- Responsibilities: normalize Ethernet, VLAN, Linux cooked, Linux cooked v2 and
  RAW IP frames into network payload plus EtherType.
- Inputs: datalink type, captured bytes and length.
- Outputs: `datalink_frame_t`.
- Invariants: every header read is guarded by captured-length checks.
- Failure modes: truncated or unsupported datalink returns error text and no
  network payload.

### `src/parser/`

- Responsibilities: parse ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 metadata.
- Inputs: packet header and captured bytes.
- Outputs: normalized `packet_info_t`.
- Invariants: offsets are validated before reads; IPv6 extension chains are
  bounded; fragments are marked instead of blindly parsing missing transport
  headers.
- Failure modes: malformed packets return `false`, set diagnostics when
  possible and are counted as parser errors by the pipeline.

### `src/queues/`

- Responsibilities: bounded multi-producer/multi-consumer queue.
- Inputs: opaque item pointers.
- Outputs: FIFO item delivery with optional timeout operations.
- Invariants: capacity never grows; push timeout increments drop counters;
  close wakes all waiters.
- Failure modes: full queue returns `false` for try/timeout push; closed queue
  stops producers and consumers.

### `src/memory/`

- Responsibilities: fixed-size object pools for hot-path packet objects.
- Inputs: capacity and element size.
- Outputs: zeroed owned objects and tracked releases.
- Invariants: every acquired item is marked in-use; release validates pointer
  ownership; double release is counted and ignored instead of blocking.
- Failure modes: pool exhaustion returns `NULL` and increments failed acquire
  counters; invalid release increments invalid release counters.

### `src/events/`

- Responsibilities: typed event dispatch, optional async queue, priority and
  telemetry.
- Inputs: `ids_event_t` publications.
- Outputs: subscriber callbacks and event-bus snapshots.
- Invariants: async events own packet/alert/message snapshots; each published
  event receives an internal UUID, monotonic timestamp, stage timestamp and
  source metadata; async publish is non-blocking.
- Failure modes: full async event queue drops the event and increments event
  drop counters.

### `src/detection/`

- Responsibilities: sharded source state, rule-driven detectors and dynamic
  defensive plugins.
- Inputs: normalized packet metadata.
- Outputs: bounded alert arrays.
- Invariants: state is keyed by source IP; each shard has a lock; per-source
  rolling windows are fixed-size; plugin ABI/capabilities are validated before
  activation.
- Failure modes: shard source exhaustion skips new actors; plugin overproduction
  is clamped to caller capacity and counted as plugin error.

### `src/correlation/`

- Responsibilities: correlate alerts by source actor over a temporal window.
- Inputs: alert arrays from detection.
- Outputs: additional correlation alerts.
- Invariants: actor table is bounded; attack score decays over time; correlation
  alerts require scan, brute-force/sensitive-access and beaconing context inside
  the configured window.
- Failure modes: actor allocation or actor-table exhaustion skips correlation
  for that source without affecting packet processing.

### `src/rules/`

- Responsibilities: parse tolerant rule files and select default/group rules.
- Inputs: `rules/default.rules` style files.
- Outputs: `ids_rules_t` and selected `ids_rule_set_t`.
- Invariants: invalid lines are non-fatal; built-in defaults remain available;
  group targets are literal IPv4/IPv6 addresses.
- Failure modes: unreadable file returns error so caller can keep defaults.

### `src/plugins/` and `include/plugin_api.h`

- Responsibilities: define plugin ABI v2 and list built-in module surfaces.
- Inputs: defensive `.so` paths.
- Outputs: packet/alert callbacks under validated capabilities.
- Invariants: ABI version and `min_core_abi` are checked; unknown capabilities
  are rejected; lifecycle order is `init -> start -> packet/alert -> stop ->
  unload`.
- Failure modes: load/start failures unload state and close the dynamic handle.

### `src/outputs/`, `src/storage/`, `src/utils/logger.c`

- Responsibilities: write local text, JSONL, PCAP context and optional SQLite.
- Inputs: packet and alert events.
- Outputs: local files and SQLite rows.
- Invariants: logger owns file handles; logger writes are mutex-serialized;
  SQLite writes are serialized by the storage mutex and measured.
- Failure modes: write failures are counted where visible; optional SQLite can
  be disabled or unavailable without disabling detection.

### `src/metrics/` and `src/dashboard/`

- Responsibilities: expose local runtime metrics and terminal summaries.
- Inputs: `ids_stats_t` snapshots.
- Outputs: localhost `/metrics` response and terminal dashboard.
- Invariants: metrics endpoint binds loopback only; dashboard uses snapshots and
  does not mutate detection state.
- Failure modes: metrics socket startup failure aborts only when explicitly
  requested; disabled metrics are a no-op.

## Replay Determinism

Offline parsing uses packet bytes and timestamps from the PCAP. Normal offline
mode drains as fast as the pipeline allows; replay mode computes sleeps from
the first PCAP timestamp and `pcap_speed`. For a fixed binary, rules file,
config and plugin set, a fixed PCAP produces the same parsed packet sequence and
detector state transitions. Wall-clock metrics such as runtime and PPS are not
part of the deterministic alert contract.

## Backpressure Contract

Capture uses non-blocking raw enqueue. Parser and detection stages use bounded
pool acquisition and bounded queue push timeouts. When downstream stages cannot
keep up, packets/events are shed, counters increase and the watchdog emits
periodic health events. The process does not grow queues or allocate emergency
buffers to hide overload.

---

## Failure Analysis

This section documents failure modes, overload scenarios, and their mitigations.

### Failure Scenarios

**F-1: Metrics server client disconnects mid-response (FIXED)**
A Prometheus scraper or curl that closes the TCP connection while SpecterIDS is writing the response body generates SIGPIPE. Without handling, SIGPIPE's default action terminates the process. Fixed: `MSG_NOSIGNAL` passed to `send()` in `write_all`; `SIGPIPE` set to `SIG_IGN` in `install_signal_handlers`.

**F-2: NTP forward jump causes pipeline packet drops (FIXED)**
`pthread_cond_timedwait` requires an absolute deadline based on a system clock. When `CLOCK_REALTIME` is used (the previous default), an NTP step-forward of any magnitude makes all in-flight deadlines expire immediately. Every pending `ids_queue_push_timeout` call returns `ETIMEDOUT` within the same millisecond, causing the pipeline to drop all packets for the duration of the normal 250ms timeout window. Fixed: all queue condvars switched to `CLOCK_MONOTONIC` via `pthread_condattr_setclock`.

**F-3: Non-deterministic offline replay with multiple workers (FIXED)**
Two parser workers compete for `raw_queue` items; processing order depends on thread scheduling. Same PCAP replayed twice produces different alert sequences. `--benchmark` now forces `parser_workers=1, detection_workers=1`. Non-benchmark offline mode emits a warning when workers > 1.

**F-4: Event bus lock contention on hot path (FIXED)**
Seven or more `ids_event_bus_publish` calls per packet, even for event types with zero subscribers (`PACKET_CAPTURED`, `DATALINK_PARSED`, `NETWORK_PACKET_PARSED`, `CORRELATION`, `HEALTH`, `RELOAD`), each acquired the bus mutex to increment `next_event_id`. At 100K PPS this was ~700K lock acquisitions/sec for no work done. Fixed: a `_Atomic uint32_t subscriber_bitmask` allows a lock-free skip in `ids_event_bus_publish` for event types with no subscribers.

**F-5: Plugin SIGSEGV kills the process**
Plugin `packet_handler` and `alert_handler` run in the detection worker thread. A NULL dereference or stack overflow inside a plugin crashes the entire process. There is no sandbox. Mitigation: ABI version check at load time, `RTLD_NOW` to surface linker errors immediately, plugin error counter. Full isolation would require fork/exec per plugin invocation. **Unresolved risk — by design for this single-process architecture.**

**F-6: Correlation engine global lock under alert storm**
`correlation_process_alerts` holds `engine->lock` for the entire per-packet loop. Under multiple detection workers and sustained alert rates > 10K/sec, this mutex becomes the bottleneck. **Unresolved — sharding the correlation engine would eliminate the contention.**

**F-7: `source_state_t` LRU eviction is O(4096) under IP spray**
When an adversary maintains exactly `MAX_TRACKED_SOURCES` active IPs per shard, every new IP from that shard triggers an O(`SOURCE_BUCKETS`) = O(4096) scan to find the LRU entry. A doubly-linked LRU list would reduce this to O(1). **Unresolved — the current workaround is the memory reduction (44KB per state, down from 128KB).**

**F-8: `make_deadline` clock_gettime failure returns zero deadline**
If `clock_gettime(CLOCK_MONOTONIC, ...)` fails (unexpected on Linux, possible on constrained embedded targets), `make_deadline` returns a zero deadline. `pthread_cond_timedwait` with a zero-second deadline expires immediately, causing the push/pop to fail instantly rather than waiting. This produces a flood of ETIMEDOUT returns and all queued packets are dropped silently. Mitigation: the `queue->dropped` counter tracks these drops; the watchdog would fire within 5 seconds.

### Overload Scenarios

**O-1: Packet burst exceeds raw_pool capacity**
`ids_pool_try_acquire` in the pcap callback returns NULL; packet is silently dropped. `ids_stats_record_drop` is called. The pool-failed-acquires counter is exported to metrics. This is bounded and intentional.

**O-2: Slow detection workers back-pressure through parsed_queue**
`ids_queue_push_timeout(..., 250ms)` in the parser worker drops the parsed packet after 250ms. If detection consistently takes > 250ms (e.g., heavy plugin), this timeout fires continuously. Mitigation: the queue-drops metric exposes this; the watchdog fires at 90% fill.

**O-3: SQLite write latency spikes**
SQLite handler runs in the event bus worker thread. A slow write (disk I/O, WAL checkpoint) blocks event dispatch for its duration. Configured `sqlite3_busy_timeout = 250ms`. Failure mode: event queue fills and events are dropped (counted). Pipeline is unaffected.

**O-4: Plugin hung in packet_handler**
A plugin that blocks indefinitely in `packet_handler` blocks the detection worker thread. This fills `parsed_queue` until `ids_queue_push_timeout` starts dropping. All detection workers are eventually starved of work if multiple shards route to the same detection worker. **Unresolved — no per-plugin timeout exists.**

### Degraded-Mode Behavior

| Condition | Behavior | Observable Signal |
|---|---|---|
| Pool exhausted | Drop packet, continue | `pool_failed_acquires_total` |
| Queue full | Drop packet/event, continue | `queue_drops_total` |
| SQLite unavailable | Log to text/JSON only | startup warning |
| Plugin load failure | Warn, continue without plugin | stderr warning |
| Metrics bind failure | Abort if enabled, skip if disabled | startup error |
| Rules file unreadable | Use built-in defaults | stderr warning |
| Config file missing | Use built-in defaults | silent |
| Capture open failure | Exit | stderr error |

### Shutdown Semantics

Shutdown is initiated by `SIGTERM` or `SIGINT` setting `g_stop_requested = 1`. The capture thread exits on the next pcap dispatch iteration (up to 1 second), then closes `raw_queue`. This propagates through the pipeline as each queue closes when its upstream producer exits. All stages drain their queues before exiting. The shutdown sequence is deterministic and has no known stall paths, provided plugins do not block indefinitely.

