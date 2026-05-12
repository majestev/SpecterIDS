# Architecture

SpecterIDS is organized as small C modules with clear ownership. The program captures packets, moves them through a bounded threaded pipeline, converts them to safe metadata, applies rule-driven detection and emits logs/dashboard/forensic data.

## Runtime Flow

```text
main.c
  |
  +-- config.c          loads optional key=value runtime configuration
  +-- rules.c           loads detection thresholds and severities
  +-- logger.c          opens text/JSONL logs
  +-- dashboard.c       tracks runtime counters
  |
  v
capture.c -> queue.c/pool.c -> parser.c -> detection.c -> correlation.c -> logger.c
                                      \-> stats.c -> dashboard.c/metrics_server.c
                                      \-> event.c -> modules/outputs
```

## Modules

- `main.c`: CLI parsing, config precedence, signal handling and lifecycle cleanup.
- `config.c`: safe `key=value` parser for `config/specterids.conf`.
- `capture.c`: `libpcap` live capture, BPF setup and dispatch loop.
- `queue.c`: bounded multi-producer/multi-consumer queues.
- `pool.c`: reusable object pools for packet-path allocations.
- `stats.c`: telemetry counters and snapshots.
- `event.c`: internal event dispatcher for decoupled subscribers.
- `modules.c`: built-in module interface registry.
- `correlation.c`: temporal correlation over alert streams.
- `metrics_server.c`: localhost read-only metrics endpoint.
- `storage.c`: directory/storage abstraction.
- `parser.c`: bounds-checked parser for Ethernet, VLAN, IPv4, TCP, UDP and ICMP.
- `rules.c`: tolerant rule parser with defaults and warnings.
- `detection.c`: per-source state machines for scan/flood/beacon heuristics.
- `logger.c`: text logs and optional JSONL alert output.
- `dashboard.c`: terminal counters, top source IPs and recent alerts.

## Safety Boundaries

The parser validates captured length before reading every header field. Truncated packets are either rejected or returned with `truncated=true` when enough metadata is available. Detection only uses metadata and never sends packets.

## State Model

Detection state is keyed by source IP. Each source has bounded event windows:

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
