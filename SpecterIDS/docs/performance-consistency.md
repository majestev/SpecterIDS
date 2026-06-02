# SpecterIDS Performance Consistency

Version 3.0.0 | Updated 2026-05-29

---

## Philosophy

SpecterIDS targets **sustained throughput and predictable latency** — not peak
benchmark numbers. A system that processes 200K PPS for one second and then
stalls for five is less useful than one that sustains 80K PPS indefinitely.

Every optimization in this document was applied after measurement, not before.

---

## Baseline (single-core replay, `make benchmark`)

Measured on: Linux x86_64, `make release`, `--pcap tests/pcaps/portscan.pcap`

| Metric | Value |
|---|---|
| PPS | ~1,200–1,700 PPS (PCAP limited) |
| Avg parse latency | 3–8 µs |
| Avg detection latency | 15–50 µs |
| Avg correlation latency | < 1 µs |
| Avg logging latency | 20–80 µs |
| Queue drops | 0 |
| Memory | ~15 MB RSS |

*Note:* The test PCAP is 3 packets. Meaningful throughput benchmarks require larger PCAPs with diverse traffic.

---

## Hot-Path Analysis

The critical path per packet:

```
pcap_dispatch                    (~2 µs per packet at 100K PPS)
  → capture callback             (pool acquire + memcpy, ~1 µs)
  → raw_queue push               (mutex + signal, ~0.5 µs)
  → parser worker                (protocol decode, ~3–8 µs)
  → parsed_queue push            (mutex + signal, ~0.5 µs)
  → detection worker             (rule evaluation, ~15–50 µs)
  → log_queue push               (mutex + signal, ~0.5 µs)
  → logger thread                (fprintf/write, ~20–80 µs)
```

**Bottleneck under moderate load:** Detection (rule evaluation, source state lookup).  
**Bottleneck under high PPS:** Queue mutex contention when workers can't keep up.

---

## Optimizations Applied (v3.0.0)

### 1. `source_state_t` size reduction (65% smaller)

| Before | After |
|---|---|
| 128 KB per source | 44 KB per source |

**Why this matters for performance:** Smaller structs fit better in CPU L1/L2 cache. A detection worker processing 16-shard × 2048 source states was touching up to 4 GB of working set. Reducing to 1.4 GB max keeps working data in L3 cache under normal loads.

**Measured impact:** Detection latency variance reduced ~20% under sustained port scan traffic in lab tests.

---

### 2. Event bus subscriber bitmask fast-path

`ids_event_bus_publish` previously acquired `bus->lock` for every event type, even types with no subscribers. At 100K PPS with 7 publishes/packet:

| Before | After |
|---|---|
| ~700K lock acquisitions/sec for zero-subscriber events | ~1 atomic load per event (lock-free) |

**Measured impact:** `detection_latency_us` reduced ~5 µs at 50K PPS in lab tests.

---

### 3. `ids_event_queue_pop` O(n²) → O(n) bubble-shift removal

`ids_event_t` is 1,232 bytes. The priority-pop previously copied up to n × 1,232 bytes inside the mutex (bubble-shift). Replaced with O(1) swap.

**Measured impact:** Event bus worker latency reduced from ~500 µs at full queue to ~50 µs under sustained alert storm.

---

### 4. `CLOCK_MONOTONIC` for all queue condvars

Prevents spurious ETIMEDOUT storms after NTP adjustment. Eliminates the drop-spike scenario (F-2 in failure-analysis.md).

---

### 5. FNV-1a canonical seed (hash consistency)

Using the canonical FNV-1a offset basis in both `detection.c` and `correlation.c` ensures hash distribution is predictable and consistent with reference implementations.

---

## Queue Sizing Guide

The default `queue_size = 1024` is appropriate for:
- Live capture at ≤ 50K PPS with 2 workers each
- Offline replay of any size with 1 worker each

For higher sustained PPS:

| Target PPS | Recommended queue_size | Estimated RSS impact |
|---|---|---|
| ≤ 50K | 1024 (default) | +0 MB |
| 50K–100K | 2048 | +~26 MB (pool growth) |
| 100K–200K | 4096 | +~52 MB |

Set `queue_size` in `config/specterids.conf`. The same value controls all three pipeline queues and their backing pools.

---

## Shard Sizing Guide

Default `detection_shards = 16`. Shards reduce lock contention by routing each source IP to one shard (hash-partitioned). Two detection workers never hold the same shard lock simultaneously.

| Active unique IPs | Recommended shards |
|---|---|
| < 500 | 4–8 (reduce overhead) |
| 500–5000 | 16 (default) |
| 5000–50000 | 64 |
| > 50000 | 128–256 |

More shards = less contention but more fixed memory. Each shard has a ~600 KB fixed cost (ARP table). 256 shards = ~150 MB fixed cost.

---

## Performance Consistency Constraints

### Replay throughput ceiling

Offline replay is bounded by the parsing + detection pipeline. For the release build with 1 worker each, typical throughput is 100K–500K PPS for small PCAPs. Large PCAPs with mixed traffic typically achieve 50K–200K PPS.

### Logging throughput ceiling

`logger_log_packet_raw` calls `fprintf` which is buffered but ultimately bounded by disk I/O. Typical ceiling: ~100K log lines/sec. Above this, `log_queue` fills and packets are dropped.

To reduce logging overhead: use `--quiet` to suppress verbose packet output. Use JSON logs only for alerts (`--json` without `--verbose`).

### SQLite throughput ceiling

With WAL mode and `busy_timeout = 250ms`, SQLite can sustain ~10K–50K writes/sec depending on disk. For packet-rate logging, SQLite is the primary bottleneck. Consider selective logging (alerts only) rather than all-packets mode.

---

## Profiling Guide

To find bottlenecks in a specific deployment:

```bash
# Sustained throughput test
./specterids --pcap large_capture.pcap --quiet --benchmark

# Queue pressure check (metrics endpoint while running)
./specterids -i eth0 --metrics 9090 &
while true; do curl -s localhost:9090/metrics | grep -E 'queue_depth|drops'; sleep 1; done

# Shard balance check
curl -s localhost:9090/metrics | grep shard_utilization

# Detection state memory
curl -s localhost:9090/metrics | grep detection_source_memory_bytes

# LRU eviction rate (indicates IP spray or too few shards)
curl -s localhost:9090/metrics | grep detection_lru_evictions_total
```
