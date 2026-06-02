# SpecterIDS Runtime Memory Behavior

Version 3.0.0 | Updated 2026-05-29

---

## Overview

SpecterIDS uses a combination of pre-allocated pools (for the pipeline), heap allocation (for detection source states), and embedded static arrays (for ARP bindings). All allocation paths are bounded and have defined maximum sizes.

---

## Pre-allocated Memory Pools

Three object pools are created at pipeline startup with capacity = `queue_size` (default 1024):

| Pool | Object Size | Capacity | Max RSS |
|---|---|---|---|
| `raw_pool` | `raw_packet_t` (≈4168 bytes) | 1024 | ~4.2 MB |
| `parsed_pool` | `parsed_packet_t` (≈4472 bytes) | 1024 | ~4.6 MB |
| `log_pool` | `log_event_t` (≈22 KB) | 1024 | ~22 MB |

**Growth:** None. All three pools are allocated once at pipeline init and freed at shutdown.  
**Exhaustion behavior:** `ids_pool_try_acquire` returns NULL; the packet or event is dropped. `pool_failed_acquires_total` is incremented.  
**Observable:** `memory_pool_utilization`, `memory_pool_failed_acquires_total` in Prometheus.

---

## Detection Source States

Source IP state is heap-allocated on first packet from that IP, up to `MAX_TRACKED_SOURCES = 2048` per shard.

| Metric | Value |
|---|---|
| `sizeof(source_state_t)` | **44,376 bytes (43.3 KB)** |
| Max sources per shard | 2048 |
| Default shards | 16 |
| Max RSS (all shards full) | 2048 × 16 × 44 KB = **1.4 GB** |
| Typical (100 active IPs/shard) | 100 × 16 × 44 KB = **70 MB** |

**Growth:** Linear in unique source IPs, capped at `MAX_TRACKED_SOURCES × shard_count`.  
**LRU eviction:** When a shard is full, the least-recently-used source is evicted and its allocation reused. Eviction cost: O(SOURCE_BUCKETS = 4096) scan.  
**Observable:** `detection_source_memory_bytes` gauge, `detection_lru_evictions_total` counter in Prometheus.

### Historical comparison

| Version | `sizeof(source_state_t)` | Max RSS |
|---|---|---|
| Pre-OMEGA | 128,300 bytes (128 KB) | 4.0 GB |
| v3.0.0 | 44,376 bytes (44 KB) | 1.4 GB |

Reduction: 65% smaller per state.

---

## ARP Binding Table

Each detection shard contains a static open-addressing hash table:

| Field | Value |
|---|---|
| `arp_table[ARP_HASH_SIZE]` | 8192 slots × `sizeof(arp_binding_t)` |
| `sizeof(arp_binding_t)` | ≈72 bytes (ip[46] + mac[18] + time_t + bool + padding) |
| Per-shard size | 8192 × 72 = 590 KB |
| All 16 shards | 16 × 590 KB = **9.4 MB** |
| Max occupancy | 4096 entries (50% load factor) |

**Growth:** None. Array is embedded in `detection_shard_t`, allocated once at engine creation.  
**Eviction:** None. ARP table uses a 50% load factor hard cap. Above 4096 entries per shard, new ARP bindings are dropped (not tracked).

---

## Detection Engine Overhead

| Component | Size |
|---|---|
| `detection_engine_t` struct | ~1 KB |
| `detection_shard_t` array (16 shards) | 16 × (590 KB ARP + 8 KB buckets + overhead) ≈ 9.6 MB |
| Plugin slots `dynamic_plugin_t[32]` | ~200 KB |
| **Total engine fixed cost** | **~10 MB** |

---

## Correlation Engine

| Metric | Value |
|---|---|
| `sizeof(correlation_source_t)` | ~300 bytes |
| Max sources | 4096 |
| Max RSS | 4096 × 300 = **1.2 MB** |

**Growth:** Linear, capped. When `source_count >= max_sources`, new source IPs are silently ignored.  
**Cleanup:** All nodes freed in `correlation_destroy`.

---

## Event Queue

| Metric | Value |
|---|---|
| `sizeof(ids_event_t)` | **1232 bytes** |
| Queue capacity | `config.queue_size` (default 1024) |
| Max RSS | 1024 × 1232 = **1.2 MB** |

**Growth:** Fixed. `ids_event_queue_init` allocates the array once.

---

## Pipeline Queues

| Queue | Item | Capacity | Max RSS |
|---|---|---|---|
| `raw_queue` | `void *` (pointer) | 1024 | 8 KB |
| `parsed_queue` | `void *` | 1024 | 8 KB |
| `log_queue` | `void *` | 1024 | 8 KB |

These queues hold pointers only; actual data lives in the pools above.

---

## SQLite Buffering

With `PRAGMA journal_mode=WAL`, SQLite maintains:
- A WAL file (unbounded during write burst, checkpointed periodically)
- A shared memory segment for WAL index

In practice, SQLite memory usage under SpecterIDS is ≤ 10 MB under normal workloads. No explicit limit is configured. Under sustained high write rates, WAL growth is possible. Observable: filesystem monitoring.

---

## Orphan Allocation Audit

At shutdown, all pools are destroyed via `ids_pool_destroy` (frees backing storage array regardless of in-use state). All detection source states are freed in `detection_destroy`. All correlation source states are freed in `correlation_destroy`. No orphan allocations on normal shutdown.

**Exception:** If the process receives SIGKILL or a plugin causes SIGSEGV, OS reclaims all process memory. No persistent leak.

---

## Memory Pressure Signals

| Metric | Interpretation |
|---|---|
| `memory_pool_failed_acquires_total > 0` | Packet drops due to pool exhaustion |
| `memory_pool_utilization > 0.9` | Pools near capacity; reduce PPS or increase `queue_size` |
| `detection_source_memory_bytes` large | Many active source IPs; check for scanning |
| `detection_lru_evictions_total` rising | Shard full; LRU evictions active (possibly adversarial IP spray) |
