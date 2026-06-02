# SpecterIDS Failure Analysis

Version 3.0.0 | Updated 2026-05-29

This document enumerates failure modes, overload scenarios, degraded-mode behavior, and unresolved risks for the SpecterIDS production runtime.

---

## Fixed Failure Modes

### F-1 — SIGPIPE kills process when Prometheus client disconnects

**Subsystem:** metrics_server.c  
**Trigger:** Prometheus scraper closes TCP connection mid-response.  
**Impact:** Process termination. All monitoring data lost.  
**Fix:** `MSG_NOSIGNAL` in `write_all`; `SIGPIPE → SIG_IGN` in `install_signal_handlers`.  
**Verification:** `curl http://localhost:9090/metrics &` then `kill %1` does not crash SpecterIDS.

---

### F-2 — NTP forward jump causes pipeline-wide packet drops

**Subsystem:** queue.c  
**Trigger:** System clock steps forward (NTP, manual adjustment, leap second).  
**Impact:** All in-flight `pthread_cond_timedwait` deadlines expire simultaneously. Every pending `ids_queue_push_timeout` and `ids_pool_acquire_timeout` call returns `ETIMEDOUT` immediately. Packet drop counter spikes; IDS blind for ~250ms.  
**Fix:** All queue condvars use `CLOCK_MONOTONIC` via `pthread_condattr_setclock`. Monotonic time is unaffected by system clock adjustments.  
**Verification:** `chronyc makestep` while replaying a PCAP — no drop spike.

---

### F-3 — Non-deterministic offline replay output

**Subsystem:** capture.c, main.c  
**Trigger:** Two or more parser or detection workers compete for queue items.  
**Impact:** Alert sequences and metric values differ across identical PCAP replays. Regression tests and benchmark comparisons are unreliable.  
**Fix:** `--benchmark` forces `parser_workers=1, detection_workers=1`. Non-benchmark offline mode emits a warning if workers > 1.  
**Verification:** `tests/test_determinism.sh` passes 8/8 checks across 3 runs.

---

### F-4 — Event bus hot-path mutex contention at high PPS

**Subsystem:** event.c  
**Trigger:** Sustained packet rate > 50K PPS with multiple parser and detection workers.  
**Impact:** Up to 7 mutex acquisitions per packet for event types with zero subscribers (`PACKET_CAPTURED`, `DATALINK_PARSED`, `NETWORK_PACKET_PARSED`, `HEALTH`, `RELOAD`, `CORRELATION`). At 100K PPS: ~600K unnecessary lock ops/sec.  
**Fix:** `_Atomic uint32_t subscriber_bitmask` in `ids_event_bus_t`. `ids_event_bus_publish` skips all processing with a single `atomic_load_explicit` for unsubscribed event types.  
**Verification:** Profiling shows event bus mutex contention eliminated for unsubscribed types.

---

## Active Failure Modes

### F-5 — Plugin code runs in process address space without sandboxing

**Subsystem:** detection.c, plugin loading  
**Trigger:** Plugin contains a NULL dereference, stack overflow, or division by zero.  
**Impact:** SIGSEGV or SIGFPE terminates the process. No recovery possible.  
**Current mitigation:** ABI version validation at load time; `RTLD_NOW` surfaces linker errors immediately; plugin error counter tracks handler failures.  
**Unresolved:** True isolation requires fork/exec per plugin or seccomp sandboxing — not feasible in the current single-process architecture.  
**Operational guidance:** Only load plugins from trusted sources. Review plugin source before deployment. Run with `LD_PRELOAD` sanitizers in staging.

---

### F-6 — Correlation engine global lock under alert storm

**Subsystem:** correlation.c  
**Trigger:** Multiple detection workers generating alerts simultaneously (DDoS scenario with >10K alerts/sec).  
**Impact:** All detection workers serialize on `engine->lock` for the duration of `correlation_process_alerts`. Detection latency increases; parsed queue fills.  
**Unresolved:** Sharding the correlation engine by source IP hash would eliminate contention. Current workaround: reduce detection workers to 1 under heavy alert load.

---

### F-7 — `evict_lru_source` O(4096) scan under adversarial IP spray

**Subsystem:** detection.c  
**Trigger:** Attacker maintains exactly `MAX_TRACKED_SOURCES` active IPs per shard, forcing LRU eviction on every new IP.  
**Impact:** Each eviction scans 4096 bucket heads. At 100K PPS with 16 shards full: ~100K × O(4096) operations per second.  
**Observable:** `detection_lru_evictions_total` counter in Prometheus metrics.  
**Unresolved:** Doubly-linked LRU list per shard would make eviction O(1). See ENGINEERING_AUDIT.md H-1.

---

### F-8 — Plugin `packet_handler` blocking indefinitely

**Subsystem:** detection.c, capture.c  
**Trigger:** Plugin enters infinite loop or blocks on I/O inside `packet_handler`.  
**Impact:** Detection worker thread stalls. `parsed_queue` fills; parser workers time out and drop packets. IDS becomes effectively blind.  
**Observable:** `queue_drops_total{name="pipeline"}` counter spikes; `detection_latency_us` metric grows without bound.  
**Unresolved:** No per-plugin timeout mechanism exists.

---

### F-9 — `make_deadline` returns zero deadline on clock failure

**Subsystem:** queue.c  
**Trigger:** `clock_gettime(CLOCK_MONOTONIC)` fails (unexpected on Linux; possible on stripped-down embedded targets).  
**Impact:** `pthread_cond_timedwait` expires immediately, returning ETIMEDOUT for every call. All `ids_queue_push_timeout` and `ids_pool_acquire_timeout` calls fail instantly. Complete packet loss.  
**Observable:** `queue_drops_total` spikes to match packet rate. `pool_failed_acquires_total` also spikes.  
**Unresolved:** `clock_gettime` failure is not explicitly counted. A diagnostic counter for deadline-creation failures would help distinguish this from legitimate queue saturation.

---

## Overload Scenarios

### O-1 — Packet burst exhausts raw_pool

**Trigger:** Burst PPS > pool capacity / mean service time.  
**Behavior:** `ids_pool_try_acquire` returns NULL; packet is dropped.  
**Observable:** `pool_failed_acquires_total`, `packets_dropped_total`.  
**Bounded:** Yes. Queue size configurable; drops are counted.

---

### O-2 — Slow detection backs up parsed_queue

**Trigger:** Detection latency consistently > `PIPELINE_QUEUE_TIMEOUT_MS` (250ms).  
**Behavior:** Parser workers time out on `ids_queue_push_timeout`; parsed packets are dropped.  
**Observable:** `queue_drops_total{name="pipeline"}` counter; `queue_depth{name="parsed"}` at/near capacity; watchdog warning at 90%.  
**Bounded:** Yes. All queues are bounded.

---

### O-3 — SQLite write latency spike

**Trigger:** Disk I/O stall, WAL checkpoint, filesystem contention.  
**Behavior:** `step_with_retry` retries 3× with 10/25/50ms backoff before failing. Storage errors increment. Event bus queue fills and drops events.  
**Observable:** `storage_errors_total`, `storage_write_latency_us` spike, `queue_drops_total{name="events"}`.  
**Bounded:** Yes. Pipeline is isolated from SQLite failures.

---

### O-4 — Event bus queue saturation

**Trigger:** SQLite handler slow; event worker thread behind producing threads.  
**Behavior:** `event_queue_try_push_owned` returns false; event is dropped and counted.  
**Observable:** `queue_drops_total{name="events"}`.  
**Bounded:** Yes. Event queue capacity = `config.queue_size`.

---

## Degraded-Mode Behavior Table

| Condition | Behavior | Operator Signal |
|---|---|---|
| Raw pool exhausted | Drop incoming packet | `pool_failed_acquires_total` |
| Pipeline queue full | Drop packet/event after timeout | `queue_drops_total` |
| SQLite unavailable | Text/JSONL logging only | Startup warning |
| Plugin load failure | Continue without plugin | stderr warning |
| Metrics port in use | Abort if `metrics_enabled`; skip if not | Startup error |
| Rules file unreadable | Built-in defaults | stderr warning with copy hint |
| Config file missing | Built-in defaults | Silent |
| PCAP file unreadable | Exit | pcap_open_offline error |
| Live interface unavailable | Exit | pcap_open_live error |
| BPF filter invalid | Exit | pcap_compile error |

---

## Shutdown Semantics

Shutdown is initiated by `SIGTERM`, `SIGINT`, or internal error setting `g_stop_requested = 1`.

**Sequence (deterministic):**
1. Capture thread sees `stop_requested`, exits within ≤ 1s (live) or on next PCAP read (offline), closes `raw_queue`.
2. Parser workers drain `raw_queue` and exit.
3. `parsed_queue` is closed.
4. Detection workers drain `parsed_queue` and exit.
5. `log_queue` is closed.
6. Logger thread drains `log_queue` and exits.
7. Event bus worker drains event queue and exits.

**Known stall risk:** Plugin blocked in `packet_handler` prevents step 4 from completing. No timeout enforcement on `pthread_join`. Manual `SIGKILL` is the operator escape hatch.
