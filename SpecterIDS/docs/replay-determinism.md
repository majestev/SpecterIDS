# SpecterIDS Replay Determinism

Version 3.0.0 | Updated 2026-05-29

---

## Definition

A PCAP replay is **deterministic** if, for a fixed binary + rules + config, the same input file produces:
- Identical parsed packet count
- Identical alert count and types
- Identical queue drop count
- Identical malformed packet count

Wall-clock metrics (PPS, runtime, latency percentiles) are explicitly excluded from the deterministic contract — they depend on hardware and OS scheduling.

---

## Sources of Nondeterminism

### 1. Multiple pipeline workers (RESOLVED)

Two parser workers competing for `raw_queue` items produce nondeterministic processing order. The same applies to detection workers. A packet processed by parser A before parser B in run 1 may be processed by B before A in run 2. Because detection state is source-IP-keyed, this matters only for packets from the same source IP that arrive in the same millisecond — but the non-determinism is theoretically possible.

**Resolution:** `--benchmark` mode forces `parser_workers=1, detection_workers=1`. With a single worker per stage, the pipeline is a strict FIFO chain and packet order is fully deterministic.

### 2. Time-based detection windows (DESIGN INVARIANT)

Detection operates on packet timestamps from the PCAP, not wall-clock time. All window comparisons (`prune_time_events`, `add_time_event`) use `packet->timestamp.tv_sec`. Replay speed does not affect detection results.

### 3. Risk score decay (DESIGN INVARIANT)

`decay_risk` and `decay_source_score` operate on packet timestamps, not `time(NULL)`. For replay, the "now" in decay is the PCAP packet timestamp. Two replays of the same PCAP see the same timestamps and produce the same decay steps.

### 4. Correlation window (DESIGN INVARIANT)

`correlation_process_alerts` uses `alert->timestamp.tv_sec` (from the packet) for the window boundary check. Deterministic by design.

### 5. FNV-1a shard routing (DESIGN INVARIANT)

`select_shard` hashes the source IP string with FNV-1a (canonical offset basis `14695981039346656037ULL`). Source IP → shard assignment is a pure function. Same binary produces the same routing on every run.

---

## Validation Methodology

The `tests/test_determinism.sh` script performs 3 consecutive benchmark runs on `tests/pcaps/portscan.pcap` and asserts all four deterministic fields are identical across runs.

```
$ ./tests/test_determinism.sh ./specterids tests/pcaps/portscan.pcap
Determinism test: tests/pcaps/portscan.pcap
Run 1...
Run 2...
Run 3...
  PASS packets_parsed (run1==run2): 3
  PASS packets_parsed (run2==run3): 3
  PASS alerts (run1==run2): 0
  PASS alerts (run2==run3): 0
  PASS queue_drops (run1==run2): 0
  PASS queue_drops (run2==run3): 0
  PASS malformed_packets (run1==run2): 0
  PASS malformed_packets (run2==run3): 0

test_determinism: ok (8 checks)
```

To extend coverage to alerting PCAPs:

```bash
./tests/test_determinism.sh ./specterids tests/pcaps/synflood.pcap
./tests/test_determinism.sh ./specterids tests/pcaps/beaconing.pcap
./tests/test_determinism.sh ./specterids tests/pcaps/bruteforce.pcap
```

---

## Operational Notes

**For regression testing:** Always use `--benchmark` (which forces single workers) when comparing alert output between builds. Multi-worker replays may produce different alert orderings even with the same binary.

**For benchmarking throughput:** Multi-worker replay is appropriate. Non-determinism in alert count is negligible for throughput measurement.

**For forensic re-analysis:** Run with `parser_workers=1 detection_workers=1` in config, or use `--benchmark`. This guarantees reproducible alert lists when re-processing the same PCAP after a rules change.

---

## Known Nondeterminism (Non-Benchmark Mode)

When using default 2 workers per stage in offline replay:
- Alert ordering within the same second is not guaranteed.
- Total alert count is usually identical across runs (detection is stateless per packet), but edge cases exist when two packets from the same source IP trigger threshold conditions and their processing order varies.

This is documented behavior, not a bug. Use `--benchmark` or explicit `parser_workers=1 detection_workers=1` for reproducible output.
