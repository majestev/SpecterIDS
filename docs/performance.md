# Performance

SpecterIDS uses a bounded pipeline with object reuse.

## Performance Features

- capture callback does bounded copy into pooled objects
- parser and detection stages run on worker threads
- logger is isolated from detection workers
- queue pressure and drops are visible in metrics
- parser/detection/logging average latencies are tracked

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
- Use BPF filters to reduce unnecessary traffic.
- Watch `specter_queue_drops_total` and queue depths in `/metrics`.
