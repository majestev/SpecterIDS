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
- alerts by severity
- alerts by type
- protocol counters
- top source IPs
- top destination ports
- queue depths
- queue drops

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
- memory usage
- CPU seconds
- alerts per minute

High queue pressure or drops means the operator should tune workers, queue size or BPF filters.
