# Detection Engine

The detection engine maintains bounded per-source state and emits alert objects.

## State

Each source IP tracks fixed-size windows for:

- port touches
- SYN attempts
- SSH attempts
- ICMP packets
- UDP packets
- DNS packets
- generic packet rate
- connection attempts
- byte volume
- beaconing tuples

## Risk

Alerts increase a temporary risk score. Risk decays over time. High scores can raise severity dynamically and can trigger `HEURISTIC_RISK`.

## Correlation

The correlation engine consumes alerts and can emit `THREAT_CORRELATION` when multiple stages of suspicious behavior appear in the same window.

## Scalability Notes

The current engine uses one lock for correctness. Parser, logger and queues are already decoupled, so the next scaling step is sharding detection state by source IP.
