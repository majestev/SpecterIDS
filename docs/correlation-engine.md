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
