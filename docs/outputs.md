# Outputs

Outputs are organized behind a registry and event-driven interface.

## Current Outputs

- console alerts
- packet/status text log
- alert text log
- alert JSONL log
- suspicious PCAP context export
- localhost metrics endpoint

## Files

- `logs/specterids.log`
- `logs/alerts.log`
- `logs/alerts.jsonl`
- `captures/suspicious.pcap`

## Rotation

Text and JSONL logs support simple size-based rotation to `.1`. Compression is intentionally left to external log rotation tooling for reliability.

## Future Storage

The storage layer separates directories for logs, captures and reports, preparing the codebase for SQLite or remote shipper integrations without changing detection logic.
