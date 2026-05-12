# Contributing

SpecterIDS accepts defensive, educational improvements.

## Before Opening a PR

```bash
make
make test
make fuzz
make analyze
```

## Rules

- Do not add offensive behavior.
- Do not add exploitation, persistence, evasion or credential capture.
- Keep parser changes bounds-checked.
- Keep queues and pools bounded.
- Add tests for new detection rules.
- Document operational limitations.

## Good First Areas

- More parser fixtures.
- IPv6 metadata parsing.
- Sharded detection state.
- Offline PCAP replay.
- Better benchmark scenarios.
