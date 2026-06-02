# Contributing to SpecterIDS

SpecterIDS welcomes defensive, educational improvements.

## Development Loop

```bash
make
make test
make fuzz
make benchmark
make analyze
```

## Contribution Rules

- Keep the project passive and defensive.
- Do not add exploitation, persistence, evasion or credential capture.
- Keep memory bounded.
- Add tests for new parser, queue, detection or correlation behavior.
- Update docs when changing CLI, config, rules or outputs.

## Pull Requests

Include:

- summary of behavior changed
- tests run
- risk/rollback notes
- docs updated
