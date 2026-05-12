# Development

## Build Targets

```bash
make
make release
make debug
make test
make fuzz
make benchmark
make analyze
make format
make clean
```

Debug builds use:

```text
-g -O0 -fsanitize=address,undefined
```

Release builds use:

```text
-O2 -DNDEBUG
```

All builds use:

```text
-Wall -Wextra -Wpedantic -std=c11
```

## Tests

Tests are plain C programs in `tests/`.

- `test_rules.c`: rule parser defaults, valid parsing and invalid-line handling.
- `test_detection.c`: port scan, SSH brute force and SYN flood alerts.
- `test_parser.c`: TCP metadata extraction and truncated-packet safety.
- `test_queue.c`: queue producer/consumer behavior.
- `fuzz_parser.c`: deterministic parser fuzz smoke test.
- `benchmark.c`: synthetic detection throughput benchmark.

Run:

```bash
make test
make fuzz
make benchmark
```

## Style

- Keep modules small and single-purpose.
- Validate pointers and buffer sizes before use.
- Prefer `snprintf` and bounded copies.
- Do not add offensive behavior or packet modification.
- Add tests for parser and detection edge cases before changing thresholds or state machines.

## Dependency Notes

Production builds require `libpcap-dev` or the equivalent distribution package. Unit tests for parser/rules/detection do not require libpcap because `parser.h` is intentionally independent from pcap types.
