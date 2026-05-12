# Hardening

## Compiler Flags

Release builds include:

```text
-Wall -Wextra -Wpedantic -std=c11
-fstack-protector-strong
-D_FORTIFY_SOURCE=2
-O2
```

Debug builds include sanitizers:

```text
-fsanitize=address,undefined
```

## Runtime Limits

- bounded queues
- bounded pools
- bounded parser copies
- fixed detection windows
- defensive config range checks
- safe fallbacks for invalid rule lines
- local-only metrics endpoint
- SIGHUP reload keeps previous rules on failure

## Safe Failure Modes

When overloaded, SpecterIDS drops packets and reports counters instead of growing memory without limit. Parser failures are counted and discarded.

## Operational Recommendation

Prefer Linux capabilities over full root where possible:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./specterids
```
