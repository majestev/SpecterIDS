# Detection Rules

Rules are loaded from `rules/default.rules` by default or from a custom file with `--rules`.

## Format

```text
RULE_NAME key=value key=value ...
```

Comments start with `#`. Empty lines are ignored. Invalid options produce warnings and leave safe defaults in place.

## Default Rules

```text
PORT_SCAN threshold=20 window=10 severity=HIGH enabled=true
SSH_BRUTE_FORCE port=22 threshold=10 window=60 severity=HIGH enabled=true
SYN_FLOOD threshold=100 window=5 severity=CRITICAL enabled=true
ICMP_FLOOD threshold=100 window=5 severity=MEDIUM enabled=true
UDP_FLOOD threshold=200 window=10 severity=MEDIUM enabled=true
BEACONING min_hits=8 interval=30 tolerance=3 severity=MEDIUM enabled=true
ARP_SPOOFING severity=HIGH enabled=true
DNS_FLOOD threshold=150 window=10 severity=MEDIUM enabled=true
RATE_ANOMALY threshold=500 window=10 severity=MEDIUM enabled=true
SLOW_SCAN threshold=15 window=300 severity=MEDIUM enabled=true
SENSITIVE_PORT threshold=1 window=60 severity=MEDIUM enabled=true
CONNECTION_EXCESS threshold=200 window=60 severity=HIGH enabled=true
LARGE_PAYLOAD threshold=1400 window=60 severity=MEDIUM enabled=true
VOLUME_ANOMALY threshold=10000000 window=60 severity=HIGH enabled=true
HEURISTIC_RISK threshold=80 window=300 severity=HIGH enabled=true
```

## Supported Options

- `enabled=true|false`
- `severity=LOW|MEDIUM|HIGH|CRITICAL`
- `threshold=<positive integer>`
- `window=<seconds>`
- `port=<1-65535>` for `SSH_BRUTE_FORCE`
- `min_hits=<positive integer>` for `BEACONING`
- `interval=<seconds>` for `BEACONING`
- `tolerance=<seconds>` for `BEACONING`

## Rule Semantics

`PORT_SCAN`: same source touches more than `threshold` distinct TCP destination ports within `window` seconds.

`SSH_BRUTE_FORCE`: same source sends more than `threshold` TCP SYN packets to `port` within `window` seconds.

`SYN_FLOOD`: same source sends more than `threshold` TCP SYN packets without ACK within `window` seconds.

`ICMP_FLOOD`: same source sends more than `threshold` ICMP packets within `window` seconds.

`UDP_FLOOD`: same source sends more than `threshold` UDP packets within `window` seconds.

`BEACONING`: same source repeatedly contacts the same destination/protocol/port at approximately `interval` seconds, allowing `tolerance` seconds of drift, for at least `min_hits` observations.

`ARP_SPOOFING`: ARP sender IP is observed with a changed MAC address.

`DNS_FLOOD`: source exceeds DNS packet thresholds.

`RATE_ANOMALY`: source exceeds generic packet-rate thresholds.

`SLOW_SCAN`: source touches many ports over a longer window.

`SENSITIVE_PORT`: source touches configured sensitive ports from `specterids.conf`.

`CONNECTION_EXCESS`: source creates too many TCP connection attempts.

`LARGE_PAYLOAD`: single packet metadata indicates an unusually large payload.

`VOLUME_ANOMALY`: source transfers excessive bytes in a window.

`HEURISTIC_RISK`: source risk score crosses the configured threshold.

## Tuning Notes

Small lab networks can use lower thresholds to demonstrate alerting quickly. Larger or noisy networks should increase thresholds and windows to reduce false positives. Beaconing is intentionally heuristic and should be treated as a signal for investigation rather than proof of compromise.
