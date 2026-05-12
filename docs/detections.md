# Detections

SpecterIDS uses transparent defensive heuristics.

## Network Behavior

- `PORT_SCAN`: many distinct destination ports in a short window.
- `SLOW_SCAN`: distinct ports over a longer window.
- `SSH_BRUTE_FORCE`: repeated TCP SYN packets to SSH or configured SSH port.
- `SYN_FLOOD`: many SYN packets without ACK.
- `ICMP_FLOOD`: many ICMP packets.
- `UDP_FLOOD`: many UDP packets.
- `DNS_FLOOD`: many DNS packets over UDP/TCP port 53 metadata.
- `BEACONING`: repeated contact with the same destination at regular intervals.

## Defensive Heuristics

- `ARP_SPOOFING`: same ARP sender IP observed with a different MAC.
- `SENSITIVE_PORT`: access to configured sensitive TCP ports.
- `CONNECTION_EXCESS`: excessive TCP connection attempts.
- `LARGE_PAYLOAD`: unusually large payload metadata.
- `VOLUME_ANOMALY`: high byte volume from one source in a time window.
- `HEURISTIC_RISK`: temporary risk score crossing a threshold.

## Risk Score

Each source IP accumulates score when alerts fire. Scores decay over time. Severity can be raised dynamically when the score is high.

This is an educational signal, not proof of malicious activity.
