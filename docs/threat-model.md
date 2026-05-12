# Threat Model

SpecterIDS is a defensive educational IDS. Its purpose is to observe network metadata in an authorized environment and raise transparent alerts.

## In Scope

- Packet metadata capture from a local Linux interface.
- Parsing Ethernet, IPv4, TCP, UDP and ICMP headers.
- Rule-based anomaly detection for scans, floods, SSH attempts and simple beaconing.
- Local logs and terminal dashboard.

## Out of Scope

- Exploitation or vulnerability validation.
- Packet injection or traffic modification.
- Credential capture or payload extraction.
- Persistence, stealth, evasion or privilege escalation.
- Automated blocking or retaliation.

## Security Assumptions

- The operator has authorization to monitor the selected interface.
- Logs are stored on a trusted local filesystem.
- Detection results are advisory and require human interpretation.
- Root privileges may be needed for capture; users should prefer Linux capabilities where possible.

## Risks and Mitigations

- High packet rates can produce large logs. Mitigation: use BPF filters and log rotation outside the app.
- Heuristic rules can produce false positives. Mitigation: tune `rules/default.rules` for the lab.
- Running as root expands blast radius. Mitigation: use `setcap cap_net_raw,cap_net_admin=eip ./specterids` where appropriate.
- IPv6 traffic is not parsed in the current version. Mitigation: document parser scope and use BPF filters when needed.
