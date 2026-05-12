# Metrics

SpecterIDS can expose a local Prometheus-style endpoint.

## Enable

```bash
sudo ./specterids -i eth0 --metrics
sudo ./specterids -i eth0 --metrics --metrics-port 9090
```

Config:

```ini
metrics_enabled=true
metrics_port=9090
```

## Endpoint

The server binds to localhost only:

```text
http://127.0.0.1:9090/metrics
```

## Example

```text
specter_packets_total 1000
specter_packets_parsed_total 998
specter_alerts_total 12
specter_queue_raw 0
specter_avg_parse_us 3.210
specter_avg_detection_us 15.420
```

## Security

The endpoint is read-only and local-only. It exposes defensive runtime counters, not packet payloads.
