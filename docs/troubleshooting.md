# Troubleshooting

## Permission Denied

Live capture requires root or packet-capture capabilities.

```bash
sudo ./specterids -i eth0
```

or:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./specterids
```

## No Packets

Check the interface name:

```bash
ip link
```

Check your BPF filter. `bpf_filter=ip` excludes ARP; use `ip or arp` if you want ARP spoofing detection.

## High Drops

Increase `queue_size`, reduce `dashboard_refresh_ms`, use a narrower `--bpf` filter, or lower packet logging volume.

## Large Logs

Use `rotation_size_mb` and external log rotation/compression for long sessions.

## Unsupported Datalink

The current parser supports Ethernet (`DLT_EN10MB`). Use a different interface or add a datalink adapter.
