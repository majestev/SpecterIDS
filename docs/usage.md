# Usage

## Build

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
make
```

## Help

```bash
./specterids --help
./specterids --version
```

## Live Capture

```bash
sudo ./specterids -i eth0
sudo ./specterids -i wlan0 --verbose
sudo ./specterids -i eth0 --quiet
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --bpf "tcp or udp"
```

## Config File

```bash
sudo ./specterids --config config/specterids.conf
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard
```

CLI arguments override the config file.

## Logs

- `logs/specterids.log`: packet metadata and status messages.
- `logs/alerts.log`: one-line text alerts.
- `logs/alerts.jsonl`: JSON Lines alerts when `--json` or `json_logs=true` is enabled.
- `captures/suspicious.pcap`: context packets around alerts when `--pcap-export` or `pcap_export=true` is enabled.

## Lab Validation

Only run validation traffic in an authorized lab.

Port scan signal:

```bash
nmap -sS -p 1-50 <lab-target-ip>
```

SSH brute force signal:

```bash
for i in $(seq 1 12); do nc -zv <lab-target-ip> 22; done
```

ICMP flood signal:

```bash
ping -f <lab-target-ip>
```

UDP flood signal:

```bash
for i in $(seq 1 250); do printf test | nc -u -w1 <lab-target-ip> 5353; done
```

Stop with `Ctrl+C`. SpecterIDS closes capture/log handles and prints a session summary.
