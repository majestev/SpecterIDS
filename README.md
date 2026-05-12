# SpecterIDS

![CI](https://github.com/example/SpecterIDS/actions/workflows/ci.yml/badge.svg)
![Language](https://img.shields.io/badge/language-C-blue)
![Platform](https://img.shields.io/badge/platform-Linux-success)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

```text
  ____                  _             ___ ____  ____
 / ___| _ __   ___  ___| |_ ___ _ __ |_ _|  _ \/ ___|
 \___ \| '_ \ / _ \/ __| __/ _ \ '__| | || | | \___ \
  ___) | |_) |  __/ (__| ||  __/ |    | || |_| |___) |
 |____/| .__/ \___|\___|\__\___|_|   |___|____/|____/
       |_|
```

---

> 🇧🇷 [Português](#português) · 🇺🇸 [English](#english)

---

<a name="português"></a>
# 🇧🇷 Português

SpecterIDS é um sistema de detecção de intrusões defensivo e educacional escrito em C para Linux. Ele captura pacotes de rede com `libpcap`, os processa em um pipeline encadeado com fila delimitada, analisa metadados de Ethernet/ARP/IPv4/TCP/UDP/ICMP, aplica regras de detecção transparentes e gera saídas profissionais em texto, JSONL e PCAP forense opcional para monitoramento autorizado em laboratório.

## Uso Ético

Use o SpecterIDS somente em redes que você possui ou nas quais tem permissão explícita para monitorar. O projeto é defensivo e educacional. Ele não explora vulnerabilidades, não modifica tráfego, não persiste em sistemas, não evade controles, não rouba dados nem realiza atividades ofensivas.

## Funcionalidades

- Captura de pacotes ao vivo via `libpcap`.
- Pipeline encadeado com fila delimitada: thread de captura, workers de análise, workers de detecção e thread de log.
- Pools de objetos para evitar `malloc/free` no caminho de pacotes.
- Barramento de eventos interno para eventos de pacote, detecção, alerta, saída, recarga e métricas.
- Interfaces de módulos internos para parsers, detecções, saídas e enriquecimentos.
- CLI profissional com `--help`, `--version`, `--config`, `--rules`, `--bpf`, `--json`, `--dashboard`, `--verbose` e `--quiet`.
- Parser seguro para metadados de Ethernet, Ethernet com tag VLAN, ARP, IPv4, TCP, UDP e ICMP.
- Suporte a arquivo de configuração com sobrescritas via CLI.
- Suporte a arquivo de regras com padrões seguros e avisos não fatais para linhas inválidas.
- Detecção de varreduras, floods, portas sensíveis, spoofing ARP, beaconing, alto volume e risco heurístico.
- Logs de texto em `logs/specterids.log` e `logs/alerts.log`.
- Alertas opcionais em JSON Lines em `logs/alerts.jsonl`.
- Exportação opcional de pacotes suspeitos em `captures/suspicious.pcap`.
- Endpoint de métricas no estilo Prometheus opcional em localhost.
- Dashboard de terminal opcional com totais, pacotes/seg, contadores de severidade de alertas, IPs de origem mais frequentes e alertas recentes.
- Testes unitários, testes de concorrência de fila, fuzzing do parser e benchmarks sintéticos.
- CI com GitHub Actions.

## Instalação

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

Fedora:

```bash
sudo dnf install gcc make libpcap-devel
```

Arch Linux:

```bash
sudo pacman -S base-devel libpcap
```

## Build

```bash
make
make debug
make release
make clean
```

Builds de debug utilizam AddressSanitizer e UndefinedBehaviorSanitizer:

```bash
make debug
```

## Execução

A captura de pacotes ao vivo geralmente requer root ou `CAP_NET_RAW`/`CAP_NET_ADMIN`.

```bash
sudo ./specterids -i eth0
sudo ./specterids -i eth0 --verbose
sudo ./specterids -i eth0 --quiet
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
sudo ./specterids -i eth0 --rules rules/default.rules
sudo ./specterids -i eth0 --config config/specterids.conf
sudo ./specterids -i eth0 --bpf "tcp or udp"
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --metrics --metrics-port 9090
kill -HUP <specterids-pid>
```

Exibir ajuda e versão:

```bash
./specterids --help
./specterids --version
```

Atalho pelo Makefile:

```bash
make run IFACE=eth0
```

## Configuração

Exemplo padrão: `config/specterids.conf`.

```ini
interface=eth0
log_dir=logs
rules_file=rules/default.rules
json_logs=true
dashboard=false
verbose=false
quiet=false
bpf_filter=ip
workers=2
queue_size=1024
rotation_size_mb=32
sensitive_ports=22,23,445,3389,5900,8080
dashboard_refresh_ms=1000
dashboard_mode=detailed
pcap_export=false
metrics_enabled=false
metrics_port=9090
```

Argumentos de CLI sobrescrevem os valores do arquivo de configuração:

```bash
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard --bpf "tcp"
```

## Regras de Detecção

As regras ficam em `rules/default.rules`:

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

Linhas de regras inválidas são ignoradas com avisos; os padrões embutidos permanecem ativos.

## Logs

Log de pacotes do sistema:

```text
[2026-05-12 19:30:00] [TCP] src=192.168.0.15:50122 dst=192.168.0.1:22 len=60 caplen=60
```

Log de alertas em texto:

```text
[2026-05-12 19:30:00] [HIGH] [PORT_SCAN] src=192.168.0.15 dst=192.168.0.1 reason="Source accessed more than 20 ports in 10 seconds"
```

Log de alertas em JSONL com `--json`:

```json
{"timestamp":"2026-05-12T19:30:00","severity":"HIGH","type":"PORT_SCAN","src_ip":"192.168.0.15","dst_ip":"192.168.0.1","reason":"Source accessed more than 20 ports in 10 seconds"}
```

## Dashboard

Ative o dashboard com:

```bash
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
```

O dashboard exibe:

- Interface monitorada
- Tempo de atividade
- Total de pacotes
- Pacotes por segundo
- Total de alertas
- Alertas por severidade
- IPs de origem mais frequentes
- Alertas recentes
- Profundidade das filas
- Drops e erros de parse
- Throughput
- Segundos de CPU e RSS máximo
- Latência média de parse/detecção/log

Exemplo de layout:

```text
SpecterIDS dashboard | iface=eth0 | mode=detailed | uptime=42.0s
  packets=12042 parsed=12040 drops=0 parse_errors=2 pps=286.67 mbps=1.832 alerts/min=4.29
  queues packet=0 parsed=0 log=1 | cpu=0.210s mem=9216KB
  alerts LOW=0 MEDIUM=2 HIGH=1 CRITICAL=0 total=3
```

## Testes

```bash
make test
make fuzz
make benchmark
make integration-test
```

A suite de testes verifica:

- Parsing válido de regras
- Tratamento seguro de regras inválidas
- Alertas de varredura de portas
- Alertas de brute-force SSH
- Alertas de SYN flood
- Comportamento seguro do parser com pacotes truncados
- Comportamento produtor/consumidor da fila
- Entradas fuzzadas no parser
- Throughput sintético de detecção
- Comportamento do barramento de eventos e motor de correlação

## Métricas

Ative um endpoint de métricas local somente leitura:

```bash
sudo ./specterids -i eth0 --metrics
curl http://127.0.0.1:9090/metrics
```

Exemplo:

```text
specter_packets_total 1000
specter_alerts_total 20
specter_queue_raw 0
specter_avg_detection_us 12.400
```

## Arquitetura

```text
CLI/config -> rules -> capture thread -> raw queue -> parser workers
                                                     -> parsed queue -> detection workers
                                                     -> log queue -> logger thread
                                                                    -> logs/JSONL/PCAP
                                                     -> stats/dashboard
                                                     -> event bus/modules
```

O parser extrai apenas metadados. O motor de detecção mantém janelas de tempo por origem e emite alertas quando os limiares são excedidos. O logger escreve texto estruturado e JSONL opcional. O SpecterIDS nunca modifica pacotes nem interage com sistemas remotos.

## Decisões de Design

- Filas delimitadas em vez de buffer ilimitado: sobrecarga se manifesta como drops visíveis, não como esgotamento de memória.
- Pools de objetos em vez de alocação no caminho de pacotes: uso de memória previsível durante picos.
- Detecção baseada em metadados: sinais defensivos úteis sem coleta de payload.
- Config/regras tolerantes: linhas inválidas geram avisos e recaem para padrões seguros.
- Escritor único para logs: rotação mais simples e menos contenção.
- O barramento de eventos é síncrono por design: fácil de raciocinar e barato para assinantes no mesmo processo.

## Modelo de Segurança

O SpecterIDS é passivo. Ele lê o tráfego da interface local, analisa metadados, grava artefatos locais e encerra de forma limpa em sinais. Não injeta pacotes, não modifica o estado da rede, não explora alvos nem coleta credenciais.

## Estrutura do Projeto

```text
SpecterIDS/
├── config/
│   └── specterids.conf
├── src/
├── include/
├── rules/
├── logs/
├── captures/
├── pcaps/
├── reports/
├── docs/
├── tests/
├── .github/workflows/ci.yml
├── Makefile
├── SECURITY.md
├── README.md
└── LICENSE
```

## Limitações

- Apenas IPv4 no parser atual.
- Apenas datalink Ethernet (`DLT_EN10MB`).
- A detecção é baseada em metadados e intencionalmente simples para fins educacionais.
- A detecção de beaconing é heurística e pode gerar falsos positivos em tráfego legítimo periódico.
- O estado de detecção atualmente usa um único lock de motor; sharding futuro pode aumentar o throughput de detecção paralela.

## Roadmap

- Modo de entrada PCAP offline para treinamento repetível e testes de regressão.
- Suporte a IPv6.
- Estado de detecção fragmentado por hash de IP de origem.
- Carregamento dinâmico de módulos após a estabilização do ABI interno.
- Grupos de regras e limiares por destino.
- Exportação para SQLite para sessões de laboratório mais longas.
- Mais testes de parser com fixtures de pacotes gerados.

## Licença

Licença MIT. Veja `LICENSE`.

---

<a name="english"></a>
# 🇺🇸 English

SpecterIDS is a defensive, educational intrusion detection system written in C for Linux. It captures network packets with `libpcap`, moves them through a bounded threaded pipeline, parses Ethernet/ARP/IPv4/TCP/UDP/ICMP metadata, applies transparent detection rules and writes professional text, JSONL and optional PCAP forensic outputs for authorized lab monitoring.

## Ethical Use

Use SpecterIDS only on networks you own or have explicit permission to monitor. The project is defensive and educational. It does not exploit vulnerabilities, modify traffic, persist on systems, evade controls, steal data or perform offensive activity.

## Features

- Live packet capture through `libpcap`.
- Bounded threaded pipeline: capture thread, parser workers, detection workers and logger thread.
- Object pools to avoid packet-path `malloc/free`.
- Internal event bus for packet, detection, alert, output, reload and metrics events.
- Internal module interfaces for parsers, detections, outputs and enrichments.
- Professional CLI with `--help`, `--version`, `--config`, `--rules`, `--bpf`, `--json`, `--dashboard`, `--verbose` and `--quiet`.
- Safe parser for Ethernet, VLAN-tagged Ethernet, ARP, IPv4, TCP, UDP and ICMP metadata.
- Config file support with CLI overrides.
- Rule file support with safe defaults and non-fatal warnings for invalid lines.
- Detection for scans, floods, sensitive ports, ARP spoofing, beaconing, high volume and heuristic risk.
- Text logs in `logs/specterids.log` and `logs/alerts.log`.
- Optional JSON Lines alerts in `logs/alerts.jsonl`.
- Optional suspicious packet export in `captures/suspicious.pcap`.
- Optional localhost Prometheus-style metrics endpoint.
- Optional terminal dashboard with totals, packets/sec, alert severity counters, top source IPs and recent alerts.
- Unit tests, queue concurrency tests, parser fuzzing and synthetic benchmarks.
- GitHub Actions CI.

## Install

Debian/Ubuntu:

```bash
sudo apt update
sudo apt install build-essential libpcap-dev
```

Fedora:

```bash
sudo dnf install gcc make libpcap-devel
```

Arch Linux:

```bash
sudo pacman -S base-devel libpcap
```

## Build

```bash
make
make debug
make release
make clean
```

Debug builds use AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make debug
```

## Run

Live packet capture usually requires root or `CAP_NET_RAW`/`CAP_NET_ADMIN`.

```bash
sudo ./specterids -i eth0
sudo ./specterids -i eth0 --verbose
sudo ./specterids -i eth0 --quiet
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
sudo ./specterids -i eth0 --rules rules/default.rules
sudo ./specterids -i eth0 --config config/specterids.conf
sudo ./specterids -i eth0 --bpf "tcp or udp"
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --metrics --metrics-port 9090
kill -HUP <specterids-pid>
```

Show help and version:

```bash
./specterids --help
./specterids --version
```

Makefile helper:

```bash
make run IFACE=eth0
```

## Configuration

Default example: `config/specterids.conf`.

```ini
interface=eth0
log_dir=logs
rules_file=rules/default.rules
json_logs=true
dashboard=false
verbose=false
quiet=false
bpf_filter=ip
workers=2
queue_size=1024
rotation_size_mb=32
sensitive_ports=22,23,445,3389,5900,8080
dashboard_refresh_ms=1000
dashboard_mode=detailed
pcap_export=false
metrics_enabled=false
metrics_port=9090
```

CLI arguments override config file values:

```bash
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard --bpf "tcp"
```

## Detection Rules

Rules live in `rules/default.rules`:

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

Invalid rule lines are ignored with warnings; built-in defaults remain active.

## Logs

System packet log:

```text
[2026-05-12 19:30:00] [TCP] src=192.168.0.15:50122 dst=192.168.0.1:22 len=60 caplen=60
```

Alert text log:

```text
[2026-05-12 19:30:00] [HIGH] [PORT_SCAN] src=192.168.0.15 dst=192.168.0.1 reason="Source accessed more than 20 ports in 10 seconds"
```

JSONL alert log with `--json`:

```json
{"timestamp":"2026-05-12T19:30:00","severity":"HIGH","type":"PORT_SCAN","src_ip":"192.168.0.15","dst_ip":"192.168.0.1","reason":"Source accessed more than 20 ports in 10 seconds"}
```

## Dashboard

Enable the dashboard with:

```bash
sudo ./specterids -i eth0 --dashboard
sudo ./specterids -i eth0 --dashboard compact
```

The dashboard shows:

- interface monitored
- uptime
- total packets
- packets per second
- total alerts
- alerts by severity
- top source IPs
- recent alerts
- queue depths
- drops and parse errors
- throughput
- CPU seconds and max RSS
- average parse/detection/logging latency

Example layout:

```text
SpecterIDS dashboard | iface=eth0 | mode=detailed | uptime=42.0s
  packets=12042 parsed=12040 drops=0 parse_errors=2 pps=286.67 mbps=1.832 alerts/min=4.29
  queues packet=0 parsed=0 log=1 | cpu=0.210s mem=9216KB
  alerts LOW=0 MEDIUM=2 HIGH=1 CRITICAL=0 total=3
```

## Tests

```bash
make test
make fuzz
make benchmark
make integration-test
```

The test suite checks:

- valid rule parsing
- safe handling of invalid rules
- port-scan alerting
- SSH brute-force alerting
- SYN-flood alerting
- safe parser behavior with truncated packets
- queue producer/consumer behavior
- fuzzed parser inputs
- synthetic detection throughput
- event bus and correlation engine behavior

## Metrics

Enable a local read-only metrics endpoint:

```bash
sudo ./specterids -i eth0 --metrics
curl http://127.0.0.1:9090/metrics
```

Example:

```text
specter_packets_total 1000
specter_alerts_total 20
specter_queue_raw 0
specter_avg_detection_us 12.400
```

## Architecture

```text
CLI/config -> rules -> capture thread -> raw queue -> parser workers
                                                     -> parsed queue -> detection workers
                                                     -> log queue -> logger thread
                                                                    -> logs/JSONL/PCAP
                                                     -> stats/dashboard
                                                     -> event bus/modules
```

The parser extracts metadata only. The detection engine keeps per-source time windows and emits alerts when thresholds are exceeded. The logger writes structured text and optional JSONL. SpecterIDS never modifies packets or interacts with remote systems.

## Design Decisions

- Bounded queues over unbounded buffering: overload becomes visible drops instead of memory exhaustion.
- Object pools over packet-path allocation: predictable memory use during bursts.
- Metadata-first detection: useful defensive signals without payload harvesting.
- Tolerant config/rules: invalid lines warn and fall back to safe defaults.
- Single writer for logs: simpler rotation and less contention.
- Event bus is synchronous by design: easy to reason about and cheap for in-process subscribers.

## Security Model

SpecterIDS is passive. It reads local interface traffic, parses metadata, writes local artifacts and exits cleanly on signals. It does not inject packets, modify network state, exploit targets or collect credentials.

## Project Structure

```text
SpecterIDS/
├── config/
│   └── specterids.conf
├── src/
├── include/
├── rules/
├── logs/
├── captures/
├── pcaps/
├── reports/
├── docs/
├── tests/
├── .github/workflows/ci.yml
├── Makefile
├── SECURITY.md
├── README.md
└── LICENSE
```

## Limitations

- IPv4 only in the current parser.
- Ethernet datalink only (`DLT_EN10MB`).
- Detection is metadata-based and intentionally simple for education.
- Beaconing detection is heuristic and may produce false positives in periodic legitimate traffic.
- Detection state currently uses one engine lock; future sharding can increase parallel detection throughput.

## Roadmap

- Offline PCAP input mode for repeatable training and regression tests.
- IPv6 support.
- Sharded detection state by source-IP hash.
- Dynamic module loading once the internal module ABI stabilizes.
- Rule groups and per-destination thresholds.
- SQLite export for longer lab sessions.
- More parser tests with generated packet fixtures.

## License

MIT License. See `LICENSE`.