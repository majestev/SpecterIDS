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

SpecterIDS é um sistema de detecção de intrusões defensivo e educacional escrito em C para Linux. Ele captura pacotes de rede com `libpcap` ou reproduz arquivos PCAP offline, processa tudo em um pipeline encadeado com filas delimitadas, analisa metadados de Ethernet/Linux cooked/RAW, ARP, IPv4, IPv6, TCP, UDP, ICMP e ICMPv6, aplica regras transparentes e gera saídas profissionais em texto, JSONL, PCAP forense opcional e SQLite opcional para monitoramento autorizado em laboratório.

## Uso Ético

Use o SpecterIDS somente em redes que você possui ou nas quais tem permissão explícita para monitorar. O projeto é defensivo e educacional. Ele não explora vulnerabilidades, não modifica tráfego, não persiste em sistemas, não evade controles, não rouba dados nem realiza atividades ofensivas.

## Funcionalidades

- Captura de pacotes ao vivo via `libpcap`.
- Modo offline com `--pcap`, replay temporal opcional `--pcap-replay`, velocidade `--pcap-speed` e alias `--speed`.
- Parser IPv4/IPv6 seguro com `inet_ntop` e tratamento de pacotes truncados.
- Abstração de datalink para Ethernet, Linux cooked capture e RAW IP.
- Pipeline encadeado com fila delimitada: thread de captura, workers de análise, workers de detecção e thread de log.
- Pools de objetos para evitar `malloc/free` no caminho de pacotes.
- Barramento de eventos interno para eventos de pacote, detecção, alerta, saída, recarga e métricas.
- Interfaces de módulos internos e plugins defensivos dinâmicos via `dlopen`.
- CLI profissional com `--help`, `--version`, `--config`, `--rules`, `--bpf`, `--json`, `--dashboard`, `--verbose` e `--quiet`.
- Parser seguro para metadados de Ethernet, Ethernet com tag VLAN, ARP, IPv4, TCP, UDP e ICMP.
- Suporte a arquivo de configuração com sobrescritas via CLI.
- Suporte a arquivo de regras com padrões seguros e avisos não fatais para linhas inválidas.
- Grupos de regras com `targets=` para limiares por destino IPv4/IPv6.
- Estado de detecção fragmentado por hash do IP de origem com `--detection-shards`.
- Detecção de varreduras, floods, portas sensíveis, spoofing ARP, beaconing, alto volume e risco heurístico.
- Logs de texto em `logs/specterids.log` e `logs/alerts.log`.
- Alertas opcionais em JSON Lines em `logs/alerts.jsonl`.
- Exportação opcional de pacotes suspeitos em `captures/suspicious.pcap`.
- Endpoint de métricas no estilo Prometheus opcional em localhost.
- Exportação SQLite opcional via `make sqlite` e `--sqlite data/specterids.db`.
- Métricas de IPv6, shard pressure, plugins, storage, filas e latência de pipeline.
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
make sqlite
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
sudo ./specterids -i eth0 --dashboard-verbose --dashboard-interval 2 --no-color
sudo ./specterids -i eth0 --rules rules/default.rules
sudo ./specterids -i eth0 --config config/specterids.conf
sudo ./specterids -i eth0 --bpf "tcp or udp"
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --metrics --metrics-port 9090
sudo ./specterids -i eth0 --metrics 9090
sudo ./specterids -i eth0 --detection-shards 16
kill -HUP <specterids-pid>
```

Replay offline não exige root:

```bash
./specterids --pcap samples/example.pcap
./specterids --pcap samples/example.pcap --json
./specterids --pcap samples/example.pcap --dashboard
./specterids --pcap samples/example.pcap --rules rules/default.rules
./specterids --pcap samples/example.pcap --sqlite data/lab.db
./specterids --pcap samples/example.pcap --pcap-replay --pcap-speed 5x
./specterids --pcap samples/example.pcap --speed 10x
./specterids --pcap samples/example.pcap --benchmark
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
pcap_file=
pcap_replay=false
pcap_speed=1x
log_dir=logs
rules_file=rules/default.rules
json_logs=true
dashboard=false
verbose=false
quiet=false
bpf_filter=ip or ip6 or arp
workers=2
detection_shards=16
queue_size=1024
rotation_size_mb=32
sensitive_ports=22,23,445,3389,5900,8080
dashboard_refresh_ms=1000
dashboard_mode=detailed
pcap_export=false
metrics_enabled=false
metrics_port=9090
sqlite_enabled=false
sqlite_path=data/specterids.db
plugins_enabled=false
plugin_dir=plugins
# plugin=plugins/libspecter_portscan.so
no_color=false
beaconing_min_hits=8
beaconing_interval=30
beaconing_tolerance=3
beaconing_ignore_private=true
beaconing_whitelist=8.8.8.8,1.1.1.1
```

Argumentos de CLI sobrescrevem os valores do arquivo de configuração:

```bash
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard --bpf "tcp"
```

## Regras de Detecção

As regras ficam em `rules/default.rules`:

```text
[group default]
PORT_SCAN threshold=20 window=10 severity=HIGH enabled=true
SSH_BRUTE_FORCE port=22 threshold=10 window=60 severity=HIGH enabled=true
SYN_FLOOD threshold=100 window=5 severity=CRITICAL enabled=true
ICMP_FLOOD threshold=100 window=5 severity=MEDIUM enabled=true
UDP_FLOOD threshold=200 window=10 severity=MEDIUM enabled=true
BEACONING min_hits=8 interval=30 tolerance=3 ignore_private=true severity=LOW enabled=true
ARP_SPOOFING severity=HIGH enabled=true
DNS_FLOOD threshold=150 window=10 severity=MEDIUM enabled=true
HTTP_FLOOD ports=80,443 threshold=300 window=10 severity=HIGH enabled=true
RATE_ANOMALY threshold=500 window=10 severity=MEDIUM enabled=true
SLOW_SCAN threshold=15 window=300 severity=MEDIUM enabled=true
SENSITIVE_PORTS ports=22,23,445,3389 threshold=1 window=60 severity=MEDIUM enabled=true
CONNECTION_EXCESS threshold=200 window=60 severity=HIGH enabled=true
LARGE_PAYLOAD threshold=1400 window=60 severity=MEDIUM enabled=true
VOLUME_ANOMALY threshold=10000000 window=60 severity=HIGH enabled=true
HEURISTIC_RISK threshold=80 window=300 severity=HIGH enabled=true

[group web_servers]
targets=192.168.1.10,2001:db8::10
PORT_SCAN threshold=50 window=20 severity=MEDIUM enabled=true
```

Linhas de regras inválidas são ignoradas com avisos; os padrões embutidos permanecem ativos.

## Logs

Log de pacotes do sistema:

```text
[2026-05-12 19:30:00] [TCP] src=192.168.0.15:50122 dst=192.168.0.1:22 len=60 caplen=60
```

## SQLite Opcional

```bash
sudo apt install sqlite3 libsqlite3-dev
make sqlite
./specterids --pcap samples/example.pcap --sqlite data/lab.db
```

O binário normal continua compilando sem SQLite. Quando habilitado, o storage cria `sessions`, `packet_summary`, `alerts`, `detections` e `metrics`.

## Plugins Defensivos

```bash
make plugins
./specterids --pcap samples/example.pcap --plugin plugins/libspecter_portscan.so
sudo ./specterids -i eth0 --plugin-dir plugins
```

Plugins usam a ABI v2 de `include/plugin_api.h`, recebem apenas metadados
parseados e podem emitir alertas defensivos. Eles são opcionais e só carregam
quando explicitamente configurados.

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
  packets=12042 parsed=12040 drops=0 parse_errors=2 dropped_alerts=0 pps=286.67 mbps=1.832 alerts/min=4.29
  queues packet=0 parsed=0 log=1 | cpu=0.210s mem=9216KB
  latency avg parse=3.100us detection=12.400us logging=5.900us | queue_pressure=1
  alerts LOW=0 MEDIUM=2 HIGH=1 CRITICAL=0 total=3
  ip-family IPv4=11900 IPv6=130 ARP=10 malformed=2 shards=16
```

## Testes

```bash
make test
make fuzz
make benchmark
make integration-test
make regression-test
```

A suite de testes verifica:

- Parsing válido de regras
- Tratamento seguro de regras inválidas
- Alertas de varredura de portas
- Alertas de brute-force SSH
- Alertas de SYN flood
- Comportamento seguro do parser com pacotes truncados
- Fixtures IPv4/IPv6/TCP/UDP/ICMP/ICMPv6
- Regressão offline com PCAPs em `tests/pcaps/`
- Carregamento da ABI de plugins dinâmicos
- Comportamento produtor/consumidor da fila
- Semântica de pools de objetos
- Parser de configuração
- Entradas fuzzadas no parser
- Throughput sintético de detecção
- Comportamento do barramento de eventos e motor de correlação
- Tratamento seguro de containers PCAP corrompidos e vazios sem crash (`tests/test_pcap_errors.sh`)
- Replay offline interrompível por sinal mesmo com grandes intervalos entre pacotes

## Métricas

Ative um endpoint de métricas local somente leitura:

```bash
sudo ./specterids -i eth0 --metrics
sudo ./specterids -i eth0 --metrics 9090
curl http://127.0.0.1:9090/metrics
```

Exemplo:

```text
parser_latency_us{proto="all"} 3.210
detection_latency_us{module="all"} 12.400
correlation_latency_us 1.100
queue_depth{name="raw"} 0
queue_drops_total{name="pipeline"} 0
packets_malformed_total{proto="all"} 4
packets_dropped_total 0
storage_write_latency_us 42.000
storage_errors_total 0
memory_pool_utilization 0.125000
plugin_latency_us{name="all"} 2.500
heartbeat_total 2
uptime_seconds 12.500
throughput_pps 1234.000
shard_utilization{id="aggregate"} 1.125
```

## Arquitetura

```text
CLI/config -> rules -> capture/offline PCAP -> raw queue -> parser workers
                                                     -> parsed queue -> detection workers
                                                     -> log queue -> logger thread
                                                                    -> logs/JSONL/PCAP
                                                     -> stats/dashboard
                                                     -> async event bus/modules/plugins/storage
```

O parser extrai apenas metadados. O motor de detecção mantém janelas de tempo por origem e emite alertas quando os limiares são excedidos. O logger escreve texto estruturado e JSONL opcional. O SpecterIDS nunca modifica pacotes nem interage com sistemas remotos.

O comportamento de replay, modos de falha, consistência de desempenho e memória
em runtime está documentado em `docs/replay-determinism.md`,
`docs/failure-analysis.md`, `docs/performance-consistency.md` e
`docs/runtime-memory-behavior.md`.

### Fluxo de Pacotes

```text
pcap live/offline -> datalink -> IPv4/IPv6/ARP parser -> packet_info_t
                  -> detection shards/plugins -> correlation -> logger/outputs
```

### Fluxo de Eventos

```text
CaptureEvent -> DatalinkEvent -> PacketParsedEvent -> DetectionEvent
             -> CorrelationEvent -> AlertEvent -> OutputEvent
             -> StorageEvent -> MetricsEvent
```

Eventos assíncronos carregam snapshots próprios para evitar ponteiros pendurados
entre workers, storage e outputs.

### Modelo de Threads

- captura/replay alimenta uma fila bruta delimitada
- workers de parser produzem metadados seguros
- workers de detecção usam shards por IP de origem
- plugins dinâmicos rodam após as detecções internas por shard
- logger serializa escrita em arquivos
- event dispatcher entrega alertas para storage/outputs
- metrics server opcional expõe apenas leitura em localhost

## Benchmarks

```bash
make benchmark
```

O benchmark sintético escreve `benchmarks.md` e mede throughput do caminho
de detecção em ambiente local. Use os números como comparação entre builds, não
como promessa de desempenho em produção.

## Decisões de Design

- Filas delimitadas em vez de buffer ilimitado: sobrecarga se manifesta como drops visíveis, não como esgotamento de memória.
- Pools de objetos em vez de alocação no caminho de pacotes: uso de memória previsível durante picos.
- Detecção baseada em metadados: sinais defensivos úteis sem coleta de payload.
- Config/regras tolerantes: linhas inválidas geram avisos e recaem para padrões seguros.
- Escritor único para logs: rotação mais simples e menos contenção.
- Barramento de eventos assíncrono com payload próprio: assinantes recebem snapshots estáveis sem depender do ciclo de vida das filas de pacote.
- Estado de detecção em shards: reduz contenção mantendo ownership simples por IP de origem.
- ABI dinâmica v2 de plugins: permite ampliar detecções defensivas sem recompilar o core.

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
├── plugins/
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

- Suporte IPv6 cobre cabeçalhos básicos e extensões comuns de forma conservadora.
- Grupos de regras usam correspondência exata de IP de destino, não CIDR.
- A detecção é baseada em metadados e intencionalmente simples para fins educacionais.
- A detecção de beaconing foi reduzida com janela, média, tolerância, whitelist e opção de ignorar destinos privados, mas ainda é heurística.
- SQLite é opcional e armazena metadados, não payloads completos.
- Plugins dinâmicos são apenas de detecção e serializados pelo core por segurança.

## Roadmap

- Correspondência CIDR em grupos de regras.
- Sandboxing de plugins além da validação de ABI.
- Mais fixtures PCAP anonimizadas de laboratório autorizado.
- Validação opcional de checksums.

## Licença

Licença MIT. Veja `LICENSE`.

---

<a name="english"></a>
# 🇺🇸 English

SpecterIDS is a defensive, educational intrusion detection system written in C for Linux. It captures live traffic with `libpcap` or replays offline PCAP files, moves packets through a bounded threaded pipeline, parses Ethernet/Linux cooked/RAW, ARP, IPv4, IPv6, TCP, UDP, ICMP and ICMPv6 metadata, applies transparent detection rules and writes professional text, JSONL, optional PCAP forensic output and optional SQLite metadata for authorized lab monitoring.

## Ethical Use

Use SpecterIDS only on networks you own or have explicit permission to monitor. The project is defensive and educational. It does not exploit vulnerabilities, modify traffic, persist on systems, evade controls, steal data or perform offensive activity.

## Features

- Live packet capture through `libpcap`.
- Offline PCAP replay with `--pcap`, optional timing preservation, `--pcap-speed` and `--speed`.
- Safe IPv4/IPv6 parsing with truncation handling.
- Datalink abstraction for Ethernet, Linux cooked capture and RAW IP.
- Bounded threaded pipeline: capture thread, parser workers, detection workers and logger thread.
- Object pools to avoid packet-path `malloc/free`.
- Internal event bus for packet, detection, alert, output, reload and metrics events.
- Internal module interfaces plus opt-in defensive dynamic plugins via `dlopen`.
- Professional CLI with `--help`, `--version`, `--config`, `--rules`, `--bpf`, `--json`, `--dashboard`, `--verbose` and `--quiet`.
- Safe parser for Ethernet, VLAN-tagged Ethernet, ARP, IPv4, TCP, UDP and ICMP metadata.
- Config file support with CLI overrides.
- Rule file support with safe defaults and non-fatal warnings for invalid lines.
- Rule groups with IPv4/IPv6 destination targets.
- Sharded detection state via `--detection-shards`.
- Detection for scans, floods, sensitive ports, ARP spoofing, beaconing, high volume and heuristic risk.
- Text logs in `logs/specterids.log` and `logs/alerts.log`.
- Optional JSON Lines alerts in `logs/alerts.jsonl`.
- Optional suspicious packet export in `captures/suspicious.pcap`.
- Optional localhost Prometheus-style metrics endpoint.
- Optional SQLite export via `make sqlite` and `--sqlite data/specterids.db`.
- IPv6, shard pressure, plugin, storage, queue and pipeline latency metrics.
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
make sqlite
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
sudo ./specterids -i eth0 --dashboard-verbose --dashboard-interval 2 --no-color
sudo ./specterids -i eth0 --rules rules/default.rules
sudo ./specterids -i eth0 --config config/specterids.conf
sudo ./specterids -i eth0 --bpf "tcp or udp"
sudo ./specterids -i eth0 --json
sudo ./specterids -i eth0 --pcap-export
sudo ./specterids -i eth0 --metrics --metrics-port 9090
sudo ./specterids -i eth0 --metrics 9090
sudo ./specterids -i eth0 --detection-shards 16
kill -HUP <specterids-pid>
```

Offline replay does not require root:

```bash
./specterids --pcap samples/example.pcap
./specterids --pcap samples/example.pcap --json
./specterids --pcap samples/example.pcap --dashboard
./specterids --pcap samples/example.pcap --sqlite data/lab.db
./specterids --pcap samples/example.pcap --pcap-replay --pcap-speed 5x
./specterids --pcap samples/example.pcap --speed 10x
./specterids --pcap samples/example.pcap --benchmark
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
pcap_file=
pcap_replay=false
pcap_speed=1x
log_dir=logs
rules_file=rules/default.rules
json_logs=true
dashboard=false
verbose=false
quiet=false
bpf_filter=ip or ip6 or arp
workers=2
detection_shards=16
queue_size=1024
rotation_size_mb=32
sensitive_ports=22,23,445,3389,5900,8080
dashboard_refresh_ms=1000
dashboard_mode=detailed
pcap_export=false
metrics_enabled=false
metrics_port=9090
sqlite_enabled=false
sqlite_path=data/specterids.db
plugins_enabled=false
plugin_dir=plugins
# plugin=plugins/libspecter_portscan.so
no_color=false
```

CLI arguments override config file values:

```bash
sudo ./specterids --config config/specterids.conf -i wlan0 --dashboard --bpf "tcp"
```

## Detection Rules

Rules live in `rules/default.rules`:

```text
[group default]
PORT_SCAN threshold=20 window=10 severity=HIGH enabled=true
SSH_BRUTE_FORCE port=22 threshold=10 window=60 severity=HIGH enabled=true
SYN_FLOOD threshold=100 window=5 severity=CRITICAL enabled=true
ICMP_FLOOD threshold=100 window=5 severity=MEDIUM enabled=true
UDP_FLOOD threshold=200 window=10 severity=MEDIUM enabled=true
BEACONING min_hits=8 interval=30 tolerance=3 ignore_private=true severity=LOW enabled=true
ARP_SPOOFING severity=HIGH enabled=true
DNS_FLOOD threshold=150 window=10 severity=MEDIUM enabled=true
HTTP_FLOOD ports=80,443 threshold=300 window=10 severity=HIGH enabled=true
RATE_ANOMALY threshold=500 window=10 severity=MEDIUM enabled=true
SLOW_SCAN threshold=15 window=300 severity=MEDIUM enabled=true
SENSITIVE_PORTS ports=22,23,445,3389 threshold=1 window=60 severity=MEDIUM enabled=true
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

## Optional SQLite

```bash
sudo apt install sqlite3 libsqlite3-dev
make sqlite
./specterids --pcap samples/example.pcap --sqlite data/lab.db
```

When enabled, storage creates `sessions`, `packet_summary`, `alerts`,
`detections` and `metrics`.

## Defensive Plugins

```bash
make plugins
./specterids --pcap samples/example.pcap --plugin plugins/libspecter_portscan.so
sudo ./specterids -i eth0 --plugin-dir plugins
```

Plugins use `include/plugin_api.h`, receive parsed metadata only and can emit
defensive alerts. They are optional and load only when explicitly configured.

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
- IPv4/IPv6/TCP/UDP/ICMP/ICMPv6 fixtures
- offline PCAP regression under `tests/pcaps/`
- dynamic plugin ABI loading
- queue producer/consumer behavior
- object-pool acquire behavior
- config parser validation
- fuzzed parser inputs
- synthetic detection throughput
- event bus and correlation engine behavior
- safe handling of corrupt and empty PCAP containers without crashing (`tests/test_pcap_errors.sh`)
- offline replay remaining signal-interruptible across large inter-packet gaps

## Metrics

Enable a local read-only metrics endpoint:

```bash
sudo ./specterids -i eth0 --metrics
sudo ./specterids -i eth0 --metrics 9090
curl http://127.0.0.1:9090/metrics
```

Example:

```text
parser_latency_us{proto="all"} 3.210
detection_latency_us{module="all"} 12.400
correlation_latency_us 1.100
queue_depth{name="raw"} 0
queue_drops_total{name="pipeline"} 0
packets_malformed_total{proto="all"} 4
packets_dropped_total 0
storage_write_latency_us 42.000
storage_errors_total 0
memory_pool_utilization 0.125000
plugin_latency_us{name="all"} 2.500
heartbeat_total 2
uptime_seconds 12.500
throughput_pps 1234.000
shard_utilization{id="aggregate"} 1.125
```

## Architecture

```text
CLI/config -> rules -> capture/offline PCAP -> raw queue -> parser workers
                                                     -> parsed queue -> detection workers
                                                     -> log queue -> logger thread
                                                                    -> logs/JSONL/PCAP
                                                     -> stats/dashboard
                                                     -> async event bus/modules/plugins/storage
```

The parser extracts metadata only. The detection engine keeps per-source time windows and emits alerts when thresholds are exceeded. The logger writes structured text and optional JSONL. SpecterIDS never modifies packets or interacts with remote systems.

Replay behavior, failure modes, performance consistency and runtime memory
behavior are documented in `docs/replay-determinism.md`,
`docs/failure-analysis.md`, `docs/performance-consistency.md` and
`docs/runtime-memory-behavior.md`.

### Packet Flow

```text
pcap live/offline -> datalink -> IPv4/IPv6/ARP parser -> packet_info_t
                  -> detection shards/plugins -> correlation -> logger/outputs
```

### Event Flow

```text
CaptureEvent -> DatalinkEvent -> PacketParsedEvent -> DetectionEvent
             -> CorrelationEvent -> AlertEvent -> OutputEvent
             -> StorageEvent -> MetricsEvent
```

Async events carry owned snapshots to avoid dangling pointers across workers,
storage and outputs.

### Threading Model

- capture/replay feeds a bounded raw queue
- parser workers produce safe metadata
- detection workers use source-IP shards
- dynamic plugins run after built-in shard detection
- logger serializes file writes
- event dispatcher delivers alerts to storage/outputs
- optional metrics server exposes read-only localhost telemetry

## Benchmarks

```bash
make benchmark
```

The synthetic benchmark writes `benchmarks.md` and is intended for
build-to-build comparison, not as a production throughput guarantee.

## Design Decisions

- Bounded queues over unbounded buffering: overload becomes visible drops instead of memory exhaustion.
- Object pools over packet-path allocation: predictable memory use during bursts.
- Metadata-first detection: useful defensive signals without payload harvesting.
- Tolerant config/rules: invalid lines warn and fall back to safe defaults.
- Single writer for logs: simpler rotation and less contention.
- Async event bus with owned payload snapshots: subscribers are decoupled from packet queue lifetimes.
- Sharded detection state: less contention while preserving clear source-IP ownership.
- Dynamic plugin ABI v2: extend defensive detections without recompiling the core.

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
├── plugins/
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

- IPv6 extension parsing is conservative.
- Rule group targets are exact IP matches, not CIDR ranges.
- Detection is metadata-based and intentionally simple for education.
- Beaconing detection is improved but still heuristic.
- SQLite stores metadata summaries, not full packet payloads.
- Dynamic plugins are detection-only and serialized by the core for safety.

## Roadmap

- CIDR matching for rule groups.
- Plugin sandboxing beyond ABI validation.
- More authorized-lab PCAP regression fixtures.
- Optional checksum validation.

## License

MIT License. See `LICENSE`.
