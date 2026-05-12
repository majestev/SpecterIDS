# Packet Flow

SpecterIDS now uses a bounded threaded pipeline.

```text
libpcap
  |
  v
capture thread
  |
  v
raw packet queue
  |
  v
parser workers
  |
  v
parsed packet queue
  |
  v
detection workers
  |
  v
log event queue
  |
  v
logger thread -> text logs / JSONL / suspicious PCAP
```

## Hot Path

The capture callback copies at most `snaplen` bytes into a pooled raw packet object. If the queue or pool is exhausted, the packet is dropped and the drop counter increases instead of blocking the capture path indefinitely.

Parser workers convert raw bytes into `packet_info_t` metadata. Detection workers apply stateful rules and emit alert objects. The logger thread is the only thread that writes log files, which avoids log-file lock contention in the detection path.

## Backpressure

Queues are bounded. The capture side uses non-blocking enqueue to prefer controlled drops over unbounded memory growth. Parser, detection and logger stages use blocking queues during normal drain.

## Forensics

When suspicious PCAP export is enabled, the logger keeps a small ring of recent packets and writes context packets to `captures/suspicious.pcap` when alerts occur.
