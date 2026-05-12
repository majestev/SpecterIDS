# Memory Management

SpecterIDS avoids packet-path allocation by using fixed-size object pools.

## Pools

- raw packet pool: stores bounded packet bytes plus capture metadata.
- parsed packet pool: stores `packet_info_t` and ownership of a raw object.
- log event pool: stores parsed packet ownership and alert arrays.

Pool capacity follows `queue_size`. The default is 1024.

## Limits

- `SPECTERIDS_MAX_PACKET_BYTES`: maximum copied bytes per packet.
- `SPECTERIDS_MAX_ALERTS_PER_PACKET`: alert burst cap per packet.
- `SPECTERIDS_MAX_SENSITIVE_PORTS`: bounded sensitive-port config.
- fixed event windows in detection state to avoid unbounded per-IP growth.

## Failure Behavior

When pools or queues are exhausted, SpecterIDS drops packets and increments drop counters. It does not allocate unbounded memory to catch up.

## Ownership

Raw packet ownership moves from capture to parser, then to detection/log events, and finally back to the raw pool after the logger thread finishes. Parsed and log event objects follow the same acquire/use/release lifecycle. This keeps ownership explicit and avoids hidden frees across modules.
