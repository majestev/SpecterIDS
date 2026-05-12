# Event System

SpecterIDS includes a small in-process event bus for decoupling runtime components.

## Event Types

- `PACKET_CAPTURED`
- `PACKET_PARSED`
- `DETECTION_COMPLETE`
- `ALERT`
- `OUTPUT_WRITTEN`
- `METRICS`
- `RELOAD`
- `HEALTH`

## Dispatch Model

The event bus is synchronous and in-process. Subscribers register a handler for a specific event type. Publishing copies the current subscriber list under a mutex and invokes handlers outside the lock.

This keeps the design simple and avoids event-handler lock contention.

## Current Uses

- Capture pipeline publishes packet, detection, alert and output events.
- Output registry subscribes to alert/output events.
- Reload events are published after `SIGHUP` reloads rule thresholds.

## Extension Point

Future modules can subscribe to `ALERT` or `PACKET_PARSED` without modifying capture or detection core code.
