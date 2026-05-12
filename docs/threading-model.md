# Threading Model

## Threads

- Capture thread: owns the `pcap_t` handle and pushes raw packet objects.
- Parser workers: parse raw packet objects into metadata.
- Detection workers: run the detection engine and create log events.
- Logger thread: writes packet logs, alert logs, JSONL and suspicious PCAP exports.
- Metrics thread: optional localhost HTTP endpoint for `/metrics`.

## Synchronization

- `ids_queue_t` uses one mutex and two condition variables per queue.
- `ids_pool_t` reuses `ids_queue_t` as a free-object list.
- The detection engine has a lock around mutable per-IP state.
- Logger writes are serialized by the logger mutex.
- Stats use a small mutex-protected aggregate.
- Event bus copies subscriber lists under lock and invokes handlers outside the lock.

## Shutdown

`SIGINT` and `SIGTERM` set a `sig_atomic_t` stop flag. The capture thread stops after the next `pcap_dispatch()` timeout, closes the raw queue, workers drain queued items, then downstream queues close in order.

## Design Tradeoffs

The current detection engine still uses a global engine lock for simplicity and correctness. The pipeline removes logging and parsing from that lock, which is the highest value performance improvement. A future version can shard detection state by source-IP hash to reduce lock contention further.

The event bus is synchronous and in-process. This avoids the complexity of a second asynchronous event pipeline while still providing a clean extension boundary.
