# LinkPulse Wire Protocol

Canonical source of truth: `tunnel-proxy/protocol.py`. `my_proxy_client/my_proxy.py`
carries a synchronized copy. Both ends must agree on framing and semantics.

## Overview

The client opens one TCP connection to the server's control port. Authentication,
tunnel registration, heartbeat, and every HTTP connection / TCP connection /
UDP peer travel over that connection as independently framed messages
distinguished by stream ID.

```
 0        2      3      4                 8                 12
+--------+------+------+-----------------+-----------------+
| Magic  | Ver  | Type |    Stream ID    |     Length      |
+--------+------+------+-----------------+-----------------+
|                   Payload (Length bytes)                  |
+-----------------------------------------------------------+
```

| Field | Size | Details |
|-------|------|---------|
| Magic | 2 | ASCII `"TN"` (`0x54 0x4E`) |
| Version | 1 | Protocol version, currently `1` |
| Type | 1 | `FrameType` value |
| Stream ID | 4 | Unsigned big-endian; `0` = control channel |
| Length | 4 | Unsigned big-endian payload size |
| Payload | var | Depends on `Type` |

Rules:

- Header is always 12 bytes, network byte order.
- `Length` must not exceed 16 MiB (16,777,216); larger frames are rejected
  before allocating the payload.
- `STREAM_DATA` payloads are capped at 64 KiB even though the frame format
  permits more.
- An unknown version, bad magic, or oversized length is a fatal protocol error
  on that connection.

## Frame types

| Value | Name | Direction | Payload |
|-------|------|-----------|---------|
| 0x01 | HELLO | client → server | 72-byte auth payload |
| 0x02 | HELLO_OK | server → client | JSON `{client_id, heartbeat_interval, server_version, capabilities?}` |
| 0x03 | HELLO_FAIL | server → client | JSON `{error}` (connection closes) |
| 0x04 | PING | either | empty |
| 0x05 | PONG | either | empty |
| 0x06 | TUNNEL_OPEN_REQUEST | client → server | JSON (see below) |
| 0x07 | TUNNEL_OPEN_RESPONSE | server → client | JSON |
| 0x08 | TUNNEL_CLOSE | either | JSON `{tunnel_id, reason?, message?}` |
| 0x09 | STREAM_OPEN | server → client | JSON `{tunnel_id, proto, remote_addr}` |
| 0x0A | STREAM_DATA | either | raw bytes (≤ 64 KiB) |
| 0x0B | STREAM_CLOSE | either | empty — abort/full close |
| 0x0C | STREAM_WINDOW_UPDATE | either | 4-byte unsigned big-endian credit |
| 0x0D | ERROR | either | JSON `{error}` |
| 0x0E | UDP_DATAGRAM | either | one complete datagram |
| 0x0F | STREAM_EOF | either | empty — half-close (capability-gated) |

`STREAM_EOF` is an optional extension. `UDP_DATAGRAM` is the UDP data type.
For compatibility with older implementations, a UDP peer may also receive
`STREAM_DATA`; current peers should tolerate it by forwarding the bytes as a
datagram payload rather than treating the frame as unknown.

## Authentication (HELLO)

Payload, exactly 72 bytes:

```
client_id : 16 bytes  (all-zero = "assign me a new identity")
timestamp : 8 bytes   (unsigned big-endian Unix seconds)
nonce     : 16 bytes  (random, single use)
hmac      : 32 bytes  HMAC-SHA256(secret, client_id || timestamp || nonce)
```

Process:

1. Client loads its persisted `client_id` (or sends zeros on first connect),
   gets the current Unix time, and generates a fresh nonce.
2. Client sends HELLO with the HMAC.
3. Server checks:
   - `|now - timestamp| <= 60` seconds;
   - HMAC matches (constant-time comparison);
   - `(client_id, nonce)` has not been seen within the skew window.
4. Server replies HELLO_OK (assigning a `client_id` if the request was
   all-zero) or HELLO_FAIL and closes.

This is **one-way** authentication: it proves possession of the secret and
prevents replay, but there is no server challenge and no confidentiality.
Enable native control TLS (`CONTROL_TLS=true` on the server, `--tls` on the
client with mandatory certificate verification) or run over a private network.
Public HTTPS does not protect this leg.

Replay state is pruned after the timestamp validity window, so a captured
HELLO stays rejected for the whole window but is not remembered forever.

## Capabilities

HELLO_OK may include an optional `capabilities` array. The server advertises:

```json
{ "client_id": "...", "heartbeat_interval": 20, "server_version": 1,
  "capabilities": ["stream_eof"] }
```

When the client sees `stream_eof`, it may include the same capability in each
`TUNNEL_OPEN_REQUEST`:

```json
{ "tunnel_id": "...", "type": "http", "capabilities": ["stream_eof"] }
```

`STREAM_EOF` is used only when both sides advertised the capability. Otherwise
the connection keeps the legacy behavior: end-of-data is signalled with an
abortive `STREAM_CLOSE`, which tears down both directions.

## Multiplexing

Stream 0 is the control plane. Every other stream ID (allocated by the server,
monotonically increasing with wraparound) represents one proxied connection:

- HTTP: one stream per public TCP connection (which may carry keep-alive
  requests).
- TCP: one stream per incoming public TCP connection.
- UDP: one stream per distinct public peer address.

Frames from different streams may be interleaved freely.

## Flow control

Each stream has independent per-direction credit:

- Both sides start with a 256 KiB send window per stream.
- Before sending `STREAM_DATA`, the sender must hold credit ≥ 1 byte and
  consumes credit equal to the payload size.
- The receiver sends `STREAM_WINDOW_UPDATE` after flushing data onward; this
  implementation batches updates at roughly 128 KiB.
- A sender with zero credit waits instead of buffering without bound.
- Credit is capped at 512 KiB (`MAX_WINDOW_CREDIT`, twice the initial window)
  so a malicious peer cannot inflate the window arbitrarily.

`UDP_DATAGRAM` does **not** consume TCP stream credit. Per-stream queues and
session/global limits bound memory. Streams share one TCP connection, so a
large frame or blocked write can still cause head-of-line delay; per-stream
flow control does not remove TCP's own ordering behaviour.

## Tunnel lifecycle

### TUNNEL_OPEN_REQUEST (client → server)

```json
{
  "tunnel_id": "uuid-hex",
  "type": "http" | "tcp" | "udp",
  "mode": "handoff" | "lease",
  "instance_id": "hex",
  "capabilities": ["stream_eof"],
  "subdomain": "app",
  "remote_port": 20000
}
```

- `tunnel_id` is client-generated and stable across reconnects. Re-requesting
  the same ID after a reconnect means “resume my logical tunnel”.
  A duplicate ID does not create a second name/listener; conflicting/duplicate
  claims are rejected safely.
- `mode` is optional (default `handoff`); unknown values are rejected.
- `instance_id` is per client process. `client_id` is shared machine-wide, so
  the pair `(client_id, instance_id)` distinguishes a reconnect from a second
  competing process.
- `subdomain` (HTTP) may be omitted; the server assigns one and returns it.
- `remote_port` (TCP/UDP) may be omitted; the server allocates from its range.

### TUNNEL_OPEN_RESPONSE (server → client)

```json
{
  "tunnel_id": "uuid-hex",
  "status": "ok" | "error",
  "type": "http" | "tcp" | "udp",
  "mode": "handoff" | "lease",
  "subdomain": "app",
  "public_url": "https://app.example.com",
  "public_host": "example.com",
  "remote_port": 20000,
  "error": "reason",
  "reason": "leased" | "in_use" | "exhausted" | "invalid"
}
```

On success the client stores the granted `subdomain` (including an
auto-assigned one) so the URL survives reconnects. Failed registrations should
be retried; names become available when an owner disconnects, a lease session
ends, or ports free up.

### TUNNEL_CLOSE

```json
{ "tunnel_id": "uuid-hex", "reason": "handoff" | "reclaimed" | "...", "message": "..." }
```

Client → server closes carry only `tunnel_id`. Server → client closes are
revocations:

| reason | meaning | client reaction |
|--------|---------|-----------------|
| `handoff` | Another client claimed the name in handoff mode | Report, stop serving, exit if nothing left |
| `reclaimed` | Same client process reconnected and took its own registration back | Ignore; the matching open response re-establishes it |

Any in-flight streams for the tunnel are aborted.

## Ownership modes

| Mode | When the name is already registered |
|------|-------------------------------------|
| `handoff` (default) | Newcomer wins. Current owner gets `TUNNEL_CLOSE reason="handoff"`, its streams abort, newcomer gets the name. |
| `lease` | Newcomer refused with `status="error", reason="leased"`. A lease request over an in-use name is refused with `reason="in_use"`; a lease never takes over. |

Identity exceptions:

- A reconnect of the same client process (same `client_id` and
  `instance_id`; an older client with no `instance_id` is treated permissively)
  reclaims its own registration, even a lease. The old registration is closed;
  `reason="reclaimed"` is sent only if it lived on a different connection.
- A different `instance_id` is a competitor, not a reconnect: refused by a
  lease, able to take over in handoff mode.

A lease lives only as long as the owning session. It is not permanent and is
not extended by HTTP reconnect waiting.

## Stream lifecycle

### STREAM_OPEN (server → client)

```
Frame header: stream_id = allocated_id
Payload: JSON { "tunnel_id": "...", "proto": "http" | "tcp" | "udp",
                "remote_addr": "ip:port" }
```

For HTTP/TCP the client connects to the local backend, then pumps bytes both
ways. If the backend cannot be reached it sends `STREAM_CLOSE` (an abort; no
half-close is attempted) and the tunnel stays registered.

For UDP the client opens a datagram endpoint to the local backend for that
stream and forwards complete datagrams.

### STREAM_DATA

Raw bytes, ≤ 64 KiB per frame, subject to credit. The sender must not send more
than the receiver's window.

### STREAM_EOF (optional, capability-gated)

Empty payload. Signals that the sender will write no more data on this stream,
while the receiver may still send in the opposite direction. The stream is
fully closed once both directions have finished. If either peer did not
advertise `stream_eof`, `STREAM_EOF` is not sent.

### STREAM_CLOSE

Empty payload. Abortive/full close: the peer stops using the stream and closes
the corresponding socket/endpoint. This is the legacy semantics and remains the
fallback when half-close is not negotiated.

### STREAM_WINDOW_UPDATE

4-byte unsigned big-endian increment. Restores send credit for the peer.

### UDP_DATAGRAM

Payload is exactly one complete UDP datagram, preserving datagram boundaries.
An empty payload is a valid (zero-length) datagram. The maximum payload is
65507 bytes. UDP frames do not consume TCP stream credit. A stream maps one
public peer to one local datagram endpoint; an idle peer is expired after the
configured `UDP_IDLE_TIMEOUT`, and the number of peers per tunnel is capped.

## Heartbeat and inactivity

- The server sends PING every `heartbeat_interval` seconds (default 20, sent in
  HELLO_OK).
- PONG (or any frame) refreshes the peer's last-seen timer.
- No frame within `heartbeat_timeout` (default 60 s) means the connection is
  considered dead and is closed.
- The client also runs an inactivity watchdog (~3× heartbeat interval) so a
  silently dropped path triggers a reconnect.

## Reconnect semantics

- The client persists `client_id` and presents it on every HELLO; the server
  recognizes the same machine.
- Public names are not reserved ahead of time. The client re-requests the same
  `tunnel_id`/subdomain/port; if free it gets them back, otherwise the
  ownership mode decides.
- **In-flight streams are not resumed.** A control connection drop aborts open
  streams and their sockets. WebSockets, in-flight HTTP requests and partial
  bodies cannot be resumed; no retransmit buffer or sequence-number scheme
  exists.
- The client retries the connection and failed registrations indefinitely
  (every 5 s by default).
- For a short period after an unexpectedly dropped HTTP owner, the server may
  park new request heads and sockets and forward them to the reconnected
  owner (or the current legitimate owner). It does not accumulate, spool, or
  replay a request body at the application level; only normal bounded TCP
  receive buffering/backpressure applies. A waiting request is not a name
  reservation or lease extension. Unknown names → 404; an expired wait/queue overflow → 503
  (`Retry-After: 2`). Grace `0` disables the wait.

## Errors

| Condition | Behaviour |
|-----------|-----------|
| Bad magic / version / oversized length | Fatal protocol error; close connection |
| HELLO_FAIL | Server closes; client exits (bad secret is not retried) |
| ERROR frame | Soft report; does not tear down the connection |
| Heartbeat timeout | Connection closed; client reconnects |
| Local backend unreachable | Per-request failure; tunnel stays registered |
| Unknown/invalid tunnel type or mode | `TUNNEL_OPEN_RESPONSE` error with `reason="invalid"` |
| Name unavailable | Error with `reason="leased"`/`"in_use"`/`"exhausted"`; client retries |

## Limits

Server-side defaults (environment-tunable): `MAX_CLIENTS=128`,
`MAX_TUNNELS_PER_CLIENT=32`, `MAX_STREAMS_PER_CLIENT=256`,
`MAX_PENDING_HTTP_CONNECTIONS=256`, `UDP_MAX_PEERS_PER_TUNNEL=128`,
`UDP_IDLE_TIMEOUT=60` s, `STREAM_WRITE_TIMEOUT=30` s.

## Versioning and extensibility

- `Version` is currently always `1`; an unknown version is rejected.
- New frame types can be added; unknown types are logged and ignored rather
  than fatal where safe.
- JSON payloads may gain optional fields without a version bump, and
  capabilities negotiate optional behaviour.
- Peers must not assume features; capability negotiation and graceful fallback
  are the compatibility mechanism.

## Implementation checklist

- [ ] Frame parse: magic, version, big-endian length, 16 MiB ceiling
- [ ] HELLO: exactly 72 bytes; HMAC over `client_id || timestamp || nonce`;
      timestamp skew and nonce replay checks
- [ ] Capabilities: advertise/echo `stream_eof`; fall back otherwise
- [ ] Flow control: per-stream, per-direction, 256 KiB initial window
- [ ] `STREAM_DATA` chunking at 64 KiB
- [ ] Multiplexing: interleave frames from different streams
- [ ] Ownership: store per-tunnel mode; handoff evicts, lease refuses; treat
      `(client_id, instance_id)` as a reconnect
- [ ] UDP: datagram boundaries, empty datagrams, 65507 ceiling, no credit
- [ ] Half-close: directional EOF keeps the other direction until both finish
- [ ] Reconnect: persist identity, re-request tunnels, retry forever, never
      resume streams
- [ ] Errors: malformed frames fatal; auth failure not retried