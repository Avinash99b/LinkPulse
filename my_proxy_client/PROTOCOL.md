# Wire Protocol Specification

This is the **canonical wire protocol** that both `proxy_server.py` and `my_proxy` implement exactly. Client developers must follow this specification precisely for interoperability.

## Overview

One TCP connection ("the control connection") is opened by the client to the server and kept open indefinitely. Every logical thing that needs to happen -- authentication, registering tunnels, and every individual public HTTP request or TCP connection -- travels over that single connection as independently-framed messages, distinguished by a stream ID.

## Frame layout

Every message is a frame with a 12-byte fixed header followed by a variable-length payload:

```
 0        2      3      4                 8                 12
 +--------+------+------+-----------------+-----------------+
 | Magic  | Ver  | Type |    Stream ID     |     Length      |
 +--------+------+------+-----------------+-----------------+
 |                    Payload (Length bytes)                 |
 +-------------------------------------------------------------+
```

| Field     | Size | Details |
|-----------|------|---------|
| Magic     | 2    | ASCII `"TN"` (0x54 0x4E). Resynchronization marker. |
| Version   | 1    | Protocol version, currently `1`. |
| Type      | 1    | `FrameType` enum value (see below). |
| Stream ID | 4    | Unsigned big-endian. `0` = control channel. |
| Length    | 4    | Unsigned big-endian. Payload size in bytes. |
| Payload   | var  | Meaning depends on `Type`. |

**Invariants:**
- Header is fixed 12 bytes, always in network (big-endian) byte order.
- `Length` ≤ 16 MiB (clients/servers must reject frames claiming larger payloads).
- `STREAM_DATA` payloads are capped at 64 KiB, even if the frame format allows larger.

## Frame types

| Value | Name                  | Direction        | Payload                                    |
|-------|-----------------------|-------------------|-------------------------------------------|
| 0x01  | HELLO                 | client → server   | binary auth payload (72 bytes)             |
| 0x02  | HELLO_OK              | server → client   | JSON `{client_id, heartbeat_interval, ...}` |
| 0x03  | HELLO_FAIL            | server → client   | JSON `{error}` (connection closes after)   |
| 0x04  | PING                  | either            | empty                                      |
| 0x05  | PONG                  | either            | empty                                      |
| 0x06  | TUNNEL_OPEN_REQUEST   | client → server   | JSON `{tunnel_id, type, subdomain?, remote_port?}` |
| 0x07  | TUNNEL_OPEN_RESPONSE  | server → client   | JSON `{tunnel_id, status, ...}`            |
| 0x08  | TUNNEL_CLOSE          | either            | JSON `{tunnel_id}`                         |
| 0x09  | STREAM_OPEN           | server → client   | JSON `{tunnel_id, proto, remote_addr}`, stream ID in header |
| 0x0A  | STREAM_DATA           | either            | raw bytes (≤ 64 KiB)                       |
| 0x0B  | STREAM_CLOSE          | either            | empty                                      |
| 0x0C  | STREAM_WINDOW_UPDATE  | either            | 4 bytes, unsigned big-endian byte credit   |
| 0x0D  | ERROR                 | either            | JSON `{error}`                             |

## Authentication (HELLO)

The HELLO frame payload is 72 bytes, structured as:

```
client_id : 16 bytes  (all-zero == "assign me a new identity")
timestamp : 8 bytes   (unsigned big-endian unix time, seconds)
nonce     : 16 bytes  (random, single-use)
hmac      : 32 bytes  HMAC-SHA256(secret, client_id || timestamp || nonce)
```

**Process:**
1. Client generates or loads its persistent client_id (UUID, 16 bytes). First time is all-zero.
2. Client gets current unix timestamp and a fresh random nonce.
3. Client computes `HMAC = HMAC-SHA256(shared_secret, client_id || timestamp || nonce)` where `||` is concatenation.
4. Client sends HELLO frame with this payload.
5. Server verifies:
   - Timestamp is within 60 seconds of server's clock (bounds replay window)
   - HMAC matches (constant-time comparison)
   - `(client_id, nonce)` hasn't been seen before in this skew window (prevents replay)
6. Server either sends HELLO_OK (with an assigned client_id if the request had all-zero) or HELLO_FAIL.
7. If HELLO_FAIL, connection closes immediately.

**Security note:** This scheme proves possession of the secret and prevents replay, but does **not** provide confidentiality of tunneled data. For production, either:
- Enable TLS on the control channel (`control.tls: true` in server config), or
- Run the control connection over a private network (VPN, WireGuard, SSH tunnel).

## Multiplexing

Stream ID = 0 is reserved for control-plane frames (HELLO, PING, TUNNEL_OPEN_*, etc.).

Every other stream ID (1 to 2^32-1, allocated by server, monotonically increasing with wraparound) represents one proxied connection:
- For HTTP: one stream = one TCP connection to the public HTTPS listener
- For TCP: one stream = one incoming TCP connection to a public port

Frames for different streams can be interleaved freely on the wire.

## Flow control

Each stream has an independent, per-direction, credit-based flow-control window:

- Each side starts with **256 KiB** of *send* credit toward the peer, per stream
- Before sending STREAM_DATA, sender must have available credit ≥ 1 byte; it consumes credit equal to payload size
- Receiver, once it has flushed the data onward, sends STREAM_WINDOW_UPDATE back with an increment restoring credit
- In this implementation, increments are batched: updates sent once ≥ 128 KiB unacknowledged
- If window reaches zero, sender blocks (awaits STREAM_WINDOW_UPDATE) rather than buffering unboundedly

This gives simple, symmetric backpressure without per-request buffering.

## Tunnel lifecycle

### TUNNEL_OPEN_REQUEST (client → server)

```json
{
  "tunnel_id": "uuid-hex",
  "type": "http" | "tcp",
  "subdomain": "app",     // http only, optional
  "remote_port": 20000    // tcp only, optional
}
```

- `tunnel_id` is client-generated and persistent across reconnects (same tunnel_id after reconnect = resume that tunnel)
- `type` is required; "http" or "tcp"
- `subdomain` (http only): client requests a specific subdomain. If omitted or taken, server assigns one.
- `remote_port` (tcp only): client requests a specific port. If omitted or taken, server assigns one.

### TUNNEL_OPEN_RESPONSE (server → client)

```json
{
  "tunnel_id": "uuid-hex",
  "status": "ok" | "error",
  "type": "http" | "tcp",
  "public_url": "https://app.forwarding.example.com",  // http only, if ok
  "public_host": "forwarding.example.com",              // tcp only, if ok
  "remote_port": 20000,                                 // tcp only, if ok
  "error": "reason for failure"                         // if error
}
```

### TUNNEL_CLOSE (either direction)

```json
{
  "tunnel_id": "uuid-hex"
}
```

Unregisters the tunnel. The tunnel is freed for reuse. Any in-flight streams for this tunnel are aborted.

## Stream lifecycle

### STREAM_OPEN (server → client)

When the server accepts a new public connection destined for a tunnel, it allocates a stream ID and sends:

```
Frame header: stream_id = allocated_id
Payload: JSON { "tunnel_id": "...", "proto": "http|tcp", "remote_addr": "ip:port" }
```

Client must:
1. Connect to the local backend (host:port from tunnel spec)
2. If connection succeeds: register a stream and start pumping data in both directions
3. If connection fails (refused, timeout): send STREAM_CLOSE immediately

### STREAM_DATA (either direction)

Raw bytes. Payload ≤ 64 KiB. Respects flow control windows.

### STREAM_CLOSE (either direction)

Empty payload. Sent when one side has finished (EOF from local backend, or error). The other side should close its corresponding socket and stop using the stream.

### STREAM_WINDOW_UPDATE (either direction)

4-byte unsigned big-endian increment. Sent after flushing received data to restore send credit for the peer.

## Heartbeat

- Server sends PING every `heartbeat_interval_seconds` (default 20s, sent in HELLO_OK)
- Peer responds with PONG (or any frame can refresh the "last seen" timer)
- If no frame received for `heartbeat_timeout_seconds` (default 60s), peer considers connection dead and disconnects

## Reconnect semantics

- Client persists its `client_id` and presents it on every future HELLO
- Server recognizes it as the same client (not a new one)
- Subdomains/ports are *not* "reserved" — they're granted to whichever client currently asks for them
  - A client wanting a stable public URL re-requests the same `subdomain` or `remote_port` on reconnect
  - If no one else claimed it, client gets it back automatically
- **In-flight streams are NOT resumed**: if control connection drops, open streams are aborted (their sockets closed). Full resumption would require sequence numbers, retransmit buffers, and significantly more state. For a self-hosted tool, occasional dropped requests on reconnect are acceptable.
- If a HELLO arrives for a `client_id` that already has a live session (race), server tears down the old session before accepting the new one

## Error handling

**Malformed frames** (bad magic, oversized length):
- Raise ProtocolError, close connection, client reconnects with backoff

**Authentication failure (HELLO_FAIL)**:
- Server closes connection immediately
- Client exits (not retried; wrong secret can't be fixed by retrying)

**ERROR frame**:
- Generic soft error report; doesn't tear down the connection

**Heartbeat timeout**:
- Either side closes connection and cleans up
- Client enters reconnect loop with backoff

**Local service unreachable (STREAM_OPEN received, connection to backend fails)**:
- Client sends STREAM_CLOSE immediately
- Tunnel remains active (per-request failure, not tunnel-level)

## Version and extensibility

- `Version` byte is currently always `1`
- New frame types can be added; unknown types are logged/ignored (not fatal)
- JSON payloads can gain new optional fields without a version bump (forward-compatible)
- Future version changes would dispatch on the `Version` byte before interpreting `Type`

---

## Implementation checklist

When implementing a client or alternative server:

- [ ] Frame parsing: struct.unpack/pack with big-endian byte order
- [ ] Magic bytes check (must be `b"TN"`)
- [ ] Length ceiling enforcement (reject > 16 MiB)
- [ ] HELLO payload: 72 bytes, HMAC-SHA256 over (client_id || timestamp || nonce)
- [ ] Flow control windows: per-stream, independent directions, credit-based
- [ ] STREAM_DATA chunking: split payloads > 64 KiB into multiple frames
- [ ] Multiplexing: interleave frames from different streams freely
- [ ] Reconnect: client persists client_id, re-requests same tunnels
- [ ] Graceful shutdown: close tunnels cleanly before disconnecting
- [ ] Error handling: malformed frames are fatal; auth failures don't retry

Refer to `my_proxy` (client) and `proxy_server.py` (server) in this project for reference implementations.
