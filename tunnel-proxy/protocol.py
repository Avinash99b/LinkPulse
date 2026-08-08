"""
protocol.py -- Canonical message protocol for the WebSocket tunnel proxy.

The WebSocket transport (see ws.py) provides framing, ordering, keep-alive
and fragmentation, so this module defines everything that sits on top of
it: JSON control-message constants, binary stream-data framing, flow
control thresholds, and the HMAC-based HELLO authentication payload.

Both the server (proxy_server.py) and any client implementation MUST use
an identical copy of this logic (or a faithful re-implementation) to
interoperate.

Transport model
---------------
Client and server exchange WebSocket messages on a single connection:

  * text messages   = UTF-8 JSON control messages ({...})
  * binary messages = stream data: [stream_id u32be][payload...]

One WebSocket connection replaces the old custom binary TCP protocol and
carries all control-plane traffic: authentication, tunnel lifecycle,
per-stream multiplexing and flow control.

Authentication
--------------
The first message a client sends MUST be a text message:

    {"type": "hello", "sign": "<hex of 72-byte HMAC payload>"}

where the 72-byte payload is built with build_hello_payload(secret,
client_id).  It proves knowledge of the shared secret with replay
protection, exactly like the previous protocol (see below).

Control messages
----------------
client -> server:
    {"type": "hello", "sign": <hex>}
    {"type": "open_tunnel", "tunnel_id": <str>, "kind": "http"|"tcp",
     "subdomain": <str|None>, "remote_port": <int|None>}
    {"type": "close_tunnel", "tunnel_id": <str>}
    {"type": "close_stream", "stream_id": <int>}
    {"type": "window_update", "stream_id": <int>, "increment": <int>}
    {"type": "error", "message": <str>}

server -> client:
    {"type": "hello_ok", "client_id": <hex>, "heartbeat_interval": <int>, "server_version": 1}
    {"type": "hello_fail", "message": <str>}
    {"type": "open_tunnel_response", "tunnel_id": <str>, "status": "ok"|"error",
     "type": ..., "public_url": <str|None>, "remote_port": <int|None>, "error": <str|None>}
    {"type": "stream_open", "stream_id": <int>, "tunnel_id": <str>,
     "proto": "http"|"tcp", "remote_addr": <str>}
    {"type": "close_stream", "stream_id": <int>}
    {"type": "window_update", "stream_id": <int>, "increment": <int>}
    {"type": "error", "message": <str>}
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
import uuid

# ---------------------------------------------------------------------------
# Endpoint / transport
# ---------------------------------------------------------------------------

# Path the HTTP server exposes the WebSocket control-plane endpoint on.
DEFAULT_WS_PATH = "/ws"

# Version reported to clients in hello_ok.
SERVER_VERSION = 1

# ---------------------------------------------------------------------------
# Flow control / framing thresholds (kept from the binary protocol)
# ---------------------------------------------------------------------------

# A single stream-data WebSocket binary message is capped so a burst can't
# hog the connection and starve other streams (head-of-line blocking).
MAX_FRAME_PAYLOAD = 64 * 1024  # 64 KiB per stream-data chunk

# Initial per-stream flow-control window (bytes each side may send before
# it must wait for a window_update). See FlowWindow in proxy_server.py.
INITIAL_WINDOW = 256 * 1024

# If a stream-data binary message or a hand-rolled chunk exceeds this,
# treat it as a protocol error instead of buffering unbounded memory.
MAX_STREAM_MESSAGE = 16 * 1024 * 1024  # 16 MiB

# After how many received-but-unacknowledged bytes a side re-sends credit.
WINDOW_UPDATE_THRESHOLD = INITIAL_WINDOW // 2


# ---------------------------------------------------------------------------
# HELLO authentication payload (binary, HMAC-SHA256)
# ---------------------------------------------------------------------------
#
#   client_id : 16 bytes. All-zero == "assign me a new identity".
#   timestamp : 8 bytes, unsigned big-endian unix time (seconds).
#   nonce     : 16 bytes, random, single-use.
#   hmac      : 32 bytes, HMAC-SHA256(secret, client_id || timestamp || nonce)
#
# Total payload size: 16 + 8 + 16 + 32 = 72 bytes. Serialized as lowercase
# hex inside the `sign` JSON field so it can ride inside a text frame.

_HELLO_FMT = "!16sQ16s32s"
HELLO_PAYLOAD_LEN = struct.calcsize(_HELLO_FMT)
NULL_CLIENT_ID = b"\x00" * 16
HELLO_TIMESTAMP_SKEW_SECONDS = 60


def build_hello_payload(secret: str, client_id_bytes: bytes = NULL_CLIENT_ID) -> bytes:
    """Build a HELLO payload. Used by clients (and by our own tests)."""
    ts = int(time.time())
    nonce = secrets.token_bytes(16)
    mac = hmac.new(
        secret.encode("utf-8"),
        client_id_bytes + struct.pack("!Q", ts) + nonce,
        hashlib.sha256,
    ).digest()
    return struct.pack(_HELLO_FMT, client_id_bytes, ts, nonce, mac)


def _check_hello_len(payload: bytes) -> bool:
    return len(payload) == HELLO_PAYLOAD_LEN


def verify_hello_payload(payload: bytes, secret: str, seen_nonces: dict):
    """Validate a HELLO payload.

    `seen_nonces` is a dict of (client_id_bytes+nonce) -> timestamp used for
    replay protection; the caller is responsible for periodically pruning
    entries older than HELLO_TIMESTAMP_SKEW_SECONDS.

    Returns (ok, client_id_hex_or_None, error_reason_or_None).
    """
    if not _check_hello_len(payload):
        return False, None, "malformed HELLO payload"

    client_id_bytes, ts, nonce, mac = struct.unpack(_HELLO_FMT, payload)

    now = int(time.time())
    if abs(now - ts) > HELLO_TIMESTAMP_SKEW_SECONDS:
        return False, None, "timestamp outside allowed skew"

    expected = _hmac(secret, client_id_bytes + struct.pack("!Q", ts) + nonce)
    if not hmac.compare_digest(mac, expected):
        return False, None, "invalid signature"

    nonce_key = client_id_bytes + nonce
    if nonce_key in seen_nonces:
        return False, None, "replayed nonce"
    seen_nonces[nonce_key] = now

    if client_id_bytes == NULL_CLIENT_ID:
        client_id_bytes = uuid.uuid4().bytes

    return True, client_id_bytes.hex(), None


def _hmac(secret: str, msg: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Stream-data binary framing
# ---------------------------------------------------------------------------

_STREAM_DATA_FMT = "!I"
_STREAM_DATA_HEADER = struct.calcsize(_STREAM_DATA_FMT)  # 4
MAX_WINDOW_PAYLOAD = MAX_STREAM_MESSAGE - _STREAM_DATA_HEADER


def encode_stream_data(stream_id: int, payload: bytes) -> bytes:
    """Wrap one chunk of stream payload for a WebSocket binary message."""
    if len(payload) > MAX_STREAM_MESSAGE:
        raise ValueError("stream data chunk exceeds MAX_STREAM_MESSAGE")
    return struct.pack(_STREAM_DATA_FMT, stream_id) + bytes(payload)


def parse_stream_data(data: bytes):
    """Unpack a binary WebSocket message into (stream_id, payload)."""
    if len(data) < _STREAM_DATA_HEADER or len(data) > _STREAM_DATA_HEADER + MAX_WINDOW_PAYLOAD:
        return None, None
    stream_id = struct.unpack(_STREAM_DATA_FMT, data[:_STREAM_DATA_HEADER])[0]
    return stream_id, data[_STREAM_DATA_HEADER:]


def new_tunnel_id() -> str:
    """A client-generated id identifying a tunnel across reconnects."""
    return uuid.uuid4().hex