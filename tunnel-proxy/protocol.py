"""
protocol.py -- Canonical wire protocol for the tunnel proxy system.

This module is the single source of truth for the framing format,
frame types, and the HELLO authentication payload layout. Both the
server (proxy_server.py) and any client implementation MUST use an
identical copy of this logic (or a faithful re-implementation) to
interoperate.

See README.md / PROTOCOL section for the full prose specification.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import hmac
import secrets
import struct
import time
import uuid

# ---------------------------------------------------------------------------
# Frame header
# ---------------------------------------------------------------------------
#
#   0        2      3      4                 8                 12
#   +--------+------+------+-----------------+-----------------+
#   | Magic  | Ver  | Type |    Stream ID     |     Length      |
#   +--------+------+------+-----------------+-----------------+
#   |                          Payload (Length bytes)           |
#   +-------------------------------------------------------------+
#
#   Magic     : 2 bytes, ASCII "TN"           -- resync / sanity check
#   Version   : 1 byte, protocol version (currently 1)
#   Type      : 1 byte, FrameType enum value
#   Stream ID : 4 bytes, unsigned big-endian. 0 == control channel.
#   Length    : 4 bytes, unsigned big-endian, length of Payload in bytes.
#   Payload   : Length bytes, meaning depends on Type (see below).
#
# Fixed header size is 12 bytes. This keeps parsing trivial and the header
# cheap to scan through even on a loaded multiplexed connection.

PROTO_MAGIC = b"TN"
PROTO_VERSION = 1

_HEADER_FMT = "!2sBBII"
HEADER_LEN = struct.calcsize(_HEADER_FMT)  # 12

# A single STREAM_DATA frame is capped so that no single frame can hog the
# multiplexed connection and delay control frames / other streams
# (head-of-line blocking). Larger writes are simply chunked into multiple
# frames by the sender.
MAX_FRAME_PAYLOAD = 64 * 1024  # 64 KiB

# Hard ceiling on any single incoming frame (defends against a malicious or
# buggy peer claiming an enormous Length and exhausting memory).
MAX_ALLOWED_LENGTH = 16 * 1024 * 1024  # 16 MiB

CONTROL_STREAM_ID = 0

# Initial per-stream flow-control window (bytes each side may send before
# it must wait for a WINDOW_UPDATE). See FlowWindow in proxy_server.py.
INITIAL_WINDOW = 256 * 1024


class FrameType(enum.IntEnum):
    # --- connection / session lifecycle -----------------------------------
    HELLO = 0x01                 # client -> server: authenticate
    HELLO_OK = 0x02               # server -> client: auth accepted
    HELLO_FAIL = 0x03             # server -> client: auth rejected (then close)
    PING = 0x04                   # either direction: heartbeat
    PONG = 0x05                   # either direction: heartbeat reply

    # --- tunnel (logical forwarding rule) lifecycle ------------------------
    TUNNEL_OPEN_REQUEST = 0x06    # client -> server: register a tunnel
    TUNNEL_OPEN_RESPONSE = 0x07   # server -> client: result of registration
    TUNNEL_CLOSE = 0x08           # either direction: unregister a tunnel

    # --- per-connection multiplexed data streams ----------------------------
    STREAM_OPEN = 0x09            # server -> client: new inbound connection
    STREAM_DATA = 0x0A            # either direction: payload chunk
    STREAM_CLOSE = 0x0B           # either direction: stream finished/aborted
    STREAM_WINDOW_UPDATE = 0x0C   # either direction: flow-control credit

    # --- datagram (UDP) traffic ---------------------------------------------
    UDP_DATAGRAM = 0x0E           # either direction: one complete UDP datagram

    # --- misc ---------------------------------------------------------------
    ERROR = 0x0D                  # either direction: generic error report


class ProtocolError(Exception):
    """Raised when a peer violates the framing protocol."""


class Frame:
    __slots__ = ("version", "type", "stream_id", "payload")

    def __init__(self, version: int, type: int, stream_id: int, payload: bytes):
        self.version = version
        self.type = type
        self.stream_id = stream_id
        self.payload = payload

    def __repr__(self):
        return (f"Frame(v={self.version}, type={FrameType(self.type).name if self.type in FrameType._value2member_map_ else self.type}, "
                f"stream={self.stream_id}, len={len(self.payload)})")


def encode_frame(frame_type: int, stream_id: int, payload: bytes = b"", version: int = PROTO_VERSION) -> bytes:
    if len(payload) > MAX_ALLOWED_LENGTH:
        raise ValueError("payload exceeds MAX_ALLOWED_LENGTH")
    header = struct.pack(_HEADER_FMT, PROTO_MAGIC, version, int(frame_type), stream_id, len(payload))
    return header + payload


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    """Read exactly one frame from an asyncio StreamReader.

    Raises asyncio.IncompleteReadError on clean/unclean EOF and
    ProtocolError on a malformed header (bad magic / oversized length).
    """
    header = await reader.readexactly(HEADER_LEN)
    magic, version, ftype, stream_id, length = struct.unpack(_HEADER_FMT, header)
    if magic != PROTO_MAGIC:
        raise ProtocolError(f"bad magic bytes: {magic!r}")
    if length > MAX_ALLOWED_LENGTH:
        raise ProtocolError(f"frame length {length} exceeds maximum {MAX_ALLOWED_LENGTH}")
    payload = await reader.readexactly(length) if length else b""
    return Frame(version=version, type=ftype, stream_id=stream_id, payload=payload)


# ---------------------------------------------------------------------------
# HELLO authentication payload
# ---------------------------------------------------------------------------
#
# The HELLO frame (stream_id = 0) proves knowledge of the shared secret
# without ever sending the secret itself, and includes basic replay
# protection. This does NOT replace transport security -- operators should
# still run the control channel over TLS (supported natively, see
# `control.tls` in config.json) or a private network (VPN / WireGuard /
# SSH tunnel) for defense in depth, since HMAC alone does not give
# confidentiality of the tunneled data's metadata.
#
#   client_id : 16 bytes. All-zero == "assign me a new identity".
#               Otherwise the client's previously-assigned id, allowing
#               it to reconnect and be recognised as the same client.
#   timestamp : 8 bytes, unsigned big-endian unix time (seconds).
#   nonce     : 16 bytes, random, single-use.
#   hmac      : 32 bytes, HMAC-SHA256(secret, client_id || timestamp || nonce)
#
# Total payload size: 16 + 8 + 16 + 32 = 72 bytes.

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


def verify_hello_payload(payload: bytes, secret: str, seen_nonces: dict) -> tuple[bool, str | None, str | None]:
    """Validate a HELLO payload.

    `seen_nonces` is a dict of (client_id_bytes+nonce) -> timestamp used for
    replay protection; the caller is responsible for periodically pruning
    entries older than HELLO_TIMESTAMP_SKEW_SECONDS.

    Returns (ok, client_id_hex_or_None, error_reason_or_None).
    """
    if len(payload) != HELLO_PAYLOAD_LEN:
        return False, None, "malformed HELLO payload"

    client_id_bytes, ts, nonce, mac = struct.unpack(_HELLO_FMT, payload)

    now = int(time.time())
    if abs(now - ts) > HELLO_TIMESTAMP_SKEW_SECONDS:
        return False, None, "timestamp outside allowed skew"

    expected = hmac.new(
        secret.encode("utf-8"),
        client_id_bytes + struct.pack("!Q", ts) + nonce,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(mac, expected):
        return False, None, "invalid signature"

    nonce_key = client_id_bytes + nonce
    if nonce_key in seen_nonces:
        return False, None, "replayed nonce"
    seen_nonces[nonce_key] = now

    if client_id_bytes == NULL_CLIENT_ID:
        client_id_bytes = uuid.uuid4().bytes

    return True, client_id_bytes.hex(), None


def new_tunnel_id() -> str:
    """A client-generated id identifying a tunnel across reconnects.

    Clients should persist this locally (alongside their client_id) so
    that re-requesting the same tunnel_id after a reconnect signals
    intent to resume the same logical tunnel.
    """
    return uuid.uuid4().hex
