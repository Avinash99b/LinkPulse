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

# Hard ceiling on the send credit either side may hold for one stream. A
# WINDOW_UPDATE that would push the window above this is capped/ignored so a
# malicious peer cannot inflate our send window without bound.
MAX_WINDOW_CREDIT = 2 * INITIAL_WINDOW

# Control/JSON payloads (tunnel/stream metadata, errors) are small; cap them
# before any buffer is allocated so a peer cannot claim 16 MiB for a frame
# that can never legitimately be that large.
MAX_CONTROL_PAYLOAD = 64 * 1024

# A single UDP datagram may never exceed the maximum UDP payload size (the
# 65535-byte IP datagram limit minus the 8-byte UDP header and 20-byte IP
# header). Empty datagrams (Length 0) are legal and meaningful for UDP.
UDP_MAX_DATAGRAM = 65507

# Capabilities negotiated between the server and a client connection.
# `stream_eof` advertises that the peer understands STREAM_EOF (a write-half
# close) in addition to STREAM_CLOSE (a full abort). When both sides agree,
# a stream can keep the opposite direction alive after one side finishes.
STREAM_CAPABILITY = "stream_eof"
SERVER_CAPABILITIES = (STREAM_CAPABILITY,)

# ---------------------------------------------------------------------------
# Tunnel ownership modes
# ---------------------------------------------------------------------------
#
# Every TUNNEL_OPEN_REQUEST carries a "mode" telling the server what should
# happen when the requested public name (subdomain / TCP port / UDP port) is
# already registered to somebody else.
#
#   handoff (default): the newcomer wins. The current owner's tunnel is
#                      revoked, the owner is told why (TUNNEL_CLOSE with
#                      reason="handoff") and the newcomer takes the name.
#   lease           : the name is reserved. A newcomer is refused with an
#                      error response; only a reconnect of the *same client
#                      process* may take the registration back.
#
# The mode declared by the tunnel's owner is what the server stores and
# enforces, so a lease protects a name from every later claimant, and a
# client asking for a lease over a name that is already in use is refused
# rather than silently stealing it.

TUNNEL_MODE_HANDOFF = "handoff"
TUNNEL_MODE_LEASE = "lease"
TUNNEL_MODES = (TUNNEL_MODE_HANDOFF, TUNNEL_MODE_LEASE)


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
    STREAM_CLOSE = 0x0B           # either direction: stream aborted (full close)
    STREAM_WINDOW_UPDATE = 0x0C   # either direction: flow-control credit
    STREAM_EOF = 0x0F             # either direction: sender's write-half ended
                                  #   (half-close; only used once both sides
                                  #    advertised the "stream_eof" capability)

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


async def read_frame_header(reader: asyncio.StreamReader) -> tuple[int, int, int, int]:
    """Read and validate just the 12-byte frame header.

    Validates the magic, the protocol version and the advertised payload
    length against MAX_ALLOWED_LENGTH, so a caller can decide how much (if
    any) payload it is willing to read before allocating a buffer.

    Returns (version, frame_type, stream_id, length).
    """
    header = await reader.readexactly(HEADER_LEN)
    magic, version, ftype, stream_id, length = struct.unpack(_HEADER_FMT, header)
    if magic != PROTO_MAGIC:
        raise ProtocolError(f"bad magic bytes: {magic!r}")
    if version != PROTO_VERSION:
        raise ProtocolError(f"unsupported protocol version {version} (expected {PROTO_VERSION})")
    if length > MAX_ALLOWED_LENGTH:
        raise ProtocolError(f"frame length {length} exceeds maximum {MAX_ALLOWED_LENGTH}")
    return version, ftype, stream_id, length


async def read_frame(reader: asyncio.StreamReader, *, max_payload: int = MAX_ALLOWED_LENGTH) -> Frame:
    """Read exactly one frame from an asyncio StreamReader.

    The header is validated first (magic, version, length) so an oversized
    or unknown-version frame is rejected *before* any payload is buffered.
    `max_payload` lets a caller impose a tighter ceiling than
    MAX_ALLOWED_LENGTH (e.g. HELLO, which must be exactly 72 bytes).

    Raises asyncio.IncompleteReadError on clean/unclean EOF and
    ProtocolError on a malformed header (bad magic / version / oversized
    length) or a fixed-size frame carrying the wrong number of bytes.
    """
    version, ftype, stream_id, length = await read_frame_header(reader)
    if length > max_payload:
        raise ProtocolError(
            f"frame type {ftype} length {length} exceeds allowed maximum {max_payload}"
        )
    expected = _FIXED_FRAME_SIZES.get(ftype)
    if expected is not None and length != expected:
        raise ProtocolError(
            f"frame type {ftype} must carry exactly {expected} bytes, got {length}"
        )
    max_for_type = _MAX_FRAME_PAYLOADS.get(ftype)
    if max_for_type is not None and length > max_for_type:
        raise ProtocolError(
            f"frame type {ftype} payload {length} exceeds maximum {max_for_type}"
        )
    if ftype in _CONTROL_PAYLOAD_TYPES and length > MAX_CONTROL_PAYLOAD:
        raise ProtocolError(
            f"control frame {ftype} payload {length} exceeds maximum {MAX_CONTROL_PAYLOAD}"
        )
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

# Frame types whose payload has a fixed, known size. Any frame of one of
# these types carrying a different Length is rejected by read_frame() as
# malformed, which keeps the parser honest about control frames.
_FIXED_FRAME_SIZES = {
    FrameType.HELLO: HELLO_PAYLOAD_LEN,
    FrameType.PING: 0,
    FrameType.PONG: 0,
    FrameType.STREAM_WINDOW_UPDATE: 4,
    # STREAM_CLOSE/STREAM_EOF are pure signals and must carry no payload.
    FrameType.STREAM_CLOSE: 0,
    FrameType.STREAM_EOF: 0,
}

# Types with a variable but bounded payload. A STREAM_DATA frame is capped at
# MAX_FRAME_PAYLOAD (64 KiB) so one stream cannot head-of-line-block the rest;
# UDP datagrams at the protocol maximum.
_MAX_FRAME_PAYLOADS = {
    FrameType.STREAM_DATA: MAX_FRAME_PAYLOAD,
    FrameType.UDP_DATAGRAM: UDP_MAX_DATAGRAM,
}

# JSON-carrying control/stream frames must stay small. This bounds memory
# before the payload is read, independently of MAX_ALLOWED_LENGTH.
_CONTROL_PAYLOAD_TYPES = frozenset({
    FrameType.HELLO_OK,
    FrameType.HELLO_FAIL,
    FrameType.TUNNEL_OPEN_REQUEST,
    FrameType.TUNNEL_OPEN_RESPONSE,
    FrameType.TUNNEL_CLOSE,
    FrameType.STREAM_OPEN,
    FrameType.ERROR,
})


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

    `seen_nonces` is a dict of (client_id_bytes+nonce) -> expiry timestamp
    (unix seconds) used for replay protection; the caller is responsible for
    periodically pruning entries whose expiry has passed. Retaining an
    expiry derived from the HELLO timestamp + allowed skew (rather than the
    receive time) bounds how long a nonce can be replayed in either
    direction, no matter how late the frame arrives.

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
    # Keep the nonce at most until the HELLO timestamp itself stops being
    # acceptable, so replays cannot be stretched by a late arrival. The +1
    # covers the inclusive `abs(now - ts) <= SKEW` boundary: at exactly
    # ts = now - SKEW the HELLO is still valid, so the nonce must still be
    # retained then.
    seen_nonces[nonce_key] = ts + HELLO_TIMESTAMP_SKEW_SECONDS + 1

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
