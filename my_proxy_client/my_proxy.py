#!/usr/bin/env python3
"""
my_proxy -- client for the self-hosted tunneling proxy.

Connects to a proxy_server.py instance, authenticates with a shared
secret, and exposes local HTTP/TCP services on public URLs/ports,
multiplexed over one persistent connection.

This file implements the CANONICAL wire protocol exactly as defined by
the server (see the "PROTOCOL" section below, a faithful reproduction of
proxy_server's protocol.py): frame layout, frame types, the HELLO
HMAC-challenge payload, JSON payload shapes for tunnel/stream control
messages, and the credit-based flow-control scheme. Nothing here
redesigns or reinterprets that protocol -- it is copied verbatim so this
client and the server are guaranteed to agree on the wire format.

Usage:
    my_proxy http 8080
    my_proxy http localhost:5173
    my_proxy http 3000 -u api
    my_proxy http 3000 -u api --lease
    my_proxy tcp 22
    my_proxy tcp 25565
    my_proxy start tunnels.json

Tunnel names and ownership
--------------------------
A tunnel's public name (subdomain for HTTP, port for TCP/UDP) can be claimed
by more than one client. Two ownership modes decide what happens then:

    handoff (default)  the newest client wins. The previous owner's tunnel is
                       revoked and it is told "Tunnel 'x' was handed off to a
                       new client"; if that was its only tunnel it exits.

    lease (--lease)    the name is reserved. Another client is refused with an
                       error instead of taking the name over. Leases are bound
                       to the client process, so a second process on the same
                       machine asking for the same name is also refused.

Reconnecting is never a conflict: the client keeps the same tunnel ids, so the
server simply hands the name back to it.

Run `my_proxy --help` / `my_proxy http --help` etc. for all options.
"""

from __future__ import annotations

import argparse
import asyncio
import calendar
import contextlib
import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

# =============================================================================
# PROTOCOL -- synchronized copy of tunnel-proxy/protocol.py (canonical).
#
# This section mirrors the canonical module exactly: frame layout, frame
# types, flow-control constants, read_frame_header()/read_frame() validation,
# the HELLO payload, and the negotiated "stream_eof" capability. Change both
# copies together; do not reinterpret the wire format here.
# =============================================================================

PROTO_MAGIC = b"TN"
PROTO_VERSION = 1

_HEADER_FMT = "!2sBBII"
HEADER_LEN = struct.calcsize(_HEADER_FMT)  # 12

MAX_FRAME_PAYLOAD = 64 * 1024        # 64 KiB per STREAM_DATA frame
MAX_ALLOWED_LENGTH = 16 * 1024 * 1024  # 16 MiB hard ceiling on any frame

CONTROL_STREAM_ID = 0
INITIAL_WINDOW = 256 * 1024  # per-stream flow-control window, each direction
WINDOW_UPDATE_THRESHOLD = INITIAL_WINDOW // 2

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

# Optional per-stream half-close. A server that supports it advertises
# "stream_eof" in its HELLO_OK ``capabilities`` list; a client that sees it
# advertises the capability back in TUNNEL_OPEN_REQUEST and may then end one
# direction of a stream with STREAM_EOF instead of aborting the whole stream
# with STREAM_CLOSE. Servers without the capability keep the legacy
# full-close-on-EOF behaviour, so the feature is only ever used when both
# ends understand it.
STREAM_EOF = 0x0F
STREAM_CAPABILITY = "stream_eof"
SERVER_CAPABILITIES = (STREAM_CAPABILITY,)
# Client-side aliases (same wire value).
CAP_STREAM_EOF = STREAM_CAPABILITY
CLIENT_CAPABILITIES = (STREAM_CAPABILITY,)


class FrameType(enum.IntEnum):
    HELLO = 0x01
    HELLO_OK = 0x02
    HELLO_FAIL = 0x03
    PING = 0x04
    PONG = 0x05
    TUNNEL_OPEN_REQUEST = 0x06
    TUNNEL_OPEN_RESPONSE = 0x07
    TUNNEL_CLOSE = 0x08
    STREAM_OPEN = 0x09
    STREAM_DATA = 0x0A
    STREAM_CLOSE = 0x0B
    STREAM_WINDOW_UPDATE = 0x0C
    STREAM_EOF = 0x0F
    UDP_DATAGRAM = 0x0E
    ERROR = 0x0D


class ProtocolError(Exception):
    """Raised when the peer violates the framing protocol."""


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


# -- HELLO authentication payload (72 bytes) --------------------------------
#   client_id : 16 bytes. All-zero == "assign me a new identity".
#   timestamp : 8 bytes, unsigned big-endian unix time (seconds).
#   nonce     : 16 bytes, random, single-use.
#   hmac      : 32 bytes, HMAC-SHA256(secret, client_id || timestamp || nonce)

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
    ts = int(time.time())
    nonce = secrets.token_bytes(16)
    mac = hmac.new(
        secret.encode("utf-8"),
        client_id_bytes + struct.pack("!Q", ts) + nonce,
        hashlib.sha256,
    ).digest()
    return struct.pack(_HELLO_FMT, client_id_bytes, ts, nonce, mac)


def new_tunnel_id() -> str:
    """Client-generated id identifying a tunnel across reconnects."""
    return uuid.uuid4().hex


# Tunnel ownership modes (mirrors protocol.py).
TUNNEL_MODE_HANDOFF = "handoff"
TUNNEL_MODE_LEASE = "lease"
TUNNEL_MODES = (TUNNEL_MODE_HANDOFF, TUNNEL_MODE_LEASE)


# =============================================================================
# Small errors specific to this client
# =============================================================================

class AuthError(Exception):
    """Server rejected our HELLO (bad secret, bad timestamp, replay, ...).
    Not retried automatically -- retrying with the same secret can't help."""


class ShuttingDown(Exception):
    """Internal signal used to unwind the connect/serve loop on a clean exit."""


# =============================================================================
# Flow control -- identical scheme to the server's FlowWindow.
# =============================================================================

class FlowWindow:
    def __init__(self, initial: int = INITIAL_WINDOW,
                 max_credit: int = MAX_WINDOW_CREDIT):
        self.available = initial
        self.max_credit = max_credit
        self.aborted = False
        self._event = asyncio.Event()
        self._event.set()

    def consume(self, n: int):
        if n < 0:
            raise ValueError("cannot consume negative credit")
        self.available -= n
        if self.available <= 0:
            self._event.clear()

    def replenish(self, n: int) -> bool:
        """Add credit, capped at max_credit. Returns False if capped."""
        if n <= 0:
            return True
        self.available += n
        capped = False
        if self.available > self.max_credit:
            self.available = self.max_credit
            capped = True
        if self.available > 0:
            self._event.set()
        return not capped

    def abort(self):
        """Wake every waiter and permanently unblock the window.

        Used when a stream is torn down: a pump blocked on zero credit must
        not stay asleep forever, or its stream would leak until the whole
        control connection reconnects."""
        self.aborted = True
        self._event.set()

    async def wait(self):
        await self._event.wait()


# =============================================================================
# Tunnel specs (what the user asked to expose) and runtime state (what the
# server actually granted, plus live stats for the dashboard)
# =============================================================================

@dataclasses.dataclass
class TunnelSpec:
    tunnel_id: str
    type: str            # "http" | "tcp" | "udp"
    local_host: str
    local_port: int
    subdomain: Optional[str] = None    # http only, requested
    remote_port: Optional[int] = None  # tcp/udp only, requested
    mode: str = TUNNEL_MODE_HANDOFF    # ownership: "handoff" | "lease"


@dataclasses.dataclass
class TunnelRuntime:
    spec: TunnelSpec
    status: str = "pending"     # pending | active | error | handed_off | closed
    public_url: Optional[str] = None
    error: Optional[str] = None
    connection_count: int = 0
    bytes_in: int = 0    # local backend -> public internet
    bytes_out: int = 0   # public internet -> local backend
    latencies_ms: deque = dataclasses.field(default_factory=lambda: deque(maxlen=50))
    failure_count: int = 0
    last_error_notice: float = 0.0

    def avg_latency_ms(self) -> Optional[float]:
        if not self.latencies_ms:
            return None
        return sum(self.latencies_ms) / len(self.latencies_ms)

    def label(self) -> str:
        """Human-readable tunnel name for log messages."""
        if self.spec.type == "http" and self.spec.subdomain:
            return self.spec.subdomain
        if self.spec.remote_port:
            return f"{self.spec.type}:{self.spec.remote_port}"
        return self.spec.tunnel_id[:8]


@dataclasses.dataclass
class ClientStream:
    stream_id: int
    tunnel_id: str
    local_reader: Optional[asyncio.StreamReader]
    local_writer: Optional[asyncio.StreamWriter]
    generation: int = 0
    udp_transport: object = None   # asyncio.DatagramTransport for udp streams
    send_window: FlowWindow = dataclasses.field(default_factory=FlowWindow)
    closed: bool = False
    opened_at: float = dataclasses.field(default_factory=time.time)
    first_byte_recorded: bool = False
    # Receive side (server -> local backend): data is queued here and drained
    # by a per-stream task, so the central dispatcher never blocks on a slow
    # local service and heartbeats keep flowing.
    recv_queue: asyncio.Queue = dataclasses.field(default_factory=asyncio.Queue)
    queued_bytes: int = 0
    recv_eof: bool = False   # server half-closed us (STREAM_EOF frame seen)
    recv_eof_drained: bool = False  # ...and all queued data was flushed
    local_eof: bool = False  # we half-closed the local backend (sent STREAM_EOF)
    # Receive-side flow control: bytes received but not yet credited, and
    # bytes delivered locally awaiting a batched WINDOW_UPDATE.
    unacked_recv_bytes: int = 0
    credit_pending: int = 0
    write_task: Optional[asyncio.Task] = None
    pump_task: Optional[asyncio.Task] = None
    # UDP: one bounded queue per stream drained by a single sender task, so a
    # burst of datagrams cannot spawn unbounded asyncio jobs.
    udp_queue: asyncio.Queue = dataclasses.field(default_factory=asyncio.Queue)
    udp_queue_bytes: int = 0
    udp_send_task: Optional[asyncio.Task] = None
    udp_dropped: int = 0
    is_udp: bool = False
    # Datagrams that arrived before the local UDP endpoint was ready.
    # Each entry is (payload, legacy) where legacy means it arrived as
    # STREAM_DATA (and therefore consumed flow-control credit to replenish).
    udp_pending: list = dataclasses.field(default_factory=list)
    udp_pending_bytes: int = 0


@dataclasses.dataclass
class PendingStream:
    """A stream the server has opened (STREAM_OPEN received) but whose
    local backend connection hasn't finished establishing yet. STREAM_DATA
    frames can legitimately arrive in this window (e.g. the server sends
    the buffered HTTP request bytes right after STREAM_OPEN) -- they must
    be queued here rather than dropped, then replayed once the local
    connection is ready."""
    tunnel_id: str
    proto: str = "tcp"
    buffered: list = dataclasses.field(default_factory=list)
    buffered_bytes: int = 0
    eof: bool = False
    closed: bool = False
    connect_task: Optional[asyncio.Task] = None


# Bound on how much a single stream may buffer while its local backend is
# connecting / slow. It is slightly larger than one flow-control window, so a
# well-behaved peer (which respects that window) can never trip it; a peer
# that ignores flow control is aborted instead of growing memory forever.
STREAM_BUFFER_LIMIT = INITIAL_WINDOW + MAX_FRAME_PAYLOAD
UDP_QUEUE_MAX = 256  # datagrams queued per UDP stream before we start dropping
MAX_LOCAL_STREAMS = 256          # pending + active streams per connection
MAX_PENDING_FRAMES = 256         # frames buffered per stream before local ready
MAX_TOTAL_UDP_QUEUED = 8 * 1024 * 1024  # client-wide UDP queue byte ceiling
SEND_TIMEOUT_DEFAULT = 30.0      # max seconds to hold the write lock / drain

# Queue sentinel meaning "the server half-closed this stream": the write task
# flushes everything queued before it, then half-closes the local socket.
_QUEUE_EOF = object()


# =============================================================================
# The client engine
# =============================================================================

class TunnelClient:
    def __init__(self, specs: list[TunnelSpec], server_host: str, server_port: int,
                 secret: str, grace_time: float, state_file: Optional[Path],
                 log: logging.Logger, recent_logs: deque,
                 client_id: Optional[str] = None,
                 mode: str = "http",
                 target_str: str = "",
                 dashboard_addr: Optional[str] = None,
                 log_file_path: Optional[str] = None,
                 retry_interval: float = 5.0,
                 managed_id: Optional[str] = None,
                 tls: bool = False,
                 ca_cert: Optional[str] = None,
                 instance_id: Optional[str] = None):
        self.specs = specs
        self.server_host = server_host
        self.server_port = server_port
        self.secret = secret
        self.grace_time = grace_time
        self.retry_interval = max(1.0, float(retry_interval))
        self.send_timeout = SEND_TIMEOUT_DEFAULT
        self.state_file = state_file
        self.log = log
        self.recent_logs = recent_logs
        self.mode = mode
        self.target_str = target_str
        self.dashboard_addr = dashboard_addr
        self.log_file_path = log_file_path
        self.tls = bool(tls)
        self.ca_cert = ca_cert or None
        self._plaintext_warned = False

        # Two distinct identities:
        #   managed_id  identifies *this process* (and its managed state file)
        #   client_id   is the machine identity shared by every process on the
        #               machine via the persisted state file
        # The server additionally needs a per-process instance id to tell a
        # reconnect (same instance) from a competing second client.
        self.managed_id = managed_id or uuid.uuid4().hex
        self.instance_id = instance_id or secrets.token_hex(8)

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()

        if client_id:
            self.client_id = _validate_client_id(client_id)
            self._client_id_bytes = bytes.fromhex(self.client_id)
        else:
            self.client_id = None
            self._client_id_bytes = self._load_client_id()
            if self._client_id_bytes != NULL_CLIENT_ID:
                self.client_id = self._client_id_bytes.hex()
            else:
                self._claim_machine_identity()

        self.tunnels: dict[str, TunnelRuntime] = {t.tunnel_id: TunnelRuntime(spec=t) for t in specs}
        self.streams: dict[int, ClientStream] = {}
        self.pending_streams: dict[int, PendingStream] = {}

        # Tunnels the server took away (handoff / closed): never re-requested.
        self._revoked_tunnel_ids: set[str] = set()
        # Background retry loops for tunnel registrations that failed (name
        # in use, lease held elsewhere, no ports free, ...).
        self._retry_tasks: dict[str, asyncio.Task] = {}
        # TUNNEL_OPEN_REQUESTs sent but not answered yet.
        self._open_inflight: set[str] = set()

        # Every background task belonging to one control connection. They are
        # cancelled *and awaited* when that connection goes away (disconnect,
        # handoff, shutdown), and a per-connection generation counter stops a
        # late task from an old connection from touching the new one.
        self._conn_tasks: set[asyncio.Task] = set()
        self._generation = 0
        self._shutdown_event = asyncio.Event()
        self._server_capabilities: set = set()
        self._server_supports_eof = False
        self._udp_queued_bytes = 0

        # Small, bounded operational counters (no per-packet counters).
        self.metrics = {
            "frames_in": 0, "frames_out": 0, "streams_opened": 0,
            "errors": 0, "udp_dropped": 0, "queue_high_water": 0,
        }

        self.process_start_time = time.time()
        self.connected_since: Optional[float] = None
        self.status = "connecting"   # connecting | connected | reconnecting | stopped
        self.reconnect_count = 0
        self._first_failure_time: Optional[float] = None
        self._retry_log_count = 0
        self._last_retry_log = 0.0
        self._shutdown_requested = False
        self._heartbeat_interval = 20  # overwritten by server's HELLO_OK value
        self._save_state("connecting")

    # -- persistence of client_id across reconnects/restarts -----------------

    def _managed_state_path(self) -> Path:
        """Managed (per-process) state file, keyed by this process's
        managed_id. This is what `linkpulse clients ...` lists and manages."""
        return _get_clients_dir() / f"{self.managed_id}.json"

    def _load_client_id(self) -> bytes:
        if not self.state_file or not self.state_file.exists():
            return NULL_CLIENT_ID
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return NULL_CLIENT_ID
        if not isinstance(data, dict):
            return NULL_CLIENT_ID
        cid = data.get("client_id")
        if not cid:
            return NULL_CLIENT_ID
        try:
            return bytes.fromhex(_validate_client_id(cid))
        except (ConfigError, ValueError):
            # A corrupt persisted id is recoverable: fall back to a fresh one.
            return NULL_CLIENT_ID

    def _claim_machine_identity(self):
        """Atomically establish the machine identity before connecting.

        Two processes starting simultaneously both try an exclusive create;
        the loser re-reads the winner's value instead of generating a second,
        competing id (and never overwrites a future shared identity with a
        stale one)."""
        if not self.state_file:
            return
        path = Path(self.state_file)
        new_id = uuid.uuid4().hex
        try:
            _ensure_private_dir(path.parent)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            self._client_id_bytes = self._load_client_id()
            if self._client_id_bytes != NULL_CLIENT_ID:
                self.client_id = self._client_id_bytes.hex()
            return
        except OSError as e:
            self.log.warning("Could not create machine identity %s: %s", path, e)
            return
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"client_id": new_id}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(path, 0o600)
        except OSError as e:
            self.log.warning("Could not write machine identity %s: %s", path, e)
            return
        self.client_id = new_id
        self._client_id_bytes = bytes.fromhex(new_id)

    def _write_machine_identity(self):
        """Persist only the machine identity (client_id).

        The state file is shared by every client process on the machine, so
        it must never receive per-process runtime status -- that would make
        two foreground clients constantly clobber each other. Runtime status
        lives in the per-process managed file instead."""
        if not self.state_file:
            return
        try:
            data = {}
            if self.state_file.exists():
                existing = _read_state_raw(self.state_file)
                if isinstance(existing, dict):
                    data.update(existing)
            cid = self.client_id or (self._client_id_bytes.hex()
                                     if self._client_id_bytes != NULL_CLIENT_ID else None)
            if not cid:
                return
            data["client_id"] = cid
            data.pop("instance_id", None)
            data.pop("pid", None)
            data.pop("status", None)
            _atomic_write_json(self.state_file, data)
        except OSError as e:
            self.log.warning("Could not persist machine identity to %s: %s", self.state_file, e)

    def _write_managed_state(self):
        cid_hex = self.client_id or (self._client_id_bytes.hex()
                                     if self._client_id_bytes != NULL_CLIENT_ID else None)
        tunnels_info = []
        public_urls = []
        for runtime in self.tunnels.values():
            info = {
                "tunnel_id": runtime.spec.tunnel_id,
                "type": runtime.spec.type,
                "mode": runtime.spec.mode,
                "status": runtime.status,
                "public_url": runtime.public_url,
                "local_destination": f"{runtime.spec.local_host}:{runtime.spec.local_port}",
            }
            tunnels_info.append(info)
            if runtime.public_url:
                public_urls.append(runtime.public_url)

        data = {
            "managed_id": self.managed_id,
            "client_id": cid_hex,
            "instance_id": self.instance_id,
            "pid": os.getpid(),
            "start_time": _proc_start_time(os.getpid()),
            "boot_id": _read_boot_id(),
            "status": self.status,
            "mode": self.mode,
            "target": self.target_str,
            "server": f"{self.server_host}:{self.server_port}",
            "dashboard": self.dashboard_addr if self.dashboard_addr else None,
            "started_at": self.process_start_time,
            "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.process_start_time)),
            "log_file": str(self.log_file_path) if self.log_file_path else None,
            "state_file": str(self.state_file) if self.state_file else None,
            "public_urls": public_urls,
            "tunnels": tunnels_info,
        }
        try:
            _atomic_write_json(self._managed_state_path(), data)
        except OSError as e:
            self.log.warning("Could not persist state to %s: %s", self._managed_state_path(), e)

    def _save_state(self, status: Optional[str] = None):
        if status:
            self.status = status
        self._write_machine_identity()
        self._write_managed_state()

    def _save_client_id(self, client_id_hex: str):
        self.client_id = _validate_client_id(client_id_hex)
        self._client_id_bytes = bytes.fromhex(self.client_id)
        self._save_state()

    # -- logging helper (also feeds the dashboard's recent-logs list) --------

    def _log(self, level: int, msg: str, *args):
        # Format and redact *before* emitting, so a secret carried in a peer
        # string never reaches the terminal or the log file either.
        try:
            text = msg % args if args else msg
        except Exception:
            text = str(msg)
        if self.secret and len(self.secret) >= 8:
            text = text.replace(self.secret, "***")
        try:
            self.log.log(level, "%s", text)
        except Exception:
            pass
        try:
            self.recent_logs.append(f"[{time.strftime('%H:%M:%S')}] {text}")
        except Exception:
            pass

    # -- outbound frame helper ------------------------------------------------

    async def _send(self, ftype: int, stream_id: int, payload: bytes = b"",
                    *, gen: Optional[int] = None,
                    expected_writer: Optional[asyncio.StreamWriter] = None):
        data = encode_frame(ftype, stream_id, payload)
        timeout = self.send_timeout
        try:
            await asyncio.wait_for(self._write_lock.acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            self._abort_connection()
            raise ConnectionError("timed out waiting for the control write lock")
        try:
            writer = self.writer
            if writer is None or writer.is_closing():
                raise ConnectionError("control connection is closed")
            if expected_writer is not None and writer is not expected_writer:
                raise ConnectionError("control writer changed")
            if gen is not None and gen != self._generation:
                raise ConnectionError("stale connection generation")
            writer.write(data)
            try:
                await asyncio.wait_for(writer.drain(), timeout=timeout)
            except asyncio.TimeoutError:
                self._abort_connection()
                raise ConnectionError("timed out draining the control connection")
            self.metrics["frames_out"] += 1
        finally:
            self._write_lock.release()

    # =========================================================================
    # Top-level run loop: connect, serve, reconnect -- forever.
    #
    # A dropped/refused/unresolvable server is retried every `retry_interval`
    # seconds (default 5s) indefinitely: the client is meant to be left
    # running on a laptop that sleeps, changes networks or boots before the
    # network is up, so giving up after a grace period would just mean the
    # tunnel silently disappears until the user notices. Only authentication
    # failure (a wrong token, which retrying cannot fix) stops the process.
    # =========================================================================

    async def run(self):
        first_attempt = True

        while not self._shutdown_requested:
            self.status = "connecting" if first_attempt else "reconnecting"
            self._save_state()
            try:
                await self._connect_and_serve(first_attempt)
                # _connect_and_serve only returns normally on a clean, requested
                # shutdown; anything else raises.
                break
            except ShuttingDown:
                break
            except AuthError as e:
                self._log(logging.ERROR, "Authentication failed: %s -- check --token. Exiting.", e)
                self.status = "disconnected"
                self._save_state("disconnected")
                sys.exit(1)
            except (ConnectionError, OSError, asyncio.TimeoutError, ProtocolError,
                    asyncio.IncompleteReadError) as e:
                if self._shutdown_requested:
                    # We closed our own writer as part of a graceful shutdown;
                    # that surfaces here as a read error, but it isn't a real
                    # connection failure and must not trigger a retry/backoff.
                    break
                self.status = "reconnecting"
                self._save_state("reconnecting")
                now = time.time()
                if self._first_failure_time is None:
                    self._first_failure_time = now
                elapsed = now - self._first_failure_time

                # Log the first few failures verbosely, then at most once a
                # minute, so a long outage doesn't flood the terminal or the
                # log file while the client keeps retrying.
                self._retry_log_count += 1
                if self._retry_log_count <= 3 or now - self._last_retry_log >= 60:
                    self._last_retry_log = now
                    if elapsed < self.grace_time:
                        self._log(logging.WARNING,
                                  "Connection issue (%s); retrying in %.0fs "
                                  "(disconnected for %.0fs)",
                                  e, self.retry_interval, elapsed)
                    else:
                        self._log(logging.ERROR,
                                  "Server unreachable for %.0fs (%s); retrying every %.0fs "
                                  "-- press Ctrl+C to stop",
                                  elapsed, e, self.retry_interval)

                if await self._sleep_or_stop(self.retry_interval):
                    # Shutdown requested while we were waiting to retry: stop
                    # at once instead of sitting out the full interval.
                    break
                first_attempt = False
                continue

            # Reached only if _connect_and_serve returned without raising and
            # without a shutdown request -- treat as a normal drop, reconnect.
            first_attempt = False

        self.status = "stopped"
        self._save_state("stopped")

    async def request_shutdown(self):
        """Called on SIGINT/SIGTERM: politely tell the server we're leaving,
        then unwind the connect/serve loop."""
        self._shutdown_requested = True
        self._shutdown_event.set()
        self._cancel_all_retries_now()
        self._save_state("stopped")
        # Abort active streams with a full STREAM_CLOSE before unregistering
        # tunnels: the server's tunnel teardown can wait for its public-side
        # stream handlers, and those only finish once the stream is closed.
        # Bounded, best-effort: shutdown must stay prompt.
        gen = self._generation
        active = []
        for stream in list(self.streams.values()):
            sid, sgen = stream.stream_id, stream.generation
            self._teardown_stream(stream, notify=False)
            if sgen == gen and self.writer is not None:
                active.append((sid, sgen))
        close_coros = []
        for sid in list(self.pending_streams):
            self.pending_streams[sid].closed = True
            close_coros.append(self._send_checked(FrameType.STREAM_CLOSE, sid, gen=gen))
        self._abort_pending_streams()

        if active and self.writer is not None:
            # A server pump can be parked on zero send credit. Grant one
            # bounded window first so it wakes and observes the dead public
            # socket, then send the full STREAM_CLOSE. Without this, the
            # server's tunnel teardown can wait for that pump.
            try:
                await asyncio.wait_for(asyncio.gather(*[
                    self._send_checked(FrameType.STREAM_WINDOW_UPDATE, sid,
                                       INITIAL_WINDOW.to_bytes(4, "big"), gen=sgen)
                    for sid, sgen in active
                ], return_exceptions=True), timeout=0.25)
            except (asyncio.TimeoutError, Exception):
                pass
            close_coros.extend(
                self._send_checked(FrameType.STREAM_CLOSE, sid, gen=sgen)
                for sid, sgen in active)
        if close_coros:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_coros, return_exceptions=True), timeout=0.25)
            except (asyncio.TimeoutError, Exception):
                pass

        if self.writer is not None:
            async def _polite_closes():
                for tunnel_id in list(self.tunnels.keys()):
                    if tunnel_id in self._revoked_tunnel_ids:
                        continue
                    await self._send(FrameType.TUNNEL_CLOSE, CONTROL_STREAM_ID,
                                     json.dumps({"tunnel_id": tunnel_id}).encode())
            try:
                # A blocked/duplex-stalled writer must not delay shutdown: one
                # small global budget, then abort the connection.
                await asyncio.wait_for(_polite_closes(), timeout=0.5)
            except (asyncio.TimeoutError, Exception):
                self._abort_connection()
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass

    async def _sleep_or_stop(self, timeout: float) -> bool:
        """Sleep up to `timeout` seconds, waking immediately on shutdown.
        Returns True if shutdown was requested."""
        if timeout <= 0:
            return self._shutdown_requested
        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _make_ssl_context(self) -> ssl.SSLContext:
        """Build a verified TLS client context.

        Certificate verification and hostname checking are mandatory: there
        is deliberately no insecure/verify-off switch. A custom CA may be
        supplied with --ca-cert / MY_PROXY_CA_CERT."""
        ctx = ssl.create_default_context(cafile=self.ca_cert or None)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    async def _open_control_connection(self):
        kwargs = {}
        if self.tls:
            kwargs["ssl"] = self._make_ssl_context()
            kwargs["server_hostname"] = self.server_host
        conn = asyncio.ensure_future(asyncio.wait_for(
            asyncio.open_connection(self.server_host, self.server_port, **kwargs),
            timeout=10,
        ))
        stopper = asyncio.ensure_future(self._shutdown_event.wait())
        try:
            done, pending = await asyncio.wait(
                {conn, stopper}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            conn.cancel()
            stopper.cancel()
            await asyncio.gather(conn, stopper, return_exceptions=True)
            raise
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if stopper in done:
            # If the connection completed in the same instant, close its
            # writer so the socket is not leaked.
            if conn.done() and not conn.cancelled() and conn.exception() is None:
                with contextlib.suppress(Exception):
                    _conn_reader, conn_writer = conn.result()
                    conn_writer.close()
            raise ShuttingDown()
        return conn.result()

    # -- per-connection task ownership ---------------------------------------

    def _track_task(self, coro, name: Optional[str] = None) -> asyncio.Task:
        task = asyncio.ensure_future(coro)
        self._conn_tasks.add(task)
        task.add_done_callback(self._conn_tasks.discard)
        return task

    async def _cancel_conn_tasks(self):
        tasks = [t for t in self._conn_tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # =========================================================================
    # One connection lifetime: connect, HELLO, register tunnels, dispatch loop
    # =========================================================================

    async def _connect_and_serve(self, first_attempt: bool):
        if first_attempt or self._retry_log_count <= 1:
            # Plain stderr line (not a log record) so a foreground start always
            # shows what it is doing; retries are covered by the throttled
            # warning/error messages in run().
            print("Connecting to %s:%s..." % (self.server_host, self.server_port), file=sys.stderr)
        if not self.tls and not self._plaintext_warned:
            self._plaintext_warned = True
            self._log(logging.WARNING,
                      "Control channel is unencrypted. Metadata and tunneled data are exposed to "
                      "the network -- pass --tls (optionally --ca-cert) or run over a private "
                      "network/VPN.")

        self.reader, self.writer = await self._open_control_connection()
        self._generation += 1
        gen = self._generation
        try:
            hello = build_hello_payload(self.secret, self._client_id_bytes)
            await self._send(FrameType.HELLO, CONTROL_STREAM_ID, hello)

            frame = await asyncio.wait_for(read_frame(self.reader), timeout=10)
            if frame.type == FrameType.HELLO_FAIL:
                reason = "unknown reason"
                try:
                    fail_info = json.loads(frame.payload.decode())
                    if isinstance(fail_info, dict):
                        reason = str(fail_info.get("error") or reason)
                except (ValueError, UnicodeDecodeError):
                    pass
                low = reason.lower()
                # Only a temporary capacity/busy refusal is retryable; a wrong
                # secret or replay must be fatal so the client stops clearly.
                retryable = any(k in low for k in (
                    "capacity", "busy", "overload", "too many clients", "try again"))
                if retryable:
                    raise ConnectionError(f"server temporarily unavailable: {reason}")
                raise AuthError(reason)
            if frame.type != FrameType.HELLO_OK:
                raise ProtocolError(f"expected HELLO_OK, got frame type {frame.type}")

            try:
                info = json.loads(frame.payload.decode())
                if not isinstance(info, dict):
                    raise ValueError("payload is not a JSON object")
            except (ValueError, UnicodeDecodeError) as e:
                raise ProtocolError(f"malformed HELLO_OK payload: {e}") from e
            new_cid = info.get("client_id")
            if not isinstance(new_cid, str):
                raise ProtocolError("HELLO_OK is missing client_id")
            try:
                self.client_id = _validate_client_id(new_cid)
            except ConfigError as e:
                raise ProtocolError(f"HELLO_OK returned an invalid client_id: {e}") from e
            self._client_id_bytes = bytes.fromhex(self.client_id)
            self._save_client_id(self.client_id)
            hb = info.get("heartbeat_interval", 20)
            try:
                hb_val = float(hb)
            except (TypeError, ValueError):
                hb_val = 0.0
            self._heartbeat_interval = hb_val if math.isfinite(hb_val) and hb_val > 0 else 20
            caps = info.get("capabilities")
            if isinstance(caps, (list, tuple)):
                self._server_capabilities = {c for c in caps if isinstance(c, str)}
            else:
                self._server_capabilities = set()
            self._server_supports_eof = CAP_STREAM_EOF in self._server_capabilities

            self.connected_since = time.time()
            self.status = "connected"
            if not first_attempt:
                self.reconnect_count += 1
                self._log(logging.INFO, "Reconnected to %s:%s (client_id=%s...)",
                          self.server_host, self.server_port, self.client_id[:8])
            else:
                self._log(logging.INFO, "Connected to %s:%s (client_id=%s...)",
                          self.server_host, self.server_port, self.client_id[:8])
            self._first_failure_time = None
            self._retry_log_count = 0

            # Close out any stream state left over from a previous connection --
            # those streams cannot be resumed (see protocol reconnect semantics).
            self._teardown_all_streams()
            self._abort_pending_streams()

            # Any in-flight registration from the previous connection is void,
            # and so are its retry timers -- every tunnel is re-requested below.
            self._open_inflight.clear()
            await self._cancel_all_retries()

            # (Re-)register every configured tunnel. Re-requesting the same
            # tunnel_id/subdomain/remote_port after a reconnect is how a stable
            # public URL is recovered, per the protocol's reconnect semantics.
            # Tunnels the server revoked (e.g. handed off to a newer client) stay
            # revoked: re-requesting them would start a takeover ping-pong.
            for runtime in self.tunnels.values():
                if runtime.spec.tunnel_id in self._revoked_tunnel_ids:
                    continue
                runtime.status = "pending"
                runtime.error = None
                await self._request_tunnel_open(runtime.spec)

            self._track_task(self._inactivity_watchdog())
            await self._dispatch_loop()
        finally:
            self._teardown_all_streams()
            self._abort_pending_streams()
            await self._cancel_conn_tasks()
            writer = self.writer
            self.writer = None
            self.reader = None
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    def _teardown_all_streams(self):
        for stream in list(self.streams.values()):
            self._teardown_stream(stream, notify=False)
        self.streams.clear()

    def _abort_pending_streams(self):
        for stream_id, pending in list(self.pending_streams.items()):
            pending.closed = True
            if pending.connect_task is not None and not pending.connect_task.done():
                pending.connect_task.cancel()
        self.pending_streams.clear()

    async def _request_tunnel_open(self, spec: TunnelSpec):
        req = {"tunnel_id": spec.tunnel_id, "type": spec.type,
               "mode": spec.mode, "instance_id": self.instance_id,
               "capabilities": list(CLIENT_CAPABILITIES)}
        if spec.type == "http" and spec.subdomain:
            req["subdomain"] = spec.subdomain
        if spec.type in ("tcp", "udp") and spec.remote_port:
            req["remote_port"] = spec.remote_port
        self._open_inflight.add(spec.tunnel_id)
        await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(req).encode())

    # =========================================================================
    # Inbound frame dispatch
    # =========================================================================

    async def _dispatch_loop(self):
        self._last_frame_at = time.time()
        while True:
            frame = await read_frame(self.reader)
            self._last_frame_at = time.time()
            self.metrics["frames_in"] += 1
            try:
                if frame.version != PROTO_VERSION:
                    raise ProtocolError(
                        f"unsupported protocol version {frame.version}")
                await self._dispatch_frame(frame)
            except ProtocolError:
                # Framing violations are fatal for this connection: let the
                # run loop tear it down and reconnect.
                raise
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # A malformed payload must never kill the process. Count it,
                # log it, and keep serving the connection.
                self.metrics["errors"] += 1
                self._log(logging.WARNING, "Error handling frame type %s: %s",
                          frame.type, e)

    async def _dispatch_frame(self, frame):
        ftype = frame.type
        if ftype == FrameType.PING:
            await self._safe_send(FrameType.PONG, CONTROL_STREAM_ID)
        elif ftype == FrameType.PONG:
            pass
        elif ftype == FrameType.TUNNEL_OPEN_RESPONSE:
            self._handle_tunnel_open_response(frame)
        elif ftype == FrameType.TUNNEL_CLOSE:
            await self._handle_tunnel_close_from_server(frame)
        elif ftype == FrameType.STREAM_OPEN:
            self._handle_stream_open(frame)
        elif ftype == FrameType.STREAM_DATA:
            if len(frame.payload) > MAX_FRAME_PAYLOAD:
                raise ProtocolError(
                    f"STREAM_DATA payload {len(frame.payload)} exceeds "
                    f"{MAX_FRAME_PAYLOAD} bytes")
            self._route_stream_data(frame)
        elif ftype == FrameType.STREAM_EOF:
            self._route_stream_eof(frame)
        elif ftype == FrameType.STREAM_CLOSE:
            self._route_stream_close(frame)
        elif ftype == FrameType.STREAM_WINDOW_UPDATE:
            self._handle_window_update(frame)
        elif ftype == FrameType.UDP_DATAGRAM:
            if len(frame.payload) > MAX_FRAME_PAYLOAD:
                raise ProtocolError(
                    f"UDP_DATAGRAM payload {len(frame.payload)} exceeds "
                    f"{MAX_FRAME_PAYLOAD} bytes")
            self._route_udp_datagram(frame)
        elif ftype == FrameType.ERROR:
            self._handle_error_frame(frame)
        else:
            self._log(logging.WARNING, "Unknown frame type %s from server", ftype)

    def _handle_error_frame(self, frame):
        try:
            info = json.loads(frame.payload.decode())
            text = info.get("error") if isinstance(info, dict) else frame.payload[:200]
        except Exception:
            text = frame.payload[:200]
        self._log(logging.WARNING, "Server error: %s", text)

    async def _inactivity_watchdog(self):
        """The server pings us periodically and expects any frame back
        within its heartbeat_timeout; symmetrically, if we haven't seen ANY
        frame from the server in a while, the connection is probably dead
        even if the OS hasn't told us yet (e.g. a silently dropped path).
        Force a reconnect rather than hanging indefinitely."""
        self._last_frame_at = time.time()
        timeout = max(self._heartbeat_interval * 3, 30)
        while True:
            await asyncio.sleep(5)
            if self._shutdown_requested:
                return
            if time.time() - self._last_frame_at > timeout:
                self._log(logging.WARNING, "No data from server in %.0fs; reconnecting", timeout)
                self._abort_connection()
                return

    def _abort_connection(self):
        """Force the current control connection to drop (watchdog/teardown)."""
        writer = self.writer
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass

    def _handle_tunnel_open_response(self, frame):
        try:
            resp = json.loads(frame.payload.decode())
            if not isinstance(resp, dict):
                raise ValueError("payload is not a JSON object")
        except (ValueError, UnicodeDecodeError):
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Malformed TUNNEL_OPEN_RESPONSE: %r", frame.payload[:200])
            return
        tunnel_id = resp.get("tunnel_id")
        if not isinstance(tunnel_id, str):
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "TUNNEL_OPEN_RESPONSE without tunnel_id")
            return
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None:
            return
        self._open_inflight.discard(tunnel_id)
        if resp.get("status") == "ok":
            runtime.status = "active"
            runtime.error = None
            runtime.failure_count = 0
            self._cancel_retry(tunnel_id)
            mode_note = " [lease]" if runtime.spec.mode == TUNNEL_MODE_LEASE else ""
            if resp.get("type") == "http":
                runtime.public_url = resp.get("public_url")
                granted = resp.get("subdomain")
                if not isinstance(granted, str) or not granted:
                    # Older servers do not report the granted subdomain; fall
                    # back to parsing the first hostname label of the URL.
                    granted = _subdomain_from_url(runtime.public_url)
                if granted:
                    runtime.spec.subdomain = granted
                self._log(logging.INFO, "HTTP tunnel ready%s: %s -> %s:%s",
                          mode_note, runtime.public_url,
                          runtime.spec.local_host, runtime.spec.local_port)
            else:
                port = resp.get("remote_port")
                host = resp.get("public_host", self.server_host)
                scheme = "udp" if resp.get("type") == "udp" else "tcp"
                runtime.public_url = f"{scheme}://{host}:{port}"
                runtime.spec.remote_port = port
                self._log(logging.INFO, "%s tunnel ready%s: %s -> %s:%s",
                          scheme.upper(), mode_note, runtime.public_url,
                          runtime.spec.local_host, runtime.spec.local_port)
        else:
            runtime.status = "error"
            runtime.error = resp.get("error", "unknown error")
            runtime.failure_count += 1

            # Don't spam identical failures: log the first one and then at
            # most one reminder a minute while the retry loop keeps trying.
            now = time.time()
            if runtime.failure_count == 1 or now - runtime.last_error_notice >= 60:
                runtime.last_error_notice = now
                attempt_note = "" if runtime.failure_count == 1 else \
                    f" (attempt {runtime.failure_count})"
                hint = ""
                reason = resp.get("reason")
                if reason == "leased":
                    hint = ("\n  A lease protects that name. Pick a different -u value, or stop "
                            "the client currently holding it.")
                elif reason == "in_use" and runtime.spec.mode == TUNNEL_MODE_LEASE:
                    hint = ("\n  --lease never takes over an existing tunnel. Reconnect without "
                            "--lease to hand the name over to this client.")
                self._log(logging.ERROR, "Tunnel '%s' failed: %s%s%s",
                          runtime.label(), runtime.error, attempt_note, hint)
            self._schedule_tunnel_retry(runtime)
        self._save_state()

    def _schedule_tunnel_retry(self, runtime: TunnelRuntime):
        tunnel_id = runtime.spec.tunnel_id
        if tunnel_id in self._revoked_tunnel_ids:
            return
        existing = self._retry_tasks.get(tunnel_id)
        if existing is not None and not existing.done():
            return
        self._retry_tasks[tunnel_id] = asyncio.create_task(self._tunnel_retry_loop(runtime))

    def _cancel_retry(self, tunnel_id: str):
        task = self._retry_tasks.pop(tunnel_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def _cancel_all_retries(self):
        tasks = [t for t in self._retry_tasks.values() if not t.done()]
        self._retry_tasks.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _cancel_all_retries_now(self):
        tasks = [t for t in self._retry_tasks.values() if not t.done()]
        self._retry_tasks.clear()
        for task in tasks:
            task.cancel()

    async def _tunnel_retry_loop(self, runtime: TunnelRuntime):
        """Keep re-requesting a tunnel whose registration failed.

        A name can be temporarily unavailable (leased by a client that is
        still being cleaned up, no free ports, ...) and the situation can
        change at any time, so the client keeps asking instead of leaving the
        tunnel dead until someone restarts it."""
        tunnel_id = runtime.spec.tunnel_id
        try:
            while (not self._shutdown_requested
                   and runtime.status == "error"
                   and tunnel_id not in self._revoked_tunnel_ids):
                await asyncio.sleep(self.retry_interval)
                if self._shutdown_requested or runtime.status != "error":
                    break
                if tunnel_id in self._revoked_tunnel_ids:
                    break
                if self.status != "connected" or self.writer is None:
                    continue
                if tunnel_id in self._open_inflight:
                    continue
                try:
                    await self._request_tunnel_open(runtime.spec)
                except (ConnectionError, OSError) as e:
                    self.log.debug("Retry of tunnel %s failed to send: %s", runtime.label(), e)
                    break
        except asyncio.CancelledError:
            raise
        finally:
            if self._retry_tasks.get(tunnel_id) is asyncio.current_task():
                self._retry_tasks.pop(tunnel_id, None)

    async def _handle_tunnel_close_from_server(self, frame):
        """Server-initiated tunnel removal (handoff, reclaim, shutdown)."""
        try:
            info = json.loads(frame.payload.decode() or "{}")
            if not isinstance(info, dict):
                info = {}
        except (ValueError, UnicodeDecodeError):
            info = {}
        tunnel_id = info.get("tunnel_id")
        runtime = self.tunnels.get(tunnel_id) if isinstance(tunnel_id, str) else None
        if runtime is None:
            return
        reason = info.get("reason") or "closed"
        message = info.get("message") or f"Tunnel '{runtime.label()}' was closed by the server"

        self._cancel_retry(tunnel_id)
        self._open_inflight.discard(tunnel_id)

        if reason == "reclaimed":
            # Same client re-claiming its own registration during a
            # reconnect; the tunnel is re-opened by the matching response.
            runtime.status = "pending"
            return

        self._revoked_tunnel_ids.add(tunnel_id)

        # Tear down any local sockets belonging to the revoked tunnel.
        for stream in list(self.streams.values()):
            if stream.tunnel_id == tunnel_id:
                self._teardown_stream(stream, notify=False)
        for stream_id, p in list(self.pending_streams.items()):
            if p.tunnel_id == tunnel_id:
                p.closed = True
                if p.connect_task is not None and not p.connect_task.done():
                    p.connect_task.cancel()
                self._drop_pending(stream_id, p)

        if reason == "handoff":
            runtime.status = "handed_off"
            runtime.error = None
            self._log(logging.WARNING,
                      "%s -- this client stops serving it. That is normal when another client "
                      "claims the same name (handoff mode).", message)
        else:
            runtime.status = "closed"
            self._log(logging.WARNING, "%s (reason: %s)", message, reason)

        self._save_state()

        if all(r.status in ("handed_off", "closed") for r in self.tunnels.values()):
            self._log(logging.INFO, "No tunnels left to serve; exiting.")
            await self._begin_exit()

    async def _begin_exit(self):
        """Leave without treating the closed connection as a failure."""
        self._shutdown_requested = True
        self._shutdown_event.set()
        self.status = "stopped"
        self._save_state("stopped")
        self._cancel_all_retries_now()
        self._abort_connection()

    def _handle_stream_open(self, frame):
        """Register the pending stream immediately (so any STREAM_DATA that
        arrives before the local connection finishes has somewhere to be
        buffered), then establish the local backend in the background."""
        try:
            meta = json.loads(frame.payload.decode())
            if not isinstance(meta, dict):
                raise ValueError("payload is not a JSON object")
        except (ValueError, UnicodeDecodeError):
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Malformed STREAM_OPEN: %r", frame.payload[:200])
            return
        tunnel_id = meta.get("tunnel_id")
        proto = meta.get("proto", "tcp")
        if not isinstance(tunnel_id, str) or not tunnel_id:
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "STREAM_OPEN without a tunnel_id")
            return
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        if frame.stream_id in self.streams or frame.stream_id in self.pending_streams:
            # Duplicate/replacement STREAM_OPEN for an id we already own:
            # refuse instead of installing a second state object under the id.
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Ignoring duplicate STREAM_OPEN for stream %s",
                      frame.stream_id)
            return
        if len(self.streams) + len(self.pending_streams) >= MAX_LOCAL_STREAMS:
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Refusing stream %s: local stream limit (%s) reached",
                      frame.stream_id, MAX_LOCAL_STREAMS)
            self._track_task(self._safe_send(FrameType.STREAM_CLOSE, frame.stream_id))
            return
        pending = PendingStream(tunnel_id=tunnel_id, proto=proto)
        self.pending_streams[frame.stream_id] = pending
        generation = self._generation
        if proto == "udp":
            pending.connect_task = self._track_task(self._establish_udp_stream(
                frame.stream_id, tunnel_id, pending, generation))
        else:
            pending.connect_task = self._track_task(self._establish_stream(
                frame.stream_id, tunnel_id, pending, generation))

    def _teardown_stream(self, stream: ClientStream, *, notify: bool = False):
        """Single idempotent teardown path for a stream.

        Cancels the stream's tasks, aborts its flow window (so a pump blocked
        on zero credit wakes up instead of leaking until reconnect), closes the
        local socket / datagram transport, and removes it from the registry.
        `notify` sends a full STREAM_CLOSE to the server (used when *we* abort;
        never when the server already closed the stream)."""
        if stream.closed:
            return
        stream.closed = True
        stream.send_window.abort()
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in (stream.write_task, stream.pump_task, stream.udp_send_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        if stream.udp_transport is not None:
            try:
                stream.udp_transport.close()
            except Exception:
                pass
            stream.udp_transport = None
        self._udp_queued_bytes = max(0, self._udp_queued_bytes - stream.udp_queue_bytes)
        stream.udp_queue_bytes = 0
        if stream.local_writer is not None:
            try:
                stream.local_writer.close()
            except Exception:
                pass
        self.streams.pop(stream.stream_id, None)
        self.pending_streams.pop(stream.stream_id, None)
        if notify and not self._shutdown_requested and self.writer is not None:
            try:
                self._track_task(self._send_checked(
                    FrameType.STREAM_CLOSE, stream.stream_id, gen=stream.generation))
            except RuntimeError:
                pass  # no running loop (e.g. called from a sync probe)

    def _maybe_finish_stream(self, stream: ClientStream):
        """Full teardown once both directions are actually finished: our local
        write-half is closed AND every byte the server queued before its EOF
        has been flushed to the local backend."""
        if stream.closed:
            return
        if stream.recv_eof_drained and stream.local_eof:
            self._teardown_stream(stream, notify=False)

    def _drop_pending(self, stream_id: int, pending: PendingStream):
        """Remove the pending entry only if it is still the object we own, so
        a late cleanup cannot pop a newer stream that reused the id."""
        if self.pending_streams.get(stream_id) is pending:
            self.pending_streams.pop(stream_id, None)

    async def _establish_stream(self, stream_id: int, tunnel_id: str,
                                pending: PendingStream, generation: int):
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None or tunnel_id in self._revoked_tunnel_ids:
            self._drop_pending(stream_id, pending)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        spec = runtime.spec
        try:
            local_reader, local_writer = await asyncio.wait_for(
                asyncio.open_connection(spec.local_host, spec.local_port), timeout=10
            )
        except (OSError, asyncio.TimeoutError) as e:
            self._log(logging.WARNING, "Local service %s:%s unreachable for tunnel %s: %s",
                      spec.local_host, spec.local_port, tunnel_id[:8], e)
            self._drop_pending(stream_id, pending)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        # Identity guard: a late local connect must not resurrect a stream
        # that was closed, handed off, or replaced while connecting.
        if (pending.closed
                or self.pending_streams.get(stream_id) is not pending
                or generation != self._generation
                or self._shutdown_requested
                or runtime.status in ("handed_off", "closed")
                or tunnel_id in self._revoked_tunnel_ids):
            try:
                local_writer.close()
            except Exception:
                pass
            self._drop_pending(stream_id, pending)
            return

        stream = ClientStream(stream_id=stream_id, tunnel_id=tunnel_id,
                              local_reader=local_reader, local_writer=local_writer,
                              generation=generation)
        self.streams[stream_id] = stream
        self._drop_pending(stream_id, pending)
        runtime.connection_count += 1
        self.metrics["streams_opened"] += 1

        stream.write_task = self._track_task(self._stream_write_loop(stream))
        # Replay any STREAM_DATA that arrived while we were still connecting.
        buffered = pending.buffered
        pending.buffered = []
        for payload in buffered:
            self._enqueue_recv(stream, payload)
        if pending.eof and not stream.closed:
            stream.recv_eof = True
            stream.recv_queue.put_nowait(_QUEUE_EOF)
        if not stream.closed:
            stream.pump_task = self._track_task(self._pump_local_to_server(stream))
            self._maybe_finish_stream(stream)

    async def _establish_udp_stream(self, stream_id: int, tunnel_id: str,
                                    pending: PendingStream, generation: int):
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None or tunnel_id in self._revoked_tunnel_ids:
            self._drop_pending(stream_id, pending)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        spec = runtime.spec
        loop = asyncio.get_running_loop()
        client = self

        stream = ClientStream(stream_id=stream_id, tunnel_id=tunnel_id,
                              local_reader=None, local_writer=None,
                              generation=generation, is_udp=True)

        class _UdpProtocol(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                # Attach the transport only to the exact stream object that
                # owns this connection: a stale callback must never hand a
                # transport to a newer stream that reused the id.
                if (client.streams.get(stream_id) is not stream
                        or stream.closed
                        or generation != client._generation):
                    try:
                        transport.close()
                    except Exception:
                        pass
                    return
                stream.udp_transport = transport

            def datagram_received(self, data, addr):
                if client.streams.get(stream_id) is stream and not stream.closed:
                    client._udp_enqueue_to_server(stream_id, data)

            def error_received(self, exc):
                client._log(logging.DEBUG, "Local UDP %s:%s error for tunnel %s: %s",
                            spec.local_host, spec.local_port, tunnel_id[:8], exc)

            def connection_lost(self, exc):
                if client.streams.get(stream_id) is stream and not stream.closed:
                    client._teardown_stream(stream, notify=True)

        self.streams[stream_id] = stream
        self._drop_pending(stream_id, pending)
        runtime.connection_count += 1
        self.metrics["streams_opened"] += 1

        try:
            await asyncio.wait_for(
                loop.create_datagram_endpoint(_UdpProtocol,
                                              remote_addr=(spec.local_host, spec.local_port)),
                timeout=10,
            )
        except (OSError, asyncio.TimeoutError) as e:
            self._log(logging.WARNING, "Local UDP %s:%s unreachable for tunnel %s: %s",
                      spec.local_host, spec.local_port, tunnel_id[:8], e)
            self._teardown_stream(stream, notify=False)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        # Identity/lifecycle guard after the await: the stream may have been
        # closed, handed off, or the connection replaced meanwhile.
        if (pending.closed
                or self.streams.get(stream_id) is not stream
                or generation != self._generation
                or self._shutdown_requested
                or runtime.status in ("handed_off", "closed")
                or tunnel_id in self._revoked_tunnel_ids
                or stream.udp_transport is None):
            self._teardown_stream(stream, notify=False)
            return

        # Replay datagrams queued while the local endpoint was being created.
        buffered = pending.buffered
        pending.buffered = []
        queued = list(buffered) + list(stream.udp_pending)
        stream.udp_pending = []
        stream.udp_pending_bytes = 0
        for payload, legacy in queued:
            if stream.closed:
                break
            self._udp_send_local(stream, payload)
            if legacy:
                await self._credit_received_data(stream, len(payload))
        if not stream.closed:
            stream.udp_send_task = self._track_task(self._udp_to_server_loop(stream))

    def _udp_enqueue_to_server(self, stream_id: int, payload: bytes):
        """Queue one local-backend datagram for the single sender task.
        A full queue drops the datagram (UDP semantics) instead of spawning
        an unbounded number of asyncio jobs."""
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed:
            return
        if (stream.udp_queue.qsize() >= UDP_QUEUE_MAX
                or stream.udp_queue_bytes + len(payload) > INITIAL_WINDOW
                or self._udp_queued_bytes + len(payload) > MAX_TOTAL_UDP_QUEUED):
            stream.udp_dropped += 1
            self.metrics["udp_dropped"] += 1
            return
        stream.udp_queue.put_nowait(payload)
        stream.udp_queue_bytes += len(payload)
        self._udp_queued_bytes += len(payload)

    async def _udp_to_server_loop(self, stream: ClientStream):
        try:
            while not stream.closed:
                payload = await stream.udp_queue.get()
                if payload is None:
                    break
                stream.udp_queue_bytes = max(0, stream.udp_queue_bytes - len(payload))
                self._udp_queued_bytes = max(0, self._udp_queued_bytes - len(payload))
                if len(payload) > UDP_MAX_DATAGRAM:
                    # Cannot be represented on the wire; drop it like any other
                    # oversized datagram.
                    stream.udp_dropped += 1
                    self.metrics["udp_dropped"] += 1
                    continue
                if not await self._send_checked(FrameType.UDP_DATAGRAM,
                                                stream.stream_id, payload,
                                                gen=stream.generation):
                    break
                runtime = self.tunnels.get(stream.tunnel_id)
                if runtime is not None:
                    runtime.bytes_in += len(payload)
                    self._record_first_byte(stream, runtime)
        except asyncio.CancelledError:
            raise
        finally:
            self._maybe_finish_stream(stream)

    def _udp_send_local(self, stream: ClientStream, payload: bytes):
        if stream.closed or stream.udp_transport is None:
            return
        transport = stream.udp_transport
        try:
            if payload:
                transport.sendto(payload)
            else:
                # Python's datagram transport silently drops zero-length
                # sendto(), but an empty UDP datagram is legal and meaningful.
                # Write it through the underlying non-blocking socket (the
                # transport was created with a fixed remote address, so it is
                # connected). Never block.
                sock = getattr(transport, "_sock", None)
                if sock is None:
                    extra = transport.get_extra_info("socket")
                    sock = getattr(extra, "_sock", None)
                if sock is not None and hasattr(sock, "send"):
                    try:
                        sock.send(b"")
                    except (BlockingIOError, InterruptedError):
                        return  # drop like any congested UDP send
                    except OSError:
                        return
                else:
                    transport.sendto(b"")
        except (OSError, ConnectionError):
            return
        runtime = self.tunnels.get(stream.tunnel_id)
        if runtime is not None:
            runtime.bytes_out += len(payload)

    def _route_udp_datagram(self, frame):
        """Server -> client datagram (new protocol; carries no flow credit)."""
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            if not stream.is_udp:
                self.metrics["errors"] += 1
                self._log(logging.WARNING,
                          "UDP_DATAGRAM for non-UDP stream %s; ignoring", frame.stream_id)
                return
            self._route_udp_payload(stream, frame.payload, legacy=False)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            if pending.proto != "udp":
                self.metrics["errors"] += 1
                self._log(logging.WARNING,
                          "UDP_DATAGRAM for non-UDP pending stream %s; ignoring",
                          frame.stream_id)
                return
            self._buffer_pending(frame.stream_id, pending, frame.payload, legacy=False)

    def _route_udp_payload(self, stream: ClientStream, payload: bytes, *, legacy: bool):
        """Deliver a datagram to the local UDP backend, buffering it until the
        local endpoint exists. `legacy` marks payloads that arrived as
        STREAM_DATA and therefore consumed server flow-control credit."""
        if stream.closed:
            return
        if legacy:
            stream.unacked_recv_bytes += len(payload)
            if stream.unacked_recv_bytes > INITIAL_WINDOW:
                self.metrics["errors"] += 1
                self._log(logging.WARNING,
                          "UDP stream %s exceeded its receive credit; aborting",
                          stream.stream_id)
                self._teardown_stream(stream, notify=True)
                return
        if stream.udp_transport is None:
            if (len(stream.udp_pending) >= MAX_PENDING_FRAMES
                    or stream.udp_pending_bytes + len(payload) > STREAM_BUFFER_LIMIT):
                self.metrics["errors"] += 1
                self._log(logging.WARNING, "UDP stream %s overflowed its pre-connect "
                          "buffer; aborting", stream.stream_id)
                self._teardown_stream(stream, notify=True)
                return
            stream.udp_pending.append((payload, legacy))
            stream.udp_pending_bytes += len(payload)
            return
        self._udp_send_local(stream, payload)
        if legacy:
            self._track_task(self._credit_received_data(stream, len(payload)))

    def _buffer_pending(self, stream_id: int, pending: PendingStream, payload: bytes,
                        *, legacy: bool = False):
        if (pending.buffered_bytes + len(payload) > STREAM_BUFFER_LIMIT
                or len(pending.buffered) >= MAX_PENDING_FRAMES):
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Stream for tunnel %s overflowed its pre-connect "
                      "buffer; aborting", pending.tunnel_id[:8])
            pending.closed = True
            if pending.connect_task is not None and not pending.connect_task.done():
                pending.connect_task.cancel()
            self._drop_pending(stream_id, pending)
            self._track_task(self._safe_send(FrameType.STREAM_CLOSE, stream_id))
            return
        if pending.proto == "udp":
            pending.buffered.append((payload, legacy))
        else:
            pending.buffered.append(payload)
        pending.buffered_bytes += len(payload)

    def _route_stream_data(self, frame):
        if not frame.payload:
            stream = self.streams.get(frame.stream_id)
            pending = self.pending_streams.get(frame.stream_id)
            is_udp = ((stream is not None and stream.is_udp)
                      or (pending is not None and pending.proto == "udp"))
            if not is_udp:
                # Empty TCP STREAM_DATA carries nothing and is a cheap
                # memory/CPU flood vector; ignore it. (Empty UDP datagrams are
                # meaningful and handled below.)
                return
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            if stream.is_udp:
                # Legacy server: UDP payload arrives as STREAM_DATA, which
                # consumed flow-control credit. Route it as a datagram and
                # replenish that credit (bounded) so the sender is not stalled.
                self._route_udp_payload(stream, frame.payload, legacy=True)
                return
            self._enqueue_recv(stream, frame.payload)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            self._buffer_pending(frame.stream_id, pending, frame.payload,
                                 legacy=(pending.proto == "udp"))

    def _enqueue_recv(self, stream: ClientStream, payload: bytes):
        if stream.closed or not payload:
            return
        n = len(payload)
        # Strict receive-window accounting: unacked_recv_bytes counts bytes
        # received but not yet credited, including queued/in-flight data.
        if (stream.unacked_recv_bytes + n > INITIAL_WINDOW
                or stream.recv_queue.qsize() >= MAX_PENDING_FRAMES
                or stream.queued_bytes + n > STREAM_BUFFER_LIMIT):
            # A peer that respects the advertised window can never reach this;
            # abort instead of buffering beyond what we advertised.
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Stream %s exceeded the receive window; aborting",
                      stream.stream_id)
            self._teardown_stream(stream, notify=True)
            return
        stream.unacked_recv_bytes += n
        stream.queued_bytes += n
        if stream.queued_bytes > self.metrics["queue_high_water"]:
            self.metrics["queue_high_water"] = stream.queued_bytes
        stream.recv_queue.put_nowait(payload)

    def _route_stream_eof(self, frame):
        """Server half-closed a stream (STREAM_EOF)."""
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            pending = self.pending_streams.get(frame.stream_id)
            if pending is not None:
                pending.eof = True
            return
        if stream.udp_transport is not None or stream.is_udp:
            return  # datagrams have no half-close
        if stream.recv_eof or stream.recv_eof_drained:
            return
        stream.recv_eof = True
        stream.recv_queue.put_nowait(_QUEUE_EOF)
        # Do NOT finish here: the write task marks recv_eof_drained only after
        # it has actually flushed every queued byte to the local backend.

    def _route_stream_close(self, frame):
        """STREAM_CLOSE is a full abort (either direction)."""
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            self._teardown_stream(stream, notify=False)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            pending.closed = True
            if pending.connect_task is not None and not pending.connect_task.done():
                pending.connect_task.cancel()
            self._drop_pending(frame.stream_id, pending)

    async def _stream_write_loop(self, stream: ClientStream):
        """Drain server->local data in order, then half-close the local socket
        after a STREAM_EOF. Running as its own task keeps the central
        dispatcher free, so heartbeats are answered even when a local backend
        is slow."""
        try:
            while not stream.closed:
                item = await stream.recv_queue.get()
                if item is _QUEUE_EOF:
                    await self._flush_local_halfclose(stream)
                    # Mark the receive direction fully drained only now, after
                    # every queued byte was written; this prevents truncating a
                    # response when the local side already finished.
                    stream.recv_eof_drained = True
                    self._maybe_finish_stream(stream)
                    break
                stream.queued_bytes = max(0, stream.queued_bytes - len(item))
                if not await self._write_to_local(stream, item):
                    return
                await self._credit_received_data(stream, len(item))
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError):
            self._teardown_stream(stream, notify=True)
        finally:
            self._maybe_finish_stream(stream)

    async def _flush_local_halfclose(self, stream: ClientStream):
        if stream.udp_transport is not None:
            return
        writer = stream.local_writer
        if writer is None:
            return
        try:
            writer.write_eof()
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError, NotImplementedError):
            pass

    async def _pump_local_to_server(self, stream: ClientStream):
        """Read from the local backend and forward as STREAM_DATA frames,
        chunked to MAX_FRAME_PAYLOAD and respecting this stream's flow
        control window -- mirrors the server's send_stream_data exactly."""
        try:
            while True:
                if stream.closed or stream.send_window.aborted:
                    return
                await stream.send_window.wait()
                if stream.closed or stream.send_window.aborted:
                    return
                chunk = await stream.local_reader.read(MAX_FRAME_PAYLOAD)
                if not chunk:
                    await self._half_close_to_server(stream)
                    return
                await self._send_stream_data(stream, chunk)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            self._teardown_stream(stream, notify=True)
        finally:
            self._maybe_finish_stream(stream)

    async def _half_close_to_server(self, stream: ClientStream):
        """Local backend reached EOF. With a stream_eof-capable server, send
        STREAM_EOF and wait for the server's own EOF before tearing down; with
        a legacy server, keep the old full-close semantics."""
        if stream.closed:
            return
        stream.local_eof = True
        if self._server_supports_eof and stream.generation == self._generation:
            await self._send_checked(FrameType.STREAM_EOF, stream.stream_id,
                                     gen=stream.generation)
            self._maybe_finish_stream(stream)
            return
        await self._send_checked(FrameType.STREAM_CLOSE, stream.stream_id,
                                 gen=stream.generation)
        self._teardown_stream(stream, notify=False)

    async def _send_stream_data(self, stream: ClientStream, data: bytes):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if stream.closed or stream.send_window.aborted:
                return
            await stream.send_window.wait()
            if stream.closed or stream.send_window.aborted:
                return
            chunk = view[offset: offset + MAX_FRAME_PAYLOAD]
            if stream.send_window.available > 0:
                chunk = chunk[: max(1, min(len(chunk), stream.send_window.available))]
            # Consume before awaiting the send: a peer WINDOW_UPDATE may
            # arrive while we wait for the write lock/drain, and counting the
            # bytes only afterwards would momentarily overstate credit.
            stream.send_window.consume(len(chunk))
            if not await self._send_checked(FrameType.STREAM_DATA, stream.stream_id,
                                            bytes(chunk), gen=stream.generation):
                # A failed send means the stream/connection is going away, so
                # the consumed credit does not need to be rolled back.
                return
            runtime = self.tunnels.get(stream.tunnel_id)
            if runtime is not None:
                runtime.bytes_in += len(chunk)
                self._record_first_byte(stream, runtime)
            offset += len(chunk)

    def _record_first_byte(self, stream: ClientStream, runtime: TunnelRuntime):
        """Truthful latency metric: elapsed time from stream open to the first
        payload byte, not an invented network round-trip time."""
        if stream.first_byte_recorded:
            return
        stream.first_byte_recorded = True
        runtime.latencies_ms.append(max(0.0, (time.time() - stream.opened_at) * 1000))

    async def _write_to_local(self, stream: ClientStream, payload: bytes) -> bool:
        """Write server->client payload to the local backend socket. Returns
        False (and tears the stream down) on a local write error. Flow-control
        credit is replenished by the caller only after a successful write, so
        a slow local service applies real backpressure."""
        writer = stream.local_writer
        if stream.closed or writer is None:
            return False
        try:
            writer.write(payload)
            await writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            self._teardown_stream(stream, notify=True)
            return False
        runtime = self.tunnels.get(stream.tunnel_id)
        if runtime is not None:
            runtime.bytes_out += len(payload)
        return True

    async def _credit_received_data(self, stream: ClientStream, n: int):
        """Receive-side credit accounting.

        `unacked_recv_bytes` tracks bytes received but not yet credited (the
        peer's outstanding window). Credit is released only after the data has
        been delivered to the local backend, and sent in bounded batches."""
        if n <= 0 or stream.closed:
            return
        stream.unacked_recv_bytes = max(0, stream.unacked_recv_bytes - n)
        stream.credit_pending += n
        if stream.credit_pending >= WINDOW_UPDATE_THRESHOLD:
            increment = min(stream.credit_pending, INITIAL_WINDOW)
            stream.credit_pending -= increment
            await self._send_checked(
                FrameType.STREAM_WINDOW_UPDATE, stream.stream_id,
                increment.to_bytes(4, "big"), gen=stream.generation)

    def _handle_window_update(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            return
        if len(frame.payload) != 4:
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "Malformed STREAM_WINDOW_UPDATE for stream %s",
                      frame.stream_id)
            return
        increment = int.from_bytes(frame.payload, "big")
        if increment <= 0 or increment > MAX_WINDOW_CREDIT:
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "STREAM_WINDOW_UPDATE %s out of range (1..%s) for stream %s",
                      increment, MAX_WINDOW_CREDIT, frame.stream_id)
            return
        if not stream.send_window.replenish(increment):
            self.metrics["errors"] += 1
            self._log(logging.WARNING, "STREAM_WINDOW_UPDATE for stream %s capped at %s "
                      "send credit", frame.stream_id, MAX_WINDOW_CREDIT)

    async def _send_checked(self, ftype: int, stream_id: int, payload: bytes = b"",
                            *, gen: Optional[int] = None) -> bool:
        """Send only if this stream still belongs to the live connection
        generation and the same writer. Generation is re-checked inside the
        write lock, so an old-generation waiter can never write to a new
        writer after reconnecting."""
        writer = self.writer
        if self._shutdown_requested or writer is None or writer.is_closing():
            return False
        if gen is not None and gen != self._generation:
            return False
        try:
            await self._send(ftype, stream_id, payload, gen=gen,
                             expected_writer=writer)
            return True
        except Exception:
            return False

    async def _safe_send(self, ftype: int, stream_id: int, payload: bytes = b"") -> bool:
        try:
            await self._send(ftype, stream_id, payload)
            return True
        except Exception:
            return False

    # -- snapshot for the dashboard -------------------------------------------

    def stats_snapshot(self) -> dict:
        now = time.time()
        tunnels = []
        for runtime in self.tunnels.values():
            spec = runtime.spec
            first_byte = runtime.avg_latency_ms()
            tunnels.append({
                "tunnel_id": runtime.spec.tunnel_id,
                "type": spec.type,
                "mode": spec.mode,
                "status": runtime.status,
                "public_url": runtime.public_url,
                "error": runtime.error,
                "local_destination": f"{spec.local_host}:{spec.local_port}",
                "connections": runtime.connection_count,
                "bytes_in": runtime.bytes_in,
                "bytes_out": runtime.bytes_out,
                # Time from stream open to first payload byte (not a network RTT).
                "first_byte_ms": first_byte,
                "avg_latency_ms": first_byte,  # backwards-compatible alias
            })
        return {
            "status": self.status,
            "server": f"{self.server_host}:{self.server_port}",
            "client_id": self.client_id,
            "managed_id": self.managed_id,
            "instance_id": self.instance_id,
            "tls": self.tls,
            "server_capabilities": sorted(self._server_capabilities),
            "process_uptime_seconds": round(now - self.process_start_time),
            "connected_since": self.connected_since,
            "connected_for_seconds": round(now - self.connected_since) if self.connected_since and self.status == "connected" else None,
            "reconnect_count": self.reconnect_count,
            "active_streams": len(self.streams) + len(self.pending_streams),
            "metrics": dict(self.metrics),
            "tunnels": tunnels,
            "recent_logs": list(self.recent_logs),
            "server_time": now,
        }


# =============================================================================
# Dashboard -- lightweight, read-only, no request inspection / replay /
# packet capture. Raw asyncio streams (no framework) to keep dependencies
# at zero.
# =============================================================================

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>my_proxy</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#d8dbe2; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; display:flex; align-items:center; gap:10px; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .dot.connected { background:#4ade80; }
  .dot.connecting, .dot.reconnecting { background:#facc15; }
  .dot.disconnected, .dot.stopped { background:#f87171; }
  .sub { color:#8a90a2; font-size:13px; margin-bottom:20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }
  .card { background:#171a21; border:1px solid #262b36; border-radius:10px; padding:14px 16px; }
  .card .label { font-size:12px; color:#8a90a2; text-transform:uppercase; letter-spacing:.04em; }
  .card .value { font-size:22px; font-weight:600; margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  caption { text-align:left; color:#8a90a2; font-size:12px; padding:0 0 6px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #262b36; }
  th { color:#8a90a2; font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
  .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; background:#26314a; color:#8fb3ff; margin-right:4px; }
  .tag.tcp { background:#312a1a; color:#e8b96a; }
  .tag.lease { background:#1f3326; color:#6ee7a0; }
  .tag.error { background:#3a1e22; color:#f87171; }
  .tag.pending { background:#2c2a1e; color:#e8d96a; }
  a { color:#8fb3ff; text-decoration:none; }
  a:hover { text-decoration:underline; }
  section { margin-bottom:28px; }
  h2 { font-size:15px; margin:0 0 10px; color:#c3c7d1; }
  #log { background:#0b0d11; border:1px solid #262b36; border-radius:10px; padding:10px 14px; height:200px; overflow-y:auto; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; white-space:pre-wrap; }
  .empty { color:#565c6c; font-style:italic; padding:14px; }
</style>
</head>
<body>
<h1><span class="dot" id="statusdot" role="img" aria-label="connection status"></span> my_proxy <span id="statustext" style="font-weight:400;color:#8a90a2;font-size:14px;"></span></h1>
<div class="sub" id="subtitle">loading...</div>

<div class="grid" id="summary-cards" aria-label="summary"></div>

<section>
  <h2 id="tunnels-heading">Tunnels</h2>
  <div id="tunnels" aria-labelledby="tunnels-heading"></div>
</section>

<section>
  <h2 id="log-heading">Recent Log Messages</h2>
  <div id="log" role="log" aria-live="polite" aria-labelledby="log-heading"></div>
</section>

<script>
function esc(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function safeUrl(u) {
  if (typeof u !== "string" || !u) return null;
  try {
    const p = new URL(u, window.location.origin);
    if (p.protocol === "http:" || p.protocol === "https:") return p.href;
  } catch (e) {}
  return null;
}
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B","KB","MB","GB","TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtDuration(s) {
  if (s === null || s === undefined) return "-";
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60), sec = Math.floor(s%60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${sec}s`;
  return `${sec}s`;
}
async function refresh() {
  let data;
  try {
    const resp = await fetch('/api/stats', { cache: 'no-store' });
    if (!resp.ok) return;
    data = await resp.json();
  } catch (e) { return; }

  document.getElementById('statusdot').className = 'dot ' + esc(data.status);
  document.getElementById('statustext').textContent = data.status;
  document.getElementById('subtitle').textContent =
    `server ${data.server} \u00b7 process uptime ${fmtDuration(data.process_uptime_seconds)} \u00b7 connected for ${fmtDuration(data.connected_for_seconds)} \u00b7 reconnects: ${data.reconnect_count}`;

  let bytesIn = 0, bytesOut = 0, conns = 0;
  data.tunnels.forEach(t => { bytesIn += t.bytes_in; bytesOut += t.bytes_out; conns += t.connections; });
  const metrics = data.metrics || {};

  const cards = [
    ["Status", data.status],
    ["Uptime", fmtDuration(data.process_uptime_seconds)],
    ["Reconnects", data.reconnect_count],
    ["Active tunnels", data.tunnels.filter(t => t.status === 'active').length],
    ["Active streams", data.active_streams],
    ["Total connections", conns],
    ["Bytes in", fmtBytes(bytesIn)],
    ["Bytes out", fmtBytes(bytesOut)],
    ["Errors", metrics.errors || 0],
  ];
  document.getElementById('summary-cards').innerHTML = cards.map(([l,v]) =>
    `<div class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></div>`).join('');

  const tunnelsEl = document.getElementById('tunnels');
  if (!data.tunnels.length) {
    tunnelsEl.textContent = 'No tunnels configured.';
  } else {
    const rows = data.tunnels.map(t => {
      const url = safeUrl(t.public_url);
      const statusClass = t.status === 'error' ? 'error' : (t.status === 'pending' ? 'pending' : '');
      const publicCell = url
        ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(t.public_url)}</a>`
        : esc(t.error || '-');
      const fb = (t.first_byte_ms !== null && t.first_byte_ms !== undefined)
        ? t.first_byte_ms.toFixed(0) + ' ms' : '-';
      return `<tr>
        <td><span class="tag ${esc(statusClass)}">${esc(t.status)}</span></td>
        <td><span class="tag ${esc(t.type)}">${esc(t.type)}</span></td>
        <td><span class="tag ${t.mode === 'lease' ? 'lease' : ''}">${esc(t.mode || 'handoff')}</span></td>
        <td>${publicCell}</td>
        <td>${esc(t.local_destination)}</td>
        <td>${esc(t.connections)}</td>
        <td>${esc(fmtBytes(t.bytes_in))}</td>
        <td>${esc(fmtBytes(t.bytes_out))}</td>
        <td>${esc(fb)}</td>
      </tr>`;
    }).join('');
    tunnelsEl.innerHTML = `
      <table>
        <caption>Tunnels exposed by this client</caption>
        <thead><tr>
          <th scope="col">Status</th><th scope="col">Protocol</th><th scope="col">Mode</th>
          <th scope="col">Public URL</th><th scope="col">Local destination</th>
          <th scope="col">Connections</th><th scope="col">Bytes in</th><th scope="col">Bytes out</th>
          <th scope="col">First byte</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  const logEl = document.getElementById('log');
  logEl.textContent = data.recent_logs.join('\\n');
  logEl.scrollTop = logEl.scrollHeight;
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


_MAX_DASH_REQUEST_LINE = 8 * 1024
_MAX_DASH_HEADERS = 64
_MAX_DASH_HEADER_BYTES = 16 * 1024

_DASH_SECURITY_HEADERS = (
    "X-Content-Type-Options: nosniff\r\n"
    "X-Frame-Options: DENY\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'none'; "
    "frame-ancestors 'none'; base-uri 'none'\r\n"
    "Cache-Control: no-store\r\n"
)


def _dashboard_response(status: int, reason: str, body: bytes, content_type: str,
                        *, head_only: bool = False) -> bytes:
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"{_DASH_SECURITY_HEADERS}"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("latin-1")
    return header if head_only else header + body


async def _handle_dashboard_conn(reader, writer, client: TunnelClient):
    try:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        except ValueError:
            writer.write(_dashboard_response(431, "Request Header Fields Too Large",
                                             b"request line too long", "text/plain"))
            await writer.drain()
            return
        if len(request_line) > _MAX_DASH_REQUEST_LINE:
            writer.write(_dashboard_response(431, "Request Header Fields Too Large",
                                             b"request line too long", "text/plain"))
            await writer.drain()
            return
        total = 0
        terminated = False
        for _ in range(_MAX_DASH_HEADERS):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
            except ValueError:
                writer.write(_dashboard_response(431, "Request Header Fields Too Large",
                                                 b"headers too large", "text/plain"))
                await writer.drain()
                return
            total += len(line)
            if total > _MAX_DASH_HEADER_BYTES:
                writer.write(_dashboard_response(431, "Request Header Fields Too Large",
                                                 b"headers too large", "text/plain"))
                await writer.drain()
                return
            if line in (b"\r\n", b"\n", b""):
                terminated = True
                break
        if not terminated:
            writer.write(_dashboard_response(431, "Request Header Fields Too Large",
                                             b"too many headers", "text/plain"))
            await writer.drain()
            return
        try:
            parts = request_line.decode(errors="replace").split(None, 2)
            if len(parts) < 2:
                raise ValueError
            method, raw_path = parts[0], parts[1]
        except ValueError:
            writer.write(_dashboard_response(400, "Bad Request", b"bad request", "text/plain"))
            await writer.drain()
            return

        path = raw_path  # exact match only: no query string, no prefix matching

        if method not in ("GET", "HEAD"):
            writer.write(_dashboard_response(405, "Method Not Allowed", b"method not allowed", "text/plain"))
            await writer.drain()
            return

        if path == "/api/stats":
            body = json.dumps(client.stats_snapshot()).encode()
            content_type = "application/json"
        elif path == "/":
            body = _DASHBOARD_HTML.encode()
            content_type = "text/html; charset=utf-8"
        else:
            writer.write(_dashboard_response(404, "Not Found", b"not found", "text/plain"))
            await writer.drain()
            return

        writer.write(_dashboard_response(200, "OK", body, content_type,
                                         head_only=(method == "HEAD")))
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def _is_loopback_host(host: str) -> bool:
    h = (host or "").strip().lower()
    if h in ("localhost", "::1", "[::1]"):
        return True
    if h.startswith("127."):
        return True
    return False


async def serve_dashboard(client: TunnelClient, host: str, port: int, log: logging.Logger):
    if not _is_loopback_host(host):
        log.warning(
            "Dashboard is bound to non-loopback address %s:%s and has NO authentication -- "
            "anyone who can reach it can read tunnel status. Prefer 127.0.0.1.", host, port)
    try:
        server = await asyncio.start_server(lambda r, w: _handle_dashboard_conn(r, w, client), host, port)
    except OSError as e:
        log.warning("Could not start dashboard on %s:%s (%s) -- continuing without it", host, port, e)
        return
    log.info("Dashboard: http://%s:%s", host, port)
    async with server:
        await server.serve_forever()


# =============================================================================
# CLI & Process Management
# =============================================================================

DEFAULT_SERVER = "127.0.0.1:9000"
DEFAULT_DASHBOARD = "127.0.0.1:4040"
DEFAULT_GRACE_TIME = 10.0
DEFAULT_RETRY_INTERVAL = 5.0
DEFAULT_STATE_FILE = Path.home() / ".my_proxy" / "state.json"


def _get_config_dir() -> Path:
    """Get the config directory, handling PyInstaller frozen executables.
    Uses ~/.config/linkpulse/ on all systems (XDG_CONFIG_HOME compliant)."""
    # XDG_CONFIG_HOME or ~/.config
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if config_home:
        base = Path(config_home)
    else:
        base = Path.home() / ".config"
    return base / "linkpulse"


def _get_clients_dir() -> Path:
    """Directory for persisting managed client instance state."""
    env_dir = os.environ.get("LINKPULSE_STATE_DIR")
    if env_dir:
        return Path(env_dir)
    return _get_config_dir() / "clients"


def _get_logs_dir() -> Path:
    """Directory for storing detached client logs."""
    env_dir = os.environ.get("LINKPULSE_LOGS_DIR")
    if env_dir:
        return Path(env_dir)
    return _get_config_dir() / "logs"


DEFAULT_TOKEN_FILE = _get_config_dir() / "authtoken.json"


class ConfigError(Exception):
    """User-facing configuration problem (friendly message, no traceback)."""


def _is_owned_app_dir(path: Path) -> bool:
    """True if `path` is (under) one of our own config/state directories."""
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    candidates = []
    try:
        candidates.append(_get_config_dir().resolve())
    except OSError:
        pass
    try:
        candidates.append(DEFAULT_STATE_FILE.parent.resolve())
    except OSError:
        pass
    for base in candidates:
        try:
            resolved.relative_to(base)
            return True
        except ValueError:
            continue
    return False


def _ensure_private_dir(path: Path) -> None:
    """Create `path` if needed and tighten it to 0700 only when it is ours.

    A user-supplied `--state-file /tmp/x.json` must not chmod the shared /tmp
    directory to 0700; only directories we created or that live under our own
    config/state roots are tightened. Permission failures on owned dirs are
    not suppressed (credentials must not be left world-readable silently)."""
    path = Path(path)
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        return
    if not existed or _is_owned_app_dir(path):
        os.chmod(path, 0o700)


def _atomic_write_json(path: Path, data: dict, mode: int = 0o600) -> None:
    """Write JSON atomically with restrictive permissions.

    A unique temp file in the destination directory is written, fsynced,
    chmodded, then os.replace()d into place, so a reader never sees a partial
    document and two writers never share a temp path."""
    path = Path(path)
    _ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read_state_raw(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


_CLIENT_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _validate_client_id(value) -> str:
    s = str(value).strip()
    if not _CLIENT_ID_RE.fullmatch(s):
        raise ConfigError("client id must be exactly 32 hex characters")
    return s.lower()


def _read_boot_id() -> Optional[str]:
    """Kernel boot id, used to tell PID reuse across a reboot from reuse
    within one boot. Linux only; None elsewhere."""
    try:
        text = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        return text or None
    except OSError:
        return None


def _proc_start_time(pid: int) -> Optional[int]:
    """Read a stable process start time used as a PID-reuse guard.

    Linux: field 22 of /proc/<pid>/stat (clock ticks since boot).
    macOS: `ps -o lstart=` parsed to epoch seconds.
    Windows: GetProcessTimes creation time (100 ns intervals).
    Returns None when it cannot be determined -- callers then fail closed."""
    if not pid or pid <= 0:
        return None
    if sys.platform == "win32":
        return _proc_start_time_windows(pid)
    if sys.platform == "darwin":
        return _proc_start_time_macos(pid)
    try:
        content = Path(f"/proc/{pid}/stat").read_text()
    except (OSError, PermissionError):
        return None
    # comm (field 2) is wrapped in parentheses and may itself contain spaces
    # or parentheses, so split off everything after the last ')'.
    rparen = content.rfind(")")
    if rparen == -1:
        return None
    rest = content[rparen + 1:].split()
    # After comm, field 3 is state; starttime is field 22 overall => index 19.
    if len(rest) < 20:
        return None
    try:
        return int(rest[19])
    except ValueError:
        return None


def _proc_start_time_macos(pid: int) -> Optional[int]:
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["TZ"] = "UTC"
    try:
        out = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True, text=True, timeout=5, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (out.stdout or "").strip()
    if out.returncode != 0 or not text:
        return None
    try:
        # LC_ALL=C + TZ=UTC makes lstart output timezone-stable; parse it as
        # UTC so the value is comparable across invocations.
        return int(calendar.timegm(time.strptime(text, "%a %b %d %H:%M:%S %Y")))
    except ValueError:
        return None


def _windows_process_info(pid: int) -> tuple[Optional[bool], Optional[int]]:
    """Return (alive, creation_start) for a PID from one process handle.

    Using a single handle avoids the open/verify/reopen PID-reuse race. Never
    uses os.kill (which maps to TerminateProcess on Windows)."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None, None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            err = ctypes.get_last_error()
            if err == 5:      # ERROR_ACCESS_DENIED: exists, cannot query
                return True, None
            return False, None
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None, None
            if code.value != STILL_ACTIVE:
                return False, None
            creation = wintypes.FILETIME()
            exit_time = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            ok = kernel32.GetProcessTimes(
                handle, ctypes.byref(creation), ctypes.byref(exit_time),
                ctypes.byref(kernel), ctypes.byref(user))
            start = ((creation.dwHighDateTime << 32) | creation.dwLowDateTime) if ok else None
            return True, start
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None, None


def _proc_start_time_windows(pid: int) -> Optional[int]:
    alive, start = _windows_process_info(pid)
    return start if alive else None


def _windows_process_alive(pid: int) -> Optional[bool]:
    """Windows liveness probe that never uses os.kill.

    On Windows, CPython's os.kill() maps to TerminateProcess for ordinary
    signal numbers -- so os.kill(pid, 0) would *kill* the process rather than
    probe it. Use OpenProcess + GetExitCodeProcess instead. Returns True/False,
    or None if liveness cannot be determined."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            err = ctypes.get_last_error()
            if err == 5:      # ERROR_ACCESS_DENIED: it exists, we just can't query it
                return True
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


def _windows_terminate_process(pid: int, exit_code: int = 1) -> bool:
    """Explicit TerminateProcess for a PID that the caller already verified."""
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        return False
    PROCESS_TERMINATE = 0x0001
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, int(pid))
        if not handle:
            return False
        try:
            return bool(kernel32.TerminateProcess(handle, int(exit_code)))
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def _is_pid_alive(pid: int, expected_start_time: Optional[int] = None,
                  expected_boot_id: Optional[str] = None) -> bool:
    """Check if process with given PID exists and is actively running.

    If expected_start_time is provided, the PID must also refer to a process
    that started at that time -- otherwise the original process has exited and
    the PID has been reused. If expected_boot_id is provided and the machine
    has rebooted since, the PID cannot be ours. On Windows this never calls
    os.kill (which would terminate the target)."""
    if not pid or pid <= 0:
        return False
    if expected_boot_id is not None:
        current_boot = _read_boot_id()
        # Strict: if we cannot read the boot id now, we cannot prove the PID
        # survived from the recorded boot, so fail closed.
        if current_boot is None or current_boot != expected_boot_id:
            return False

    if sys.platform == "win32":
        alive, actual_start = _windows_process_info(pid)
        if not alive:
            # False or unknown -> fail closed, never probe destructively.
            return False
        if expected_start_time is not None:
            return actual_start is not None and actual_start == expected_start_time
        return True
    else:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # The process exists but we may not be allowed to inspect it; fall
            # through so the start-time evidence (if required) is still checked.
            pass
        except OSError:
            return False

        proc_status = Path(f"/proc/{pid}/status")
        if proc_status.exists():
            try:
                content = proc_status.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    if line.startswith("State:"):
                        if "Z" in line or "zombie" in line.lower():
                            return False
                        break
            except (OSError, PermissionError):
                pass

    if expected_start_time is not None:
        actual = _proc_start_time(pid)
        # Strict: if the recorded start time cannot be read now, we cannot
        # prove this is the same process, so fail closed rather than assume.
        if actual is None or actual != expected_start_time:
            return False
    return True


def _verify_client_process(pid: int, state: dict) -> bool:
    """Verify that a PID really is the LinkPulse client recorded in `state`.

    The recorded start time (plus boot id, where available) is the only
    accepted evidence. When it is missing we fail closed and refuse to treat
    the PID as ours, so a reused PID belonging to an unrelated process is
    never signalled."""
    expected_start = state.get("start_time")
    expected_boot = state.get("boot_id")
    if not _is_pid_alive(pid, expected_start, expected_boot):
        return False
    if expected_start is not None:
        return True
    return False


def _terminate_pid(pid: int, force: bool = False) -> bool:
    """Best-effort signal that never raises.

    Windows has no SIGKILL and os.kill maps to TerminateProcess, so use the
    explicit TerminateProcess API there. Callers must have verified PID
    identity before calling this."""
    if sys.platform == "win32":
        return _windows_terminate_process(pid)
    try:
        if force and hasattr(signal, "SIGKILL"):
            os.kill(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, ValueError):
        return False


_CLIENT_LOOKUP_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _safe_state_file(path: Path, base: Path) -> bool:
    """True only for a regular, non-symlink file contained within `base`."""
    try:
        if path.is_symlink():
            return False
        resolved = path.resolve()
        resolved.relative_to(base.resolve())
    except (OSError, ValueError):
        return False
    return resolved.is_file()


def _find_client_state_file(client_id_or_prefix: str) -> tuple[Optional[Path], Optional[str]]:
    """Find the client state file matching a client id, managed id or
    unambiguous prefix.

    The lookup is validated (no separators / absolute paths), must resolve to
    a real file inside the clients directory, and refuses symlinks so a
    crafted name cannot make us read or delete an arbitrary file."""
    if not isinstance(client_id_or_prefix, str) or not _CLIENT_LOOKUP_RE.fullmatch(client_id_or_prefix):
        return None, ("Invalid client id/prefix: use only letters, digits, '-' and '_'.")
    clients_dir = _get_clients_dir()
    if not clients_dir.exists():
        return None, f"Client '{client_id_or_prefix}' not found."
    try:
        base = clients_dir.resolve()
    except OSError:
        base = clients_dir

    exact = clients_dir / f"{client_id_or_prefix}.json"
    if _safe_state_file(exact, base):
        return exact, None

    matches = []
    for f in sorted(clients_dir.glob("*.json")):
        if not _safe_state_file(f, base):
            continue
        # Match on the managed file stem (legacy layout) or on the recorded
        # machine client_id (current layout, where the stem is a managed id).
        if f.stem.startswith(client_id_or_prefix):
            matches.append(f)
            continue
        data = _read_client_state(f)
        cid = data.get("client_id")
        if isinstance(cid, str) and cid.startswith(client_id_or_prefix):
            matches.append(f)

    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        names = ", ".join(m.stem for m in matches[:5])
        return None, f"Ambiguous client ID prefix '{client_id_or_prefix}' matches multiple clients: {names}"
    return None, f"Client '{client_id_or_prefix}' not found."


def _format_uptime(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "-"
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{s}s")
    return " ".join(parts[:2]) if parts else "0s"


def _read_client_state(state_file: Path) -> dict:
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"client_id": state_file.stem, "status": "corrupt", "state_file": str(state_file)}
        return data
    except Exception:
        return {"client_id": state_file.stem, "status": "corrupt", "state_file": str(state_file)}


def _cli_clients_list() -> None:
    clients_dir = _get_clients_dir()
    if not clients_dir.exists():
        print("No LinkPulse clients found.")
        return

    client_files = sorted((f for f in clients_dir.glob("*.json") if _safe_state_file(f, clients_dir)),
                          key=lambda f: f.stat().st_mtime, reverse=True)
    if not client_files:
        print("No LinkPulse clients found.")
        return

    rows = []
    for f in client_files:
        data = _read_client_state(f)
        cid = data.get("client_id", f.stem)
        pid = data.get("pid", "-")
        mode = data.get("mode", "-")
        target = data.get("target", "-")
        server = data.get("server", "-")
        raw_status = data.get("status", "unknown")

        if raw_status == "corrupt":
            status = "corrupt"
        elif isinstance(pid, int) and pid > 0:
            if _verify_client_process(pid, data):
                status = raw_status if raw_status != "stopped" else "running"
            else:
                status = "stopped"
        else:
            status = "stopped"

        pid_str = str(pid) if isinstance(pid, int) and pid > 0 else "-"
        managed = data.get("managed_id") or f.stem
        rows.append((cid, managed, pid_str, mode, target, server, status))

    headers = ("CLIENT ID", "MANAGED ID", "PID", "MODE", "TARGET", "SERVER", "STATUS")
    col_widths = [len(h) for h in headers]
    for r in rows:
        for i, val in enumerate(r):
            col_widths[i] = max(col_widths[i], len(str(val)))

    fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
    print(fmt.format(*headers))
    for r in rows:
        print(fmt.format(*r))


def _cli_clients_info(client_id: str) -> None:
    state_file, err = _find_client_state_file(client_id)
    if err or not state_file:
        print(f"Error: {err or 'Client not found.'}", file=sys.stderr)
        sys.exit(1)

    data = _read_client_state(state_file)
    cid = data.get("client_id", state_file.stem)
    pid = data.get("pid")
    mode = data.get("mode", "-")
    target = data.get("target", "-")
    server = data.get("server", "-")
    started_at = data.get("started_at")
    started_at_iso = data.get("started_at_iso", "-")
    log_file = data.get("log_file") or "-"
    dashboard = data.get("dashboard")
    public_urls = data.get("public_urls", [])
    raw_status = data.get("status", "unknown")

    is_alive = False
    if isinstance(pid, int) and pid > 0:
        is_alive = _verify_client_process(pid, data)

    live_stats = None
    if is_alive and dashboard:
        try:
            req = urllib.request.Request(f"http://{dashboard}/api/stats")
            with urllib.request.urlopen(req, timeout=0.3) as resp:
                if resp.status == 200:
                    candidate = json.loads(resp.read(1_000_000).decode())
                    # Guard against multiple clients sharing the default
                    # dashboard port: only trust stats that belong to this
                    # exact process (client_id + instance_id).
                    expected_instance = data.get("instance_id")
                    if (candidate.get("client_id") == cid
                            and (not expected_instance
                                 or candidate.get("instance_id") == expected_instance)):
                        live_stats = candidate
        except Exception:
            pass

    if not is_alive:
        status = "stopped"
        uptime_str = "-"
    else:
        if live_stats:
            status = live_stats.get("status", "running")
            uptime_str = _format_uptime(live_stats.get("process_uptime_seconds"))
            dash_tunnels = live_stats.get("tunnels", [])
            if dash_tunnels:
                urls = [t.get("public_url") for t in dash_tunnels if t.get("public_url")]
                if urls:
                    public_urls = urls
        else:
            status = raw_status if raw_status != "stopped" else "running"
            uptime = (time.time() - started_at) if started_at else None
            uptime_str = _format_uptime(uptime)

    print(f"Client ID:       {cid}")
    if data.get("managed_id"):
        print(f"Managed ID:      {data['managed_id']}")
    print(f"PID:             {pid if pid else '-'}")
    print(f"Status:          {status}")
    print(f"Mode:            {mode}")
    print(f"Local target:    {target}")
    modes = []
    for t in ((live_stats or {}).get("tunnels") or data.get("tunnels", [])):
        if t.get("mode") and t["mode"] not in modes:
            modes.append(t["mode"])
    if modes:
        print(f"Tunnel modes:    {', '.join(modes)}")
    if public_urls:
        print(f"Public endpoint: {', '.join(public_urls)}")
    print(f"Server:          {server}")
    if dashboard:
        print(f"Dashboard:       http://{dashboard}")
    print(f"Started:         {started_at_iso}")
    print(f"Uptime:          {uptime_str}")
    if live_stats:
        conn_count = sum(t.get("connections", 0) for t in live_stats.get("tunnels", []))
        print(f"Connections:     {conn_count}")
    print(f"Log file:        {log_file}")
    print(f"State file:      {state_file}")


def _record_identity_state(pid, data: dict) -> str:
    """Classify a recorded PID without signalling it.

    Returns one of:
      verified - alive and matches the recorded start time/boot id
      dead     - not running (or no PID)
      reused   - alive but a *different* process now owns the PID (record stale)
      unknown  - alive but identity cannot be proven (fail closed)
    """
    if not (isinstance(pid, int) and pid > 0):
        return "dead"
    if _verify_client_process(pid, data):
        return "verified"
    if not _is_pid_alive(pid):
        return "dead"
    expected = data.get("start_time")
    if expected is None:
        return "unknown"
    actual = _proc_start_time(pid)
    if actual is None:
        return "unknown"
    if actual != expected:
        return "reused"
    return "unknown"


def _stop_verified_client(pid: int, data: dict, *, label: str) -> bool:
    """Gracefully stop a verified client PID, escalating to a force kill only
    after re-verifying identity (race guard). Never signals an unverified PID."""
    if not _verify_client_process(pid, data):
        return False
    expected_start = data.get("start_time")
    expected_boot = data.get("boot_id")
    print(f"Stopping client {label} (PID {pid})...")
    _terminate_pid(pid, force=False)
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if not _is_pid_alive(pid, expected_start, expected_boot):
            return True
        time.sleep(0.1)
    # Re-verify before escalating: the PID may have been reused meanwhile.
    if _is_pid_alive(pid, expected_start, expected_boot) and _verify_client_process(pid, data):
        _terminate_pid(pid, force=True)
        time.sleep(0.2)
    return not _is_pid_alive(pid, expected_start, expected_boot)


def _cli_clients_delete(client_id: str) -> None:
    state_file, err = _find_client_state_file(client_id)
    if err or not state_file:
        print(f"Error: {err or 'Client not found.'}", file=sys.stderr)
        sys.exit(1)

    data = _read_client_state(state_file)
    cid = data.get("client_id", state_file.stem)
    pid = data.get("pid")
    state = _record_identity_state(pid, data)

    if state == "unknown":
        print(f"Warning: client {cid} (PID {pid}) is alive but its recorded identity "
              f"cannot be verified; refusing to signal or remove it.", file=sys.stderr)
        return

    if state == "verified":
        stopped = _stop_verified_client(pid, data, label=cid)
        if not stopped and _is_pid_alive(pid, data.get("start_time"), data.get("boot_id")):
            print(f"Warning: client {cid} (PID {pid}) is still running and could not be "
                  f"re-verified; refusing to remove its record.", file=sys.stderr)
            return
        try:
            state_file.unlink(missing_ok=True)
        except OSError as e:
            print(f"Error removing state file: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Client {cid} stopped and removed.")
    else:
        # Dead, or a stale record whose PID now belongs to another process.
        try:
            state_file.unlink(missing_ok=True)
        except OSError as e:
            print(f"Error removing state file: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Client {cid} (stopped) removed.")


def _cli_clients_clear(force: bool = False) -> None:
    """Remove all client state files.

    Without --force: only removes idle (stopped / dead / corrupt) clients.
    Connected clients are skipped with a warning.

    With --force: stops all connected clients (SIGTERM -> SIGKILL) and
    removes every state file.
    """
    clients_dir = _get_clients_dir()
    if not clients_dir.exists():
        print("No LinkPulse clients found.")
        return

    client_files = [f for f in clients_dir.glob("*.json") if _safe_state_file(f, clients_dir)]
    if not client_files:
        print("No LinkPulse clients found.")
        return

    removed = 0
    skipped = 0

    for f in client_files:
        data = _read_client_state(f)
        cid = data.get("client_id", f.stem)
        pid = data.get("pid")
        state = _record_identity_state(pid, data)

        if state == "unknown":
            print(f"  Skipped  {cid}  (PID {pid}: recorded identity cannot be verified)")
            skipped += 1
            continue

        if state == "verified":
            if not force:
                raw_status = data.get("status", "unknown")
                print(f"  Skipped  {cid}  (status: {raw_status}, PID {pid}) -- use -f to force")
                skipped += 1
                continue
            # --force: stop the running client (re-verifies before any kill)
            if (not _stop_verified_client(pid, data, label=cid)
                    and _is_pid_alive(pid, data.get("start_time"), data.get("boot_id"))):
                print(f"  Skipped  {cid}  (could not re-verify PID {pid}; not removing)")
                skipped += 1
                continue

        try:
            f.unlink(missing_ok=True)
        except OSError as e:
            print(f"  Error removing {cid}: {e}", file=sys.stderr)
            continue
        label = "Stopped and removed" if state == "verified" else "Removed"
        print(f"  {label}  {cid}")
        removed += 1

    parts = [f"{removed} client(s) removed"]
    if skipped:
        parts.append(f"{skipped} connected client(s) skipped")
    print(" | ".join(parts) + ".")


def _child_command_prefix() -> list:
    if getattr(sys, "frozen", False):
        # PyInstaller --onefile: sys.executable points inside the ephemeral
        # temp extraction dir which is deleted when the parent exits. Use the
        # stable on-disk binary path (honouring PATH via shutil.which).
        import shutil
        binary = shutil.which(sys.argv[0]) or os.path.abspath(sys.argv[0])
        return [binary]
    return [sys.executable, str(Path(__file__).resolve())]


def _build_child_args(args: argparse.Namespace, mode: str, target_str: str,
                      managed_id: str, state_file: Path, log_file: Path) -> list:
    """Build the detached child's argv from *parsed, normalized* args.

    Forwarding the parent's raw sys.argv would echo whatever the test/runner
    happened to pass and could drop resolved values (env, saved config), so we
    serialize the resolved namespace instead."""
    if mode == "multi":
        child = ["start", target_str]
    else:
        child = [mode, target_str]
        if mode == "http" and getattr(args, "subdomain", None):
            child += ["-u", args.subdomain]
        if mode in ("tcp", "udp") and getattr(args, "remote_port", None):
            child += ["--remote-port", str(args.remote_port)]
    child += [
        "--daemon-child",
        "--client-id", args.client_id,
        "--managed-id", managed_id,
        "--state-file", str(state_file),
        "--log-file", str(log_file),
        "--server", args.server,
        "--grace-time", str(args.grace_time),
        "--retry-interval", str(args.retry_interval),
        "--log-level", args.log_level,
    ]
    if getattr(args, "no_dashboard", False):
        child.append("--no-dashboard")
    else:
        child += ["--dashboard", args.dashboard]
    if getattr(args, "lease", False):
        child.append("--lease")
    if getattr(args, "tls", False):
        child.append("--tls")
    if getattr(args, "ca_cert", None):
        child += ["--ca-cert", args.ca_cert]
    child += ["--token", args.token]
    return child


def _await_child_startup(proc: subprocess.Popen, state_file: Path,
                         timeout: float = 3.0) -> tuple[bool, object]:
    """Bounded startup handshake.

    Returns as soon as the child has written its own state (pid + a non-
    "starting" status) or, at the latest, after `timeout` seconds if it is
    still alive. If the child exits first (crash/validation error) it reports
    failure instead of a bogus success. It never waits for the server, so an
    offline server is fine. Returns (ok, detail)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc = proc.poll()
        if rc is not None:
            return False, f"process exited with code {rc}"
        data = _read_state_raw(state_file)
        pid = data.get("pid")
        if isinstance(pid, int) and pid > 0 and data.get("status") not in (None, "starting"):
            return True, data
        time.sleep(0.05)
    rc = proc.poll()
    if rc is not None:
        return False, f"process exited with code {rc}"
    return True, _read_state_raw(state_file)


def _spawn_detached(args: argparse.Namespace, mode: str, target_str: str,
                    log_file_path: Optional[str] = None) -> None:
    """Spawn a background client process and return immediately."""
    if getattr(args, "daemon_child", False):
        print("Error: cannot detach from a daemon child process.", file=sys.stderr)
        sys.exit(1)
    if not getattr(args, "token", None):
        print("Error: refusing to start a background client without an "
              "authentication token.", file=sys.stderr)
        sys.exit(1)

    clients_dir = _get_clients_dir()
    logs_dir = _get_logs_dir()
    _ensure_private_dir(clients_dir)
    _ensure_private_dir(logs_dir)

    # A detached instance is its own identity by default; an explicit
    # --client-id keeps the machine/client meaning and is shared.
    managed_id = uuid.uuid4().hex
    managed_state_file = clients_dir / f"{managed_id}.json"

    if getattr(args, "_state_file_explicit", False) and getattr(args, "state_file", None):
        state_file = Path(args.state_file)
        try:
            if state_file.resolve() == managed_state_file.resolve():
                print("Error: --state-file must not alias the managed instance "
                      "record.", file=sys.stderr)
                sys.exit(1)
        except OSError:
            pass
        if getattr(args, "client_id", None):
            client_id = args.client_id
        else:
            # Reuse the shared machine identity from an explicit state file
            # instead of overwriting it with a fresh per-spawn id.
            existing = _read_state_raw(state_file).get("client_id")
            try:
                client_id = (_validate_client_id(existing) if existing
                             else uuid.uuid4().hex)
            except ConfigError:
                client_id = uuid.uuid4().hex
    else:
        client_id = getattr(args, "client_id", None) or managed_id
        # Machine identity lives here; a non-.json suffix keeps it out of the
        # managed clients listing.
        state_file = clients_dir / f"{managed_id}.identity"
    args.client_id = client_id
    log_file = Path(log_file_path) if log_file_path else (logs_dir / f"{managed_id}.log")

    cmd = _child_command_prefix() + _build_child_args(
        args, mode, target_str, managed_id, state_file, log_file)

    initial_data = {
        "managed_id": managed_id,
        "client_id": client_id,
        "pid": 0,
        "status": "starting",
        "mode": mode,
        "target": target_str,
        "server": args.server,
        "dashboard": None if getattr(args, "no_dashboard", False) else args.dashboard,
        "started_at": time.time(),
        "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "log_file": str(log_file),
        "state_file": str(state_file),
        "public_urls": [],
        "tunnels": [],
        "cmdline": [mode, target_str],
    }
    _atomic_write_json(managed_state_file, initial_data)

    env = os.environ.copy()
    if getattr(sys, "frozen", False):
        # Strip PyInstaller-internal variables so the child extracts into its
        # own temp dir instead of referencing the parent's, which is deleted
        # when the parent exits.
        for key in list(env):
            if key.startswith("_PYI_") or key == "_MEIPASS2":
                del env[key]
        orig_ldpath = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig_ldpath is not None:
            env["LD_LIBRARY_PATH"] = orig_ldpath
        else:
            env.pop("LD_LIBRARY_PATH", None)

    log_fd = os.fdopen(
        os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600),
        "a", encoding="utf-8")
    try:
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=subprocess.STDOUT,
                creationflags=creationflags, close_fds=True, env=env,
            )
        else:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=subprocess.STDOUT,
                start_new_session=True, close_fds=True, env=env,
            )
    except OSError as e:
        log_fd.close()
        print(f"Error: could not launch background client: {e}", file=sys.stderr)
        sys.exit(1)
    log_fd.close()

    ok, detail = _await_child_startup(proc, managed_state_file, timeout=3.0)
    if not ok:
        print(f"Error: LinkPulse client failed to start: {detail}", file=sys.stderr)
        print(f"  See log: {log_file}", file=sys.stderr)
        sys.exit(1)

    # Stamp pid/start_time only if the child has not written its own record
    # yet -- otherwise we would clobber the richer state it just persisted.
    current = _read_state_raw(managed_state_file)
    if not current.get("pid"):
        current = dict(initial_data)
        current["pid"] = proc.pid
        current["start_time"] = _proc_start_time(proc.pid)
        current["boot_id"] = _read_boot_id()
        current["status"] = "running"
        _atomic_write_json(managed_state_file, current)

    print("LinkPulse client started in background.")
    print(f"  Client ID:   {client_id}")
    print(f"  Managed ID:  {managed_id}")
    print(f"  PID:         {proc.pid}")
    print(f"  Mode:        {mode}")
    print(f"  Target:      {target_str}")
    print(f"  Server:      {args.server}")
    print(f"  Log file:    {log_file}")
    print(f"  State file:  {managed_state_file}")
    sys.exit(0)


def _validate_port(port, what: str = "port") -> int:
    if isinstance(port, bool):
        raise ConfigError(f"{what} must be an integer, got a boolean")
    if isinstance(port, float):
        if not port.is_integer():
            raise ConfigError(f"{what} must be a whole number, got {port!r}")
        value = int(port)
    elif isinstance(port, int):
        value = port
    elif isinstance(port, str):
        text = port.strip()
        if not re.fullmatch(r"[0-9]+", text):
            raise ConfigError(f"{what} must be an integer, got {port!r}")
        value = int(text)
    else:
        raise ConfigError(f"{what} must be an integer, got {port!r}")
    if not (1 <= value <= 65535):
        raise ConfigError(f"{what} must be between 1 and 65535, got {value}")
    return value


def _parse_host_port(s: str, default_host: str = "127.0.0.1",
                     default_port: int = 9000) -> tuple[str, int]:
    """Parse host:port, supporting bracketed IPv6 literals ([::1]:9000).

    A bracketed address with any trailing garbage (e.g. '[::1]junk') is
    rejected rather than silently treated as the default port."""
    s = str(s).strip()
    if not s:
        raise ConfigError("empty host:port address")
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ConfigError(f"invalid IPv6 address {s!r} (missing ']')")
        host = s[1:end]
        if not host:
            raise ConfigError(f"invalid IPv6 address {s!r} (empty host)")
        rest = s[end + 1:]
        if rest == "":
            return host, default_port
        if rest.startswith(":") and len(rest) > 1:
            return host, _validate_port(rest[1:], "port")
        raise ConfigError(f"invalid address {s!r}: unexpected suffix after ']'")
    if "]" in s:
        raise ConfigError(f"invalid address {s!r}: unmatched ']'")
    if s.count(":") > 1:
        # Bare IPv6 literal with no port attached.
        return s, default_port
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return (host or default_host), _validate_port(port, "port")
    return s, default_port


def _normalize_server_address(s: str, default_port: int = 9000) -> str:
    """Normalize a server address: strip scheme/path and append the default
    control port when none is given, preserving bracketed IPv6.

    Note: an ``https://`` prefix is only stripped for storage -- it does NOT by
    itself enable TLS. Pass --tls / set MY_PROXY_TLS=true to encrypt the
    control channel."""
    s = str(s).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].strip().rstrip("/")
    if not s:
        raise ConfigError("empty server address")
    host, port = _parse_host_port(s, default_port=default_port)
    if not host:
        raise ConfigError("server address has no host")
    if ":" in host:  # IPv6 literal -> re-bracket so host:port stays parseable
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _parse_target(s: str) -> tuple[str, int]:
    """Parse an http/tcp/udp target: 'PORT' (-> localhost:PORT) or
    'HOST:PORT' (bracketed IPv6 supported)."""
    s = str(s).strip()
    if not s:
        raise ConfigError("empty target; expected PORT or HOST:PORT")
    if s.startswith("["):
        host, port = _parse_host_port(s, default_host="localhost", default_port=0)
        if port == 0:
            raise ConfigError(f"invalid target {s!r}; missing port")
        return host, port
    if ":" in s:
        if s.count(":") > 1:
            raise ConfigError(
                f"invalid target {s!r}: IPv6 addresses must be bracketed, e.g. [::1]:8080")
        host, port = s.rsplit(":", 1)
        return (host or "localhost"), _validate_port(port, "target port")
    return "localhost", _validate_port(s, "target port")


def _subdomain_from_url(url) -> Optional[str]:
    """Fallback: extract the first hostname label from a public URL, safely."""
    if not isinstance(url, str) or not url:
        return None
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.split(".", 1)[0] or None


class _TrackedValueAction(argparse.Action):
    """Store a value and record that it was given explicitly.

    Enables robust precedence (explicit CLI > env > config > saved > default)
    without relying on "does the value still equal the default?" heuristics,
    which break for explicitly passed default-valued options."""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, f"_exp_{self.dest}", True)


def _build_arg_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.register("action", "tracked", _TrackedValueAction)
    common.add_argument("-d", "--detach", action="store_true",
                        help="run client in background (detached mode)")
    common.add_argument("--server", action="tracked", default=DEFAULT_SERVER,
                         help=f"proxy control server as host:port (default: {DEFAULT_SERVER}, env MY_PROXY_SERVER)")
    common.add_argument("--token", action="tracked", default=None,
                         help="shared secret for authentication (env MY_PROXY_TOKEN)")
    common.add_argument("--grace-time", action="tracked", type=float, default=DEFAULT_GRACE_TIME,
                         help=f"after this many seconds without a server connection, retries are logged "
                              f"as errors instead of warnings (default: {DEFAULT_GRACE_TIME}); the client "
                              f"always keeps retrying and never gives up")
    common.add_argument("--retry-interval", action="tracked", type=float,
                         default=DEFAULT_RETRY_INTERVAL,
                         help=f"seconds between reconnect attempts (default: {DEFAULT_RETRY_INTERVAL}, "
                              f"env MY_PROXY_RETRY_INTERVAL); retries continue indefinitely")
    common.add_argument("--lease", action="store_true",
                         help="lease the requested name instead of taking it over: refuse to start that "
                              "tunnel if another client already holds the subdomain/port (default is "
                              "handoff mode, where the newest client wins)")
    common.add_argument("--dashboard", action="tracked", default=DEFAULT_DASHBOARD,
                         help=f"local dashboard address (default: {DEFAULT_DASHBOARD})")
    common.add_argument("--no-dashboard", action="store_true", help="disable the local dashboard")
    common.add_argument("--state-file", action="tracked", default=None,
                         help=f"machine identity file, shared by processes on this host "
                              f"(default: {DEFAULT_STATE_FILE}, env MY_PROXY_STATE_FILE)")
    common.add_argument("--tls", action="store_true",
                         help="encrypt the control channel with TLS (env MY_PROXY_TLS=true); "
                              "certificate verification is always on")
    common.add_argument("--ca-cert", action="tracked", default=None,
                         help="PEM bundle to verify the server certificate against "
                              "(env MY_PROXY_CA_CERT); implies --tls")
    common.add_argument("--client-id", action="tracked", default=None, help=argparse.SUPPRESS)
    common.add_argument("--managed-id", action="tracked", default=None, help=argparse.SUPPRESS)
    common.add_argument("--log-file", action="tracked", default=None, help=argparse.SUPPRESS)
    common.add_argument("--daemon-child", action="store_true", help=argparse.SUPPRESS)
    common.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                         help="logging verbosity (default: INFO)")

    parser = argparse.ArgumentParser(
        prog="linkpulse",
        description="LinkPulse - Self-hosted tunneling client.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  linkpulse http 8080                               Expose localhost:8080 via HTTP tunnel
  linkpulse http 8080 -d                            Expose localhost:8080 in background
  linkpulse http 8080 -u api                        Request the public name "api"
  linkpulse http 8080 -u api --lease                Lease "api": never hand it off to other clients
  linkpulse tcp 22 --remote-port 20022              Expose localhost:22 via TCP tunnel
  linkpulse tcp 22 -d                               Expose localhost:22 in background
  linkpulse http 8080 --tls --server host:9000      Encrypted control channel (verified TLS)
  linkpulse start tunnels.json                      Open multiple tunnels from config
  linkpulse clients list                            List running LinkPulse clients
  linkpulse clients info <client-id>                Show details for a client
  linkpulse clients delete <client-id>              Stop and remove a client
  linkpulse clients clear                           Remove all idle clients
  linkpulse clients clear -f                        Stop and remove ALL clients
  linkpulse authtoken <secret>                      Save authentication token
  linkpulse server proxy.example.com:9000           Save server address

Tunnel names are shared: by default a newer client claiming the same
subdomain/port hands the name off to itself (handoff mode). Use --lease to
reserve a name for this client instead. The client never gives up reconnecting
to the server; it retries every 5 seconds until stopped.
""")
    sub = parser.add_subparsers(dest="command", required=True)

    http_p = sub.add_parser("http", parents=[common], help="expose a local HTTP service")
    http_p.add_argument("target", help="local port (e.g. 8080) or host:port (e.g. localhost:5173)")
    http_p.add_argument("-u", "--subdomain", help="requested subdomain for the public URL")

    tcp_p = sub.add_parser("tcp", parents=[common], help="expose a local TCP service")
    tcp_p.add_argument("target", help="local port (e.g. 22) or host:port")
    tcp_p.add_argument("--remote-port", type=int, help="requested public port (if available)")

    udp_p = sub.add_parser("udp", parents=[common], help="expose a local UDP service")
    udp_p.add_argument("target", help="local port (e.g. 53) or host:port")
    udp_p.add_argument("--remote-port", type=int, help="request a specific public port")

    start_p = sub.add_parser("start", parents=[common], help="open multiple tunnels from a JSON config file")
    start_p.add_argument("config", help="path to JSON config file (see config.example.json)")

    auth_p = sub.add_parser("authtoken", parents=[common], help="save shared secret to config file")
    auth_p.add_argument("token", help="the shared secret to save")

    server_p = sub.add_parser("server", parents=[common], help="save proxy server address to config file")
    server_p.add_argument("address", help="proxy server address (host:port)")

    clients_p = sub.add_parser("clients", aliases=["client"], help="manage LinkPulse client instances")
    clients_sub = clients_p.add_subparsers(dest="clients_command", required=True)

    clients_sub.add_parser("list", aliases=["ls"], help="list running and managed clients")

    info_p = clients_sub.add_parser("info", aliases=["show", "status"], help="show details for a client")
    info_p.add_argument("client_id", help="the client ID (or prefix)")

    del_p = clients_sub.add_parser("delete", aliases=["stop", "rm", "kill"], help="stop a client and remove its state")
    del_p.add_argument("client_id", help="the client ID (or prefix)")

    clear_p = clients_sub.add_parser("clear", aliases=["prune"], help="remove all idle clients; -f to also stop connected ones")
    clear_p.add_argument("-f", "--force", action="store_true",
                          help="also stop and remove connected clients")

    return parser


def _normalize_mode(value, where: str = "config") -> str:
    mode = str(value or TUNNEL_MODE_HANDOFF).strip().lower()
    if mode not in TUNNEL_MODES:
        raise ConfigError(f"invalid mode {value!r} in {where}; expected 'handoff' or 'lease'")
    return mode


def _load_json_config(path: str) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e}")
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigError(f"config {path} is not valid JSON: {e}")
    if not isinstance(cfg, dict):
        raise ConfigError(f"config {path} must be a JSON object")
    return cfg


def _build_specs_from_config(cfg: dict, cli_lease: bool, where: str) -> list[TunnelSpec]:
    tunnels = cfg.get("tunnels")
    if tunnels is None:
        raise ConfigError(f"{where}: missing 'tunnels' list")
    if not isinstance(tunnels, list):
        raise ConfigError(f"{where}: 'tunnels' must be a list")
    default_mode = (TUNNEL_MODE_LEASE if cli_lease
                    else _normalize_mode(cfg.get("mode", TUNNEL_MODE_HANDOFF), where))
    specs = []
    for i, t in enumerate(tunnels):
        if not isinstance(t, dict):
            raise ConfigError(f"{where}: tunnel #{i + 1} must be an object")
        ttype = t.get("type")
        if ttype not in ("http", "tcp", "udp"):
            raise ConfigError(f"{where}: tunnel #{i + 1} has unknown type {ttype!r}")
        if "local" not in t:
            raise ConfigError(f"{where}: tunnel #{i + 1} is missing 'local'")
        try:
            host, port = _parse_target(str(t["local"]))
        except ConfigError as e:
            raise ConfigError(f"{where}: tunnel #{i + 1}: {e}")
        mode = default_mode if cli_lease else _normalize_mode(t.get("mode", default_mode), where)
        remote_port = t.get("remote_port")
        if remote_port is not None:
            remote_port = _validate_port(remote_port, f"{where}: tunnel #{i + 1} remote_port")
        if ttype == "http":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                    local_host=host, local_port=port,
                                    subdomain=t.get("subdomain"), mode=mode))
        else:
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type=ttype,
                                    local_host=host, local_port=port,
                                    remote_port=remote_port, mode=mode))
    return specs


def _load_start_config(path: str, cli_args: argparse.Namespace) -> tuple[list[TunnelSpec], argparse.Namespace]:
    """Backwards-compatible wrapper around the config loader."""
    cfg = _load_json_config(path)
    specs = _build_specs_from_config(cfg, bool(getattr(cli_args, "lease", False)), path)
    return specs, cli_args


def _explicit(args: argparse.Namespace, dest: str) -> bool:
    """True if the option was passed explicitly on the command line."""
    return bool(getattr(args, f"_exp_{dest}", False))


def _env_bool(name: str) -> Optional[bool]:
    if name not in os.environ:
        return None
    raw = os.environ[name].strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"environment variable {name} must be a boolean (true/false), got {os.environ[name]!r}")


def _env_float(name: str) -> Optional[float]:
    if name not in os.environ:
        return None
    try:
        value = float(os.environ[name])
    except ValueError:
        raise ConfigError(f"environment variable {name} must be a number, got {os.environ[name]!r}")
    if not math.isfinite(value):
        raise ConfigError(f"environment variable {name} must be finite")
    return value


def _resolve_runtime_config(args: argparse.Namespace, cfg: dict) -> None:
    """Apply precedence explicit CLI > environment > per-config file > saved
    authtoken.json > hard defaults, then validate. Mutates `args` in place."""
    # Validate the config document's own field types up front, regardless of
    # whether a higher-precedence source will win.
    cfg_token = cfg.get("token")
    if cfg_token is not None and not isinstance(cfg_token, str):
        raise ConfigError("config 'token' must be a string")
    cfg_server = cfg.get("server")
    if cfg_server is not None and not isinstance(cfg_server, str):
        raise ConfigError("config 'server' must be a string")
    # -- server ---------------------------------------------------------------
    if _explicit(args, "server"):
        server = args.server
    elif os.environ.get("MY_PROXY_SERVER"):
        server = os.environ["MY_PROXY_SERVER"]
    elif cfg.get("server"):
        server = cfg["server"]
    else:
        server = _load_saved_server() or DEFAULT_SERVER
    args.server = _normalize_server_address(server)

    # -- token ----------------------------------------------------------------
    if _explicit(args, "token") and args.token is not None:
        token = args.token
    elif os.environ.get("MY_PROXY_TOKEN"):
        token = os.environ["MY_PROXY_TOKEN"]
    elif cfg.get("token") is not None:
        token = cfg["token"]
    else:
        token = _load_saved_token()
    if token is not None and not isinstance(token, str):
        raise ConfigError("token must be a string")
    if token == "":
        raise ConfigError("token must not be empty")
    args.token = token

    # -- grace time -----------------------------------------------------------
    if _explicit(args, "grace_time"):
        grace = args.grace_time
    else:
        grace = _env_float("MY_PROXY_GRACE_TIME")
        if grace is None:
            grace = cfg.get("grace_time", DEFAULT_GRACE_TIME)
    try:
        grace = float(grace)
    except (TypeError, ValueError):
        raise ConfigError(f"--grace-time must be a number, got {grace!r}")
    if not math.isfinite(grace) or grace < 0:
        raise ConfigError(f"--grace-time must be a finite, non-negative number, got {grace}")
    args.grace_time = grace

    # -- retry interval -------------------------------------------------------
    if _explicit(args, "retry_interval"):
        retry = args.retry_interval
    else:
        retry = _env_float("MY_PROXY_RETRY_INTERVAL")
        if retry is None:
            retry = cfg.get("retry_interval", DEFAULT_RETRY_INTERVAL)
    try:
        retry = float(retry)
    except (TypeError, ValueError):
        raise ConfigError(f"--retry-interval must be a number, got {retry!r}")
    if not math.isfinite(retry) or retry <= 0:
        raise ConfigError(f"--retry-interval must be a finite number > 0, got {retry}")
    args.retry_interval = retry

    # -- dashboard ------------------------------------------------------------
    if getattr(args, "no_dashboard", False):
        args.dashboard = None
    else:
        if _explicit(args, "dashboard"):
            dash = args.dashboard
        elif os.environ.get("MY_PROXY_DASHBOARD"):
            dash = os.environ["MY_PROXY_DASHBOARD"]
        elif cfg.get("dashboard"):
            dash = cfg["dashboard"]
        else:
            dash = DEFAULT_DASHBOARD
        _parse_host_port(dash, default_host="127.0.0.1", default_port=4040)
        args.dashboard = dash

    # -- machine identity state file -----------------------------------------
    if _explicit(args, "state_file") and args.state_file:
        state_file = args.state_file
        state_explicit = True
    elif os.environ.get("MY_PROXY_STATE_FILE"):
        state_file = os.environ["MY_PROXY_STATE_FILE"]
        state_explicit = True
    elif cfg.get("state_file"):
        state_file = cfg["state_file"]
        state_explicit = True
    else:
        state_file = DEFAULT_STATE_FILE
        state_explicit = False
    args.state_file = str(state_file)
    # Detached spawning needs to know whether the machine identity file was
    # deliberately configured, so it does not reuse the shared default for a
    # throwaway background instance.
    args._state_file_explicit = state_explicit

    # -- TLS ------------------------------------------------------------------
    cfg_tls = cfg.get("tls")
    if cfg_tls is not None and not isinstance(cfg_tls, bool):
        raise ConfigError("config 'tls' must be true or false")
    ca_cert = None
    if _explicit(args, "ca_cert") and args.ca_cert is not None:
        ca_cert = args.ca_cert
    elif os.environ.get("MY_PROXY_CA_CERT"):
        ca_cert = os.environ["MY_PROXY_CA_CERT"]
    elif cfg.get("ca_cert") is not None:
        ca_cert = cfg["ca_cert"]
    if ca_cert is not None and not isinstance(ca_cert, str):
        raise ConfigError("ca_cert must be a path string")
    env_tls = _env_bool("MY_PROXY_TLS")
    if getattr(args, "tls", False):
        tls = True
    elif env_tls is not None:
        tls = env_tls
    elif cfg_tls is True:
        tls = True
    else:
        tls = False
    if ca_cert:
        if not Path(ca_cert).is_file():
            raise ConfigError(f"--ca-cert file not found: {ca_cert}")
        tls = True
    args.tls = tls
    args.ca_cert = ca_cert

    # -- identifiers ----------------------------------------------------------
    if getattr(args, "client_id", None):
        args.client_id = _validate_client_id(args.client_id)
    if getattr(args, "managed_id", None):
        mid = str(args.managed_id).strip()
        if not re.fullmatch(r"[0-9a-fA-F]{1,64}", mid):
            raise ConfigError("invalid managed id")
        args.managed_id = mid.lower()


def _load_saved_token() -> Optional[str]:
    """Load the saved auth token from the config file."""
    token = _read_state_raw(DEFAULT_TOKEN_FILE).get("token")
    return token if isinstance(token, str) else None


def _load_saved_server() -> Optional[str]:
    """Load the saved server address from the config file."""
    server = _read_state_raw(DEFAULT_TOKEN_FILE).get("server")
    return server if isinstance(server, str) else None


def _save_config(token: Optional[str] = None, server: Optional[str] = None) -> None:
    """Save the auth token and/or server address to the config file.

    Written atomically with mode 0600 (secrets file), and an existing
    corrupt/non-object file is reported instead of silently overwritten."""
    try:
        data = {}
        if DEFAULT_TOKEN_FILE.exists():
            try:
                parsed = json.loads(DEFAULT_TOKEN_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                raise ConfigError(
                    f"existing config {DEFAULT_TOKEN_FILE} is unreadable/corrupt ({e}); "
                    f"refusing to overwrite it")
            if not isinstance(parsed, dict):
                raise ConfigError(
                    f"existing config {DEFAULT_TOKEN_FILE} is not a JSON object; "
                    f"refusing to overwrite it")
            data = parsed
        if token is not None:
            data["token"] = token
        if server is not None:
            data["server"] = server
        _atomic_write_json(DEFAULT_TOKEN_FILE, data, mode=0o600)
        if token is not None:
            print(f"Saved auth token to {DEFAULT_TOKEN_FILE}")
        if server is not None:
            print(f"Saved server address to {DEFAULT_TOKEN_FILE}")
    except (ConfigError, OSError) as e:
        print(f"Error saving config: {e}", file=sys.stderr)
        sys.exit(1)


def _setup_logging(level: str, recent_logs: deque) -> logging.Logger:
    log = logging.getLogger("my_proxy")
    log.setLevel(getattr(logging, level))
    if not log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", "%H:%M:%S"))
        log.addHandler(handler)
    log.propagate = False
    return log


async def _run_client(client: TunnelClient, args: argparse.Namespace,
                      dash_host: Optional[str], dash_port: Optional[int],
                      log: logging.Logger):
    loop = asyncio.get_running_loop()
    tasks = [asyncio.create_task(client.run())]
    if args.dashboard and dash_host is not None and dash_port is not None:
        tasks.append(asyncio.create_task(serve_dashboard(client, dash_host, dash_port, log)))

    shutdown_once = {"done": False}

    def _signal_handler(signum, frame):
        if shutdown_once["done"]:
            return
        shutdown_once["done"] = True
        log.info("Shutting down...")
        try:
            # signal handlers run on the main thread; hop back onto the loop
            # safely instead of using loop.add_signal_handler (which is
            # unavailable on Windows).
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(client.request_shutdown()))
        except RuntimeError:
            pass  # loop already closing

    installed = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
            installed.append(sig)
        except (ValueError, OSError, AttributeError):
            # ValueError: not the main thread; AttributeError: no such signal.
            pass

    try:
        await tasks[0]
    finally:
        for sig in installed:
            with contextlib.suppress(Exception):
                signal.signal(sig, signal.SIG_DFL)
        for t in tasks[1:]:
            t.cancel()
        if len(tasks) > 1:
            await asyncio.gather(*tasks[1:], return_exceptions=True)


async def _async_main(args: argparse.Namespace):
    # Handle clients management commands
    if args.command in ("clients", "client"):
        cmd = args.clients_command
        if cmd in ("list", "ls"):
            _cli_clients_list()
        elif cmd in ("info", "show", "status"):
            _cli_clients_info(args.client_id)
        elif cmd in ("delete", "stop", "rm", "kill"):
            _cli_clients_delete(args.client_id)
        elif cmd in ("clear", "prune"):
            _cli_clients_clear(force=getattr(args, "force", False))
        return

    # Handle authtoken command
    if args.command == "authtoken":
        _save_config(token=args.token)
        return

    # Handle server command
    if args.command == "server":
        _save_config(server=_normalize_server_address(args.address))
        return

    # Determine mode and target string
    if args.command in ("http", "tcp", "udp"):
        mode = args.command
        target_str = args.target
    elif args.command == "start":
        mode = "multi"
        target_str = args.config
    else:
        mode = args.command
        target_str = ""

    recent_logs: deque = deque(maxlen=200)
    log = _setup_logging(args.log_level, recent_logs)

    # Load the per-tunnel JSON config *first*, so schema errors are reported
    # before we complain about a missing token.
    cfg: dict = {}
    if args.command == "start":
        try:
            cfg = _load_json_config(args.config)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        _resolve_runtime_config(args, cfg)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.token:
        print("Error: No shared secret provided. Pass --token, set MY_PROXY_TOKEN, or run 'linkpulse authtoken <token>'.",
              file=sys.stderr)
        sys.exit(1)

    if args.command in ("http", "tcp", "udp"):
        try:
            host, port = _parse_target(args.target)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        tunnel_mode = TUNNEL_MODE_LEASE if args.lease else TUNNEL_MODE_HANDOFF
        if args.command == "http":
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                 local_host=host, local_port=port,
                                 subdomain=args.subdomain, mode=tunnel_mode)]
        else:
            remote_port = None
            if getattr(args, "remote_port", None) is not None:
                try:
                    remote_port = _validate_port(args.remote_port, "--remote-port")
                except ConfigError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type=args.command,
                                 local_host=host, local_port=port,
                                 remote_port=remote_port, mode=tunnel_mode)]
    elif args.command == "start":
        try:
            specs = _build_specs_from_config(cfg, bool(args.lease), args.config)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        raise SystemExit(f"unknown command {args.command!r}")

    if not specs:
        print("Error: No tunnels to open.", file=sys.stderr)
        sys.exit(1)

    try:
        server_host, server_port = _parse_host_port(args.server)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    state_file = Path(args.state_file) if args.state_file else DEFAULT_STATE_FILE
    if args.dashboard:
        try:
            dash_host, dash_port = _parse_host_port(args.dashboard, default_host="127.0.0.1", default_port=4040)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        dash_host, dash_port = None, None

    # Only now -- after all validation -- spawn the background child, so an
    # invalid invocation (missing token, bad config, ...) fails in the
    # foreground instead of reporting a bogus successful background start.
    if getattr(args, "detach", False) and not getattr(args, "daemon_child", False):
        _spawn_detached(args, mode, target_str, log_file_path=getattr(args, "log_file", None))
        return

    client = TunnelClient(
        specs=specs, server_host=server_host, server_port=server_port,
        secret=args.token, grace_time=args.grace_time, state_file=state_file,
        log=log, recent_logs=recent_logs,
        client_id=getattr(args, "client_id", None),
        mode=mode,
        target_str=target_str,
        dashboard_addr=None if not args.dashboard else f"{dash_host}:{dash_port}",
        log_file_path=getattr(args, "log_file", None),
        retry_interval=args.retry_interval,
        managed_id=getattr(args, "managed_id", None),
        tls=args.tls,
        ca_cert=args.ca_cert,
    )
    await _run_client(client, args, dash_host, dash_port, log)


def main():
    parser = _build_arg_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        pass
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
