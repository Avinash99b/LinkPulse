#!/usr/bin/env python3
"""
proxy_server.py -- Self-hosted tunneling proxy server (ngrok-alike).

Accepts persistent, authenticated, multiplexed client connections and
routes public HTTP(S)/TCP traffic to the appropriate client-side backend,
without any external services (SQLite + local files only).

Run:
    python3 proxy_server.py

Configuration via environment variables:
    SHARED_SECRET        - Required, shared secret for client authentication
    CONTROL_HOST         - Control channel host (default: 0.0.0.0)
    CONTROL_PORT         - Control channel port (default: 9000)
    CONTROL_TLS          - Serve the control channel over TLS (default: false)
    CONTROL_CERT_PATH    - Control TLS certificate (default: CERT_PATH)
    CONTROL_KEY_PATH     - Control TLS private key (default: KEY_PATH)
    HTTP_HOST            - Public HTTP host (default: 0.0.0.0)
    HTTP_PORT            - Public HTTP port (default: 80)
    WILDCARD_DOMAIN      - Required, wildcard domain for tunnels
    TCP_PORT_MIN         - TCP port range minimum (default: 20000)
    TCP_PORT_MAX         - TCP port range maximum (default: 20100)
    DASHBOARD_HOST       - Dashboard host (default: 127.0.0.1)
    DASHBOARD_PASSWORD   - Required password for the private dashboard
    JWT_SECRET           - Required high-entropy secret used to sign dashboard JWTs
    DASHBOARD_PORT       - Dashboard port (default: 8080)
    HTTP_ONLY            - If true, use http:// URLs (default: true)
    EXTERNAL_SSL         - Trust an upstream TLS terminator; advertise https
                           URLs even without local certificates (default: false)
    HEARTBEAT_INTERVAL   - Heartbeat interval in seconds (default: 20)
    HEARTBEAT_TIMEOUT    - Heartbeat timeout in seconds (default: 60)
    STALE_GRACE_SECONDS  - Stale client cleanup grace period (default: 300)
    HTTP_RECONNECT_GRACE_SECONDS      - Hold transient HTTP 404s while a
                                        client reconnects (default: 8; 0 disables)
    HTTP_RECONNECT_MAX_WAITERS_PER_NAME - Waiters per host (default: 16)
    HTTP_RECONNECT_MAX_WAITERS        - Total concurrent waiters (default: 128)
    MAX_CLIENTS                       - Max concurrent client sessions (default: 128)
    MAX_TUNNELS_PER_CLIENT            - Max tunnels per session (default: 32)
    MAX_STREAMS_PER_CLIENT            - Max live streams per session (default: 256)
    MAX_PENDING_HTTP_CONNECTIONS      - Max in-flight public HTTP conns (default: 256)
    UDP_MAX_PEERS_PER_TUNNEL          - Max UDP peers per tunnel (default: 128)
    UDP_IDLE_TIMEOUT                  - Reap idle UDP peers after seconds (default: 60)
    STREAM_WRITE_TIMEOUT              - Abort a stalled stream after seconds (default: 30)
    DB_PATH              - SQLite database path (default: /data/tunnel_proxy.db)
    LOG_LEVEL            - Logging level (default: INFO)
    LOG_FILE             - Log file path (default: /var/log/tunnel-proxy/tunnel_proxy.log)

See README.md for the full architecture / protocol write-up and setup
instructions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import re
import secrets
import signal
import socket
import ssl
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from protocol import (
    CONTROL_STREAM_ID,
    Frame,
    FrameType,
    HELLO_PAYLOAD_LEN,
    INITIAL_WINDOW,
    MAX_ALLOWED_LENGTH,
    MAX_FRAME_PAYLOAD,
    MAX_WINDOW_CREDIT,
    ProtocolError,
    SERVER_CAPABILITIES,
    STREAM_CAPABILITY,
    TUNNEL_MODE_HANDOFF,
    TUNNEL_MODE_LEASE,
    TUNNEL_MODES,
    UDP_MAX_DATAGRAM,
    encode_frame,
    read_frame,
    read_frame_header,
    verify_hello_payload,
)
from storage import Storage
import dashboard as dashboard_mod

log = logging.getLogger("proxy")

WINDOW_UPDATE_THRESHOLD = INITIAL_WINDOW // 2

# HTTP request bounds (the public listener accepts untrusted bytes).
MAX_HTTP_HEADER_BYTES = 32 * 1024
MAX_HTTP_REQUEST_LINE = 8 * 1024
MAX_HTTP_BODY_BYTES = 8 * 1024

# How many ports to probe when a client did not request a specific one.
# Probing is a blocking syscall, so we never scan an entire (possibly
# 55k-port) range inside the event loop.
PORT_ALLOC_ATTEMPTS = 64

# Bound on the retained "this host recently vanished" hints.
MAX_RECONNECT_HINTS = 4096

# Sentinel placed on a stream's writer queue to mean "sender is done".
_EOF_SENTINEL = object()

# Control-channel writes are bounded so one stalled client can never hold the
# global claim lock (or the heartbeat loop) forever. Revocation notices use a
# shorter budget: the recipient is a different, possibly-dead session.
CONTROL_WRITE_TIMEOUT = 10.0
CONTROL_NOTIFY_TIMEOUT = 2.0


class OutboundBuffer:
    """A byte-bounded, fragmentation-tolerant queue of frames.

    The control reader must never await the public socket, and it must not
    reject a compliant peer just because its 256 KiB window arrived as many
    small frames. Small payloads are coalesced into chunk-sized bytearrays so
    item count stays proportional to bytes/MAX_FRAME_PAYLOAD, while the total
    buffered bytes are bounded by the receive window.
    """

    __slots__ = ("_chunks", "queued_bytes", "eof", "_event")

    def __init__(self):
        self._chunks: deque[bytearray] = deque()
        self.queued_bytes = 0
        self.eof = False
        self._event = asyncio.Event()

    def put(self, data: bytes) -> bool:
        """Queue data without awaiting. Returns False on overflow."""
        if not data:
            return True
        if self.queued_bytes + len(data) > INITIAL_WINDOW + MAX_FRAME_PAYLOAD:
            return False
        if self._chunks and len(self._chunks[-1]) + len(data) <= MAX_FRAME_PAYLOAD:
            self._chunks[-1].extend(data)
        else:
            self._chunks.append(bytearray(data))
        self.queued_bytes += len(data)
        self._event.set()
        return True

    def signal_eof(self):
        self.eof = True
        self._event.set()

    def abort(self):
        self._chunks.clear()
        self.queued_bytes = 0
        self.eof = True
        self._event.set()

    async def get(self) -> bytes:
        while True:
            if self._chunks:
                chunk = self._chunks.popleft()
                self.queued_bytes -= len(chunk)
                return bytes(chunk)
            if self.eof:
                return _EOF_SENTINEL
            self._event.clear()
            if self._chunks or self.eof:
                continue
            await self._event.wait()


# =============================================================================
# Flow control
# =============================================================================

class FlowWindow:
    """Tracks remaining send credit for one direction of one stream.

    consume() is called before sending data; if the window is exhausted the
    sender must await() until a WINDOW_UPDATE (replenish()) arrives from the
    peer. This gives simple, symmetric backpressure so a slow reader on
    either side of a tunnel can't cause unbounded buffering in the proxy.
    """

    def __init__(self, initial: int = INITIAL_WINDOW):
        self.available = initial
        self._event = asyncio.Event()
        self._event.set()

    def consume(self, n: int):
        self.available -= n
        if self.available <= 0:
            self._event.clear()

    def replenish(self, n: int) -> int:
        """Add `n` bytes of credit, capped at MAX_WINDOW_CREDIT.

        Returns the amount actually added (the caller may need to know if a
        malicious peer tried to over-credit us).
        """
        before = self.available
        self.available = min(self.available + n, MAX_WINDOW_CREDIT)
        if self.available > 0:
            self._event.set()
        return self.available - before

    async def wait(self):
        await self._event.wait()


# =============================================================================
# Per-stream / per-tunnel / per-client state
# =============================================================================

class StreamState:
    """One multiplexed logical connection (one HTTP request-connection or
    one raw TCP connection, or one UDP peer) riding on a client's control
    connection."""

    __slots__ = (
        "stream_id", "tunnel_id", "public_writer", "udp_remote_addr",
        "send_window", "unacked_recv_bytes", "recv_credit",
        "closed", "client_eof", "server_eof", "half_close",
        "writer_eof_drained", "_finalized",
        "bytes_in", "bytes_out", "last_activity",
        "send_queue", "writer_task", "pump_task",
    )

    def __init__(self, stream_id: int, tunnel_id: str,
                 public_writer: Optional[asyncio.StreamWriter],
                 udp_remote_addr: Optional[tuple] = None):
        self.stream_id = stream_id
        self.tunnel_id = tunnel_id
        self.public_writer = public_writer
        self.udp_remote_addr = udp_remote_addr
        self.send_window = FlowWindow()
        self.unacked_recv_bytes = 0      # drained to public, not yet credited
        self.recv_credit = INITIAL_WINDOW  # bytes the client may still send us
        self.closed = False
        self.client_eof = False
        self.server_eof = False
        self.half_close = False
        # True only after the writer task has drained every queued byte and
        # applied the write-half close. Streams are finalized only once both
        # this and server_eof are set, so a queued response is never truncated.
        self.writer_eof_drained = False
        self._finalized = False
        self.bytes_in = 0
        self.bytes_out = 0
        # Monotonic: compared against time.monotonic() by the UDP reaper.
        self.last_activity = time.monotonic()
        self.send_queue: Optional[OutboundBuffer] = None
        self.writer_task: Optional[asyncio.Task] = None
        self.pump_task: Optional[asyncio.Task] = None

    @property
    def is_udp(self) -> bool:
        return self.udp_remote_addr is not None


@dataclass
class TunnelInfo:
    tunnel_id: str
    type: str  # "http" | "tcp" | "udp"
    mode: str = TUNNEL_MODE_HANDOFF  # ownership policy: "handoff" | "lease"
    instance_id: Optional[str] = None  # client-process identity (reconnect vs. competitor)
    subdomain: Optional[str] = None
    remote_port: Optional[int] = None
    tcp_server: Optional[asyncio.base_events.Server] = None
    udp_sock: Optional[socket.socket] = None
    udp_streams: Optional[dict] = None  # remote addr -> stream_id
    serve_task: Optional[asyncio.Task] = None  # UDP receive loop (owned)
    supports_stream_eof: bool = False
    connection_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


class ClientSession:
    def __init__(self, client_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 limits: Optional[dict] = None):
        self.client_id = client_id
        self.reader = reader
        self.writer = writer
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.last_seen_mono = time.monotonic()
        self.tunnels: dict[str, TunnelInfo] = {}
        self.streams: dict[int, StreamState] = {}
        self._next_stream_id = 1
        self._write_lock = asyncio.Lock()
        self.alive = True
        self.bytes_in = 0   # public -> client, aggregate
        self.bytes_out = 0  # client -> public, aggregate
        # Negotiated once a TUNNEL_OPEN_REQUEST explicitly advertises it.
        self.supports_stream_eof = False
        # Every task this session owns (heartbeat, stream pumps, UDP servers)
        # so teardown can cancel and await them all.
        self.tasks: set[asyncio.Task] = set()
        limits = limits or {}
        self.max_streams = int(limits.get("max_streams_per_client", 256))
        self.stream_write_timeout = float(limits.get("stream_write_timeout", 30))
        self.control_write_timeout = CONTROL_WRITE_TIMEOUT
        self._cleaned = False
        self._cleanup_lock = asyncio.Lock()

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def alloc_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id = (self._next_stream_id + 1) & 0xFFFFFFFF
        if self._next_stream_id == 0:
            self._next_stream_id = 1
        return sid

    def can_open_stream(self) -> bool:
        return self.alive and len(self.streams) < self.max_streams

    async def send_frame(self, ftype: int, stream_id: int, payload: bytes = b"",
                         timeout: Optional[float] = None):
        data = encode_frame(ftype, stream_id, payload)
        async with self._write_lock:
            writer = self.writer
            if writer is None:
                raise ConnectionError("control connection is closed")
            writer.write(data)
            try:
                await asyncio.wait_for(writer.drain(),
                                       timeout=timeout or self.control_write_timeout)
            except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                # A peer that will not drain its control socket must not hold
                # the global claim lock or the heartbeat loop hostage.
                try:
                    writer.close()
                except Exception:
                    pass
                raise ConnectionError("control write failed") from e


# =============================================================================
# Server context (holds all shared state)
# =============================================================================

class ServerContext:
    def __init__(self, config: dict):
        self.config = config
        self.storage = Storage(config["storage"]["db_path"])
        self.clients: dict[str, set[ClientSession]] = {}
        self.by_subdomain: dict[str, tuple[ClientSession, str]] = {}
        self.by_port: dict[int, tuple[ClientSession, str]] = {}
        self.by_udp_port: dict[int, tuple[ClientSession, str]] = {}
        # Global registry of live tunnel ids. Two tunnnels may never share an
        # id, which would otherwise orphan the first one and collide in the
        # database. This is in-memory, so no schema migration is needed.
        self.tunnel_id_owner: dict[str, tuple[ClientSession, str]] = {}
        self.seen_nonces: dict[bytes, int] = {}
        self.start_time = time.time()
        self.recent_logs: deque[str] = deque(maxlen=200)
        self._used_ports_lock = asyncio.Lock()
        # Serialises name claims (subdomain / port reservation, lease checks,
        # evictions) so two clients racing for the same name can never both
        # win or both evict each other.
        self.claim_lock = asyncio.Lock()
        # Every background/owned task so shutdown can cancel and await them.
        self.tasks: set[asyncio.Task] = set()
        # Public HTTP connection bound (all accepted conns, not just waiters).
        self.pending_http = 0
        self.active_http = 0
        self.pending_control = 0
        # Writers accepted but not yet handed off to a session stream; closed
        # and awaited on shutdown.
        self.accepted_writers: set[asyncio.StreamWriter] = set()
        # Recently-disconnected HTTP host hints and the waiters parked on
        # them. All timing is monotonic.
        self.reconnect_hints: dict[str, float] = {}
        self.reconnect_events: dict[str, asyncio.Event] = {}
        self.reconnect_waiters_by_name: dict[str, int] = {}
        self.reconnect_waiters_total = 0
        # Effective TLS state for URL advertisement, set by run(); direct
        # ServerContext construction in tests falls back to config flags.
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.advertise_https = bool(config.get("external_ssl")) and not config.get("http_only")
        # True only when a real local HTTPS listener is bound. An upstream
        # terminator (EXTERNAL_SSL) advertises https but must not trigger an
        # HTTP->HTTPS redirect on the backend HTTP port.
        self.https_listener = False

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def spawn_accepted(self, coro, writer: asyncio.StreamWriter) -> asyncio.Task:
        """Track an accepted connection's writer for shutdown cleanup."""
        self.accepted_writers.add(writer)

        async def _runner():
            try:
                await coro
            except asyncio.CancelledError:
                # A cancelled accept handler must not leave its transport open
                # (that would make Server.wait_closed() hang at shutdown).
                try:
                    writer.close()
                except Exception:
                    pass
                raise
            finally:
                self.accepted_writers.discard(writer)

        return self.spawn(_runner())

    def total_sessions(self) -> int:
        return sum(len(s) for s in self.clients.values())

    @property
    def limits(self) -> dict:
        return self.config.get("limits", {})

    def log_event(self, msg: str):
        self.recent_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")


# =============================================================================
# Config
# =============================================================================

DEFAULT_CONFIG = {
    "shared_secret": "CHANGE_ME",
    "control": {"host": "0.0.0.0", "port": 9000, "tls": False,
                "cert_path": None, "key_path": None},
    "http": {"host": "0.0.0.0", "port": 80},
    "https": {"host": "0.0.0.0", "port": 443},
    # No implicit domain: WILDCARD_DOMAIN must be provided explicitly.
    "wildcard_domain": "",
    # Narrow default ranges keep allocation fast and avoid exposing a huge
    # swathe of ports; operators can widen them explicitly when needed.
    "tcp": {"port_range": [20000, 20100], "bind_host": "0.0.0.0"},
    "udp": {"port_range": [20000, 20100], "bind_host": "0.0.0.0"},
    "dashboard": {"host": "127.0.0.1", "port": 8081},
    "dashboard_password": "",
    "jwt_secret": "",
    "http_only": False,
    "external_ssl": False,
    "allow_http_fallback": False,
    "tls": {
        "cert_path": "/etc/letsencrypt/live/linkpulse.avinash9.in/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/linkpulse.avinash9.in/privkey.pem",
    },
    "heartbeat_interval_seconds": 20,
    "heartbeat_timeout_seconds": 60,
    "stale_grace_seconds": 300,
    "http_reconnect_grace_seconds": 8,
    "http_reconnect_max_waiters_per_name": 16,
    "http_reconnect_max_waiters": 128,
    "limits": {
        "max_clients": 128,
        "max_tunnels_per_client": 32,
        "max_streams_per_client": 256,
        "max_pending_http_connections": 256,
        "udp_max_peers_per_tunnel": 128,
        "udp_idle_timeout": 60,
        "stream_write_timeout": 30,
    },
    "storage": {"db_path": "/data/tunnel_proxy.db"},
    "logging": {"level": "INFO", "file": "/var/log/tunnel-proxy/tunnel_proxy.log"},
}

# Secrets that must never be used in production.
_PLACEHOLDER_SECRETS = {
    "", "change_me", "changeme", "change-me", "change me",
    "replace_me", "replaceme", "your_secret", "your-secret",
    "secret", "password", "placeholder",
}

# Hostnames used in redirects/URLs. Reject anything that could inject CR/LF
# or a scheme into a Location header.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _env_int(name: str, current: int) -> int:
    if name in os.environ:
        raw = os.environ[name].strip()
        try:
            return int(raw)
        except ValueError:
            raise RuntimeError(f"{name} must be an integer, got {raw!r}")
    return current


def _env_bool(name: str, current: bool) -> bool:
    if name not in os.environ:
        return current
    raw = os.environ[name].strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise RuntimeError(f"{name} must be a boolean (true/false), got {os.environ[name]!r}")


def _env_str(name: str, current: str) -> str:
    if name in os.environ:
        return os.environ[name]
    return current


def load_config() -> dict:
    """Load configuration from environment variables with defaults."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy

    # Required environment variables
    if "SHARED_SECRET" in os.environ:
        cfg["shared_secret"] = os.environ["SHARED_SECRET"]
    if "WILDCARD_DOMAIN" in os.environ:
        cfg["wildcard_domain"] = os.environ["WILDCARD_DOMAIN"]

    # Optional environment variables with defaults
    cfg["control"]["host"] = _env_str("CONTROL_HOST", cfg["control"]["host"])
    cfg["control"]["port"] = _env_int("CONTROL_PORT", cfg["control"]["port"])
    cfg["control"]["tls"] = _env_bool("CONTROL_TLS", cfg["control"]["tls"])
    cfg["control"]["cert_path"] = _env_str("CONTROL_CERT_PATH", cfg["control"]["cert_path"] or "")
    cfg["control"]["key_path"] = _env_str("CONTROL_KEY_PATH", cfg["control"]["key_path"] or "")
    cfg["http"]["host"] = _env_str("HTTP_HOST", cfg["http"]["host"])
    cfg["http"]["port"] = _env_int("HTTP_PORT", cfg["http"]["port"])
    cfg["https"]["host"] = _env_str("HTTPS_HOST", cfg["https"]["host"])
    cfg["https"]["port"] = _env_int("HTTPS_PORT", cfg["https"]["port"])
    cfg["tcp"]["port_range"][0] = _env_int("TCP_PORT_MIN", cfg["tcp"]["port_range"][0])
    cfg["tcp"]["port_range"][1] = _env_int("TCP_PORT_MAX", cfg["tcp"]["port_range"][1])
    cfg["udp"]["port_range"][0] = _env_int("UDP_PORT_MIN", cfg["udp"]["port_range"][0])
    cfg["udp"]["port_range"][1] = _env_int("UDP_PORT_MAX", cfg["udp"]["port_range"][1])
    cfg["tls"]["cert_path"] = _env_str("CERT_PATH", cfg["tls"]["cert_path"])
    cfg["tls"]["key_path"] = _env_str("KEY_PATH", cfg["tls"]["key_path"])
    cfg["dashboard"]["host"] = _env_str("DASHBOARD_HOST", cfg["dashboard"]["host"])
    cfg["dashboard"]["port"] = _env_int("DASHBOARD_PORT", cfg["dashboard"]["port"])
    cfg["dashboard_password"] = _env_str("DASHBOARD_PASSWORD", cfg["dashboard_password"])
    cfg["jwt_secret"] = _env_str("JWT_SECRET", cfg["jwt_secret"])
    cfg["http_only"] = _env_bool("HTTP_ONLY", cfg["http_only"])
    cfg["external_ssl"] = _env_bool("EXTERNAL_SSL", cfg["external_ssl"])
    cfg["allow_http_fallback"] = _env_bool("ALLOW_HTTP_FALLBACK", cfg["allow_http_fallback"])
    cfg["heartbeat_interval_seconds"] = _env_int("HEARTBEAT_INTERVAL", cfg["heartbeat_interval_seconds"])
    cfg["heartbeat_timeout_seconds"] = _env_int("HEARTBEAT_TIMEOUT", cfg["heartbeat_timeout_seconds"])
    cfg["stale_grace_seconds"] = _env_int("STALE_GRACE_SECONDS", cfg["stale_grace_seconds"])
    cfg["http_reconnect_grace_seconds"] = _env_int(
        "HTTP_RECONNECT_GRACE_SECONDS", cfg["http_reconnect_grace_seconds"])
    cfg["http_reconnect_max_waiters_per_name"] = _env_int(
        "HTTP_RECONNECT_MAX_WAITERS_PER_NAME", cfg["http_reconnect_max_waiters_per_name"])
    cfg["http_reconnect_max_waiters"] = _env_int(
        "HTTP_RECONNECT_MAX_WAITERS", cfg["http_reconnect_max_waiters"])
    lim = cfg["limits"]
    lim["max_clients"] = _env_int("MAX_CLIENTS", lim["max_clients"])
    lim["max_tunnels_per_client"] = _env_int("MAX_TUNNELS_PER_CLIENT", lim["max_tunnels_per_client"])
    lim["max_streams_per_client"] = _env_int("MAX_STREAMS_PER_CLIENT", lim["max_streams_per_client"])
    lim["max_pending_http_connections"] = _env_int(
        "MAX_PENDING_HTTP_CONNECTIONS", lim["max_pending_http_connections"])
    lim["udp_max_peers_per_tunnel"] = _env_int("UDP_MAX_PEERS_PER_TUNNEL", lim["udp_max_peers_per_tunnel"])
    lim["udp_idle_timeout"] = _env_int("UDP_IDLE_TIMEOUT", lim["udp_idle_timeout"])
    lim["stream_write_timeout"] = _env_int("STREAM_WRITE_TIMEOUT", lim["stream_write_timeout"])
    cfg["storage"]["db_path"] = _env_str("DB_PATH", cfg["storage"]["db_path"])
    cfg["logging"]["level"] = _env_str("LOG_LEVEL", cfg["logging"]["level"])
    cfg["logging"]["file"] = _env_str("LOG_FILE", cfg["logging"]["file"])

    # Default TLS paths follow the wildcard domain if not overridden. Cert and
    # key are resolved independently so setting only one does not reset the
    # other back to a default.
    default_tls_dir = (f"/etc/letsencrypt/live/{cfg['wildcard_domain']}"
                       if cfg.get("wildcard_domain") else "")
    if "CERT_PATH" not in os.environ:
        cfg["tls"]["cert_path"] = f"{default_tls_dir}/fullchain.pem" if default_tls_dir else ""
    if "KEY_PATH" not in os.environ:
        cfg["tls"]["key_path"] = f"{default_tls_dir}/privkey.pem" if default_tls_dir else ""

    return cfg


def _check_port(name: str, value) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 65535):
        raise RuntimeError(f"{name} must be a port in 1..65535, got {value!r}")


def _check_range(name: str, value) -> None:
    if (not isinstance(value, (list, tuple)) or len(value) != 2
            or not all(isinstance(v, int) and not isinstance(v, bool) for v in value)):
        raise RuntimeError(f"{name} must be a [min, max] pair, got {value!r}")
    lo, hi = value
    _check_port(f"{name}[0]", lo)
    _check_port(f"{name}[1]", hi)
    if lo > hi:
        raise RuntimeError(f"{name} minimum {lo} is greater than maximum {hi}")


def _check_nonneg_int(name: str, value) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RuntimeError(f"{name} must be a non-negative integer, got {value!r}")


def _check_pos_int(name: str, value) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise RuntimeError(f"{name} must be a positive integer, got {value!r}")


def validate_config(cfg: dict) -> None:
    """Fail fast on missing/invalid configuration.

    Called from run() only, after load_config(), so the in-process tests that
    build a ServerContext directly from DEFAULT_CONFIG are unaffected.
    """
    secret = str(cfg.get("shared_secret") or "")
    if secret.strip().lower() in _PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "SHARED_SECRET is missing or still the placeholder value; set a strong, "
            "unique SHARED_SECRET before starting the server."
        )
    if len(secret) < 8:
        raise RuntimeError("SHARED_SECRET must be at least 8 characters long.")

    wildcard = str(cfg.get("wildcard_domain") or "").strip()
    if not wildcard:
        raise RuntimeError("WILDCARD_DOMAIN is required (e.g. tunnel.example.com).")
    if not _DOMAIN_RE.fullmatch(wildcard):
        raise RuntimeError(
            f"WILDCARD_DOMAIN {wildcard!r} is not a valid DNS domain name "
            "(labels of a-z/0-9/-, separated by dots; no scheme or slashes)."
        )

    for name in ("http_only", "external_ssl", "allow_http_fallback"):
        if not isinstance(cfg.get(name), bool):
            raise RuntimeError(f"{name} must be a boolean true/false value.")

    password = str(cfg.get("dashboard_password") or "")
    if password.strip().lower() in _PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "DASHBOARD_PASSWORD is missing or still a placeholder; set a strong password.")
    if len(password) < 8:
        raise RuntimeError("DASHBOARD_PASSWORD must be at least 8 characters long.")
    jwt_secret = str(cfg.get("jwt_secret") or "")
    if jwt_secret.strip().lower() in _PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "JWT_SECRET is missing or still a placeholder; set a high-entropy secret.")
    if len(jwt_secret) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters long.")

    _check_port("CONTROL_PORT", cfg["control"]["port"])
    _check_port("HTTP_PORT", cfg["http"]["port"])
    _check_port("HTTPS_PORT", cfg["https"]["port"])
    _check_port("DASHBOARD_PORT", cfg["dashboard"]["port"])
    _check_range("TCP_PORT_MIN/MAX", cfg["tcp"]["port_range"])
    _check_range("UDP_PORT_MIN/MAX", cfg["udp"]["port_range"])

    _check_pos_int("HEARTBEAT_INTERVAL", cfg["heartbeat_interval_seconds"])
    _check_pos_int("HEARTBEAT_TIMEOUT", cfg["heartbeat_timeout_seconds"])
    if cfg["heartbeat_timeout_seconds"] <= cfg["heartbeat_interval_seconds"]:
        raise RuntimeError("HEARTBEAT_TIMEOUT must be greater than HEARTBEAT_INTERVAL.")
    _check_nonneg_int("STALE_GRACE_SECONDS", cfg["stale_grace_seconds"])
    _check_nonneg_int("HTTP_RECONNECT_GRACE_SECONDS", cfg["http_reconnect_grace_seconds"])
    _check_nonneg_int("HTTP_RECONNECT_MAX_WAITERS_PER_NAME", cfg["http_reconnect_max_waiters_per_name"])
    _check_nonneg_int("HTTP_RECONNECT_MAX_WAITERS", cfg["http_reconnect_max_waiters"])
    lim = cfg["limits"]
    _check_pos_int("MAX_CLIENTS", lim["max_clients"])
    _check_pos_int("MAX_TUNNELS_PER_CLIENT", lim["max_tunnels_per_client"])
    _check_pos_int("MAX_STREAMS_PER_CLIENT", lim["max_streams_per_client"])
    _check_pos_int("MAX_PENDING_HTTP_CONNECTIONS", lim["max_pending_http_connections"])
    _check_pos_int("UDP_MAX_PEERS_PER_TUNNEL", lim["udp_max_peers_per_tunnel"])
    _check_pos_int("UDP_IDLE_TIMEOUT", lim["udp_idle_timeout"])
    _check_pos_int("STREAM_WRITE_TIMEOUT", lim["stream_write_timeout"])


class DequeLogHandler(logging.Handler):
    """Feeds formatted log records into ctx.recent_logs for the dashboard."""

    def __init__(self, ctx: ServerContext):
        super().__init__()
        self.ctx = ctx

    def emit(self, record: logging.LogRecord):
        try:
            self.ctx.recent_logs.append(self.format(record))
        except Exception:
            pass


# =============================================================================
# Port / subdomain allocation
# =============================================================================

def _port_is_bindable(port: int, socktype: int = socket.SOCK_STREAM) -> bool:
    s = socket.socket(socket.AF_INET, socktype)
    if sys.platform == "win32":
        # On Windows, SO_REUSEADDR permits binding to a port that's already
        # in LISTEN state elsewhere (unlike POSIX, where it only affects
        # sockets stuck in TIME_WAIT) -- so using it here would make this
        # probe report already-occupied ports as free. SO_EXCLUSIVEADDRUSE
        # is the Windows-correct flag for an exclusive availability check.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except (AttributeError, OSError):
            pass
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _allocate_port(ctx: ServerContext, preferred: Optional[int], registry: dict,
                   socktype: int) -> Optional[int]:
    """Pick a bindable public port.

    A port the client explicitly asked for either works or fails -- we never
    silently substitute a random one, and we never scan a whole range inside
    the event loop. When no preference is given we probe a bounded number of
    random candidates.
    """
    lo, hi = (ctx.config["tcp"] if socktype == socket.SOCK_STREAM else ctx.config["udp"])["port_range"]
    if preferred is not None:
        try:
            p = int(preferred)
        except (TypeError, ValueError):
            return None
        if not (lo <= p <= hi) or p in registry:
            return None
        return p if _port_is_bindable(p, socktype) else None

    span = hi - lo + 1
    if span <= 0:
        return None
    for _ in range(min(PORT_ALLOC_ATTEMPTS, span)):
        p = random.randint(lo, hi)
        if p in registry or p in ctx.by_port or p in ctx.by_udp_port:
            continue
        if _port_is_bindable(p, socktype):
            return p
    return None


def allocate_tcp_port(ctx: ServerContext, preferred: Optional[int] = None) -> Optional[int]:
    return _allocate_port(ctx, preferred, ctx.by_port, socket.SOCK_STREAM)


def allocate_udp_port(ctx: ServerContext, preferred: Optional[int] = None) -> Optional[int]:
    return _allocate_port(ctx, preferred, ctx.by_udp_port, socket.SOCK_DGRAM)


def allocate_subdomain(ctx: ServerContext, preferred: Optional[str]) -> Optional[str]:
    def valid(s):
        return bool(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", s))

    if preferred:
        preferred = preferred.lower()
        if not valid(preferred):
            return None
        if preferred not in ctx.by_subdomain:
            return preferred
        return None  # explicitly requested and already taken -> caller reports error
    for _ in range(20):
        candidate = secrets.token_hex(4)
        if candidate not in ctx.by_subdomain:
            return candidate
    return None


# =============================================================================
# Stream data plumbing (public socket <-> multiplexed control connection)
# =============================================================================

async def send_stream_data(session: ClientSession, stream: StreamState, data: bytes):
    """Chunk `data` into <= MAX_FRAME_PAYLOAD frames, respecting flow control.

    Never blocks forever: a peer that stops granting credit for longer than
    the stream write timeout is treated as stalled and the stream is aborted.
    """
    view = memoryview(data)
    total = len(view)
    offset = 0
    timeout = session.stream_write_timeout
    while offset < total:
        try:
            await asyncio.wait_for(stream.send_window.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            raise ConnectionError("flow-control credit timeout")
        available = max(1, min(stream.send_window.available, MAX_FRAME_PAYLOAD, total - offset))
        chunk = bytes(view[offset: offset + available])
        await session.send_frame(FrameType.STREAM_DATA, stream.stream_id, chunk)
        stream.send_window.consume(len(chunk))
        stream.bytes_in += len(chunk)
        session.bytes_in += len(chunk)
        tunnel = session.tunnels.get(stream.tunnel_id)
        if tunnel:
            tunnel.bytes_in += len(chunk)
        offset += len(chunk)


async def _finalize_stream(session: ClientSession, stream: StreamState, *, close_writer: bool = True):
    """Remove a stream from all registries and stop its owned tasks.

    Idempotent. Cancels and *awaits* both the writer and the public pump
    (except the calling task) so a zero-credit pump cannot linger after the
    stream is gone. ``closed`` is set first so a task's own EOF finalizer
    becomes a no-op instead of recursing.
    """
    if stream._finalized:
        return
    stream._finalized = True
    stream.closed = True
    session.streams.pop(stream.stream_id, None)
    if stream.is_udp:
        tunnel = session.tunnels.get(stream.tunnel_id)
        if tunnel is not None and tunnel.udp_streams is not None:
            tunnel.udp_streams.pop(stream.udp_remote_addr, None)
    if stream.send_queue is not None:
        stream.send_queue.abort()
    try:
        current = asyncio.current_task()
    except RuntimeError:
        current = None
    victims = [t for t in (stream.writer_task, stream.pump_task)
               if t is not None and t is not current and not t.done()]
    for t in victims:
        t.cancel()
    if victims:
        await asyncio.gather(*victims, return_exceptions=True)
    if close_writer and stream.public_writer is not None:
        try:
            stream.public_writer.close()
        except Exception:
            pass


async def abort_stream(session: ClientSession, stream: StreamState, *, notify: bool = True):
    """Full abort of a stream: drop queued data, close both directions."""
    was_open = not stream.closed
    await _finalize_stream(session, stream)
    if notify and was_open and session.alive:
        try:
            await session.send_frame(FrameType.STREAM_CLOSE, stream.stream_id)
        except Exception:
            pass


async def _maybe_finalize_stream(session: ClientSession, stream: StreamState):
    """Finalize only once the writer has flushed the queue *and* the public
    side has ended, so a queued response is never truncated by an early EOF.
    """
    if stream.closed or stream._finalized:
        return
    if stream.server_eof and stream.writer_eof_drained:
        await _finalize_stream(session, stream)


async def _stream_writer_loop(session: ClientSession, stream: StreamState):
    """Drain the client -> public queue onto the public socket.

    This is a task of its own precisely so the control-connection reader
    never awaits a slow public destination's drain().
    """
    queue = stream.send_queue
    try:
        while True:
            item = await queue.get()
            if item is _EOF_SENTINEL:
                writer = stream.public_writer
                if writer is not None:
                    try:
                        if stream.half_close and writer.can_write_eof():
                            writer.write_eof()
                        else:
                            writer.close()
                    except Exception:
                        pass
                # Every queued byte was written+drained before the sentinel,
                # so the write half is genuinely flushed now.
                stream.writer_eof_drained = True
                await _maybe_finalize_stream(session, stream)
                return
            try:
                stream.public_writer.write(item)
                await asyncio.wait_for(stream.public_writer.drain(),
                                       timeout=session.stream_write_timeout)
            except asyncio.TimeoutError:
                log.info("Stream %s write stalled; aborting", stream.stream_id)
                await abort_stream(session, stream, notify=True)
                return
            except (ConnectionError, OSError):
                await abort_stream(session, stream, notify=True)
                return
            n = len(item)
            stream.bytes_out += n
            session.bytes_out += n
            tunnel = session.tunnels.get(stream.tunnel_id)
            if tunnel:
                tunnel.bytes_out += n
            stream.unacked_recv_bytes += n
            if stream.unacked_recv_bytes >= WINDOW_UPDATE_THRESHOLD:
                increment = stream.unacked_recv_bytes
                stream.unacked_recv_bytes = 0
                stream.recv_credit = min(stream.recv_credit + increment, MAX_WINDOW_CREDIT)
                try:
                    await session.send_frame(
                        FrameType.STREAM_WINDOW_UPDATE, stream.stream_id, increment.to_bytes(4, "big")
                    )
                except Exception:
                    return
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("stream writer loop failed for stream %s", stream.stream_id)


async def pump_public_to_client(session: ClientSession, stream: StreamState,
                                pub_reader: asyncio.StreamReader, ctx: ServerContext):
    """Read from the public-facing socket and forward as STREAM_DATA frames."""
    try:
        while not stream.closed:
            try:
                await asyncio.wait_for(stream.send_window.wait(), timeout=session.stream_write_timeout)
            except asyncio.TimeoutError:
                break
            chunk = await pub_reader.read(MAX_FRAME_PAYLOAD)
            if not chunk:
                break
            await send_stream_data(session, stream, chunk)
    except asyncio.CancelledError:
        raise
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        await _server_side_eof(session, stream)


async def _server_side_eof(session: ClientSession, stream: StreamState):
    """The public->client direction ended. Signal EOF (or abort) to the client."""
    if stream.closed:
        return
    stream.server_eof = True
    if stream.is_udp:
        await _finalize_stream(session, stream)
        return
    if session.supports_stream_eof:
        if session.alive:
            try:
                await session.send_frame(FrameType.STREAM_EOF, stream.stream_id)
            except Exception:
                pass
    else:
        if session.alive:
            try:
                await session.send_frame(FrameType.STREAM_CLOSE, stream.stream_id)
            except Exception:
                pass
        # Legacy full-close: no further client data is meaningful, so signal
        # the writer to flush what is already queued and close the write half.
        if not stream.client_eof:
            stream.client_eof = True
            stream.half_close = False
            if stream.send_queue is not None:
                stream.send_queue.signal_eof()
    await _maybe_finalize_stream(session, stream)


async def open_new_stream(session: ClientSession, tunnel: TunnelInfo,
                          pub_reader: asyncio.StreamReader, pub_writer: asyncio.StreamWriter,
                          initial_data: bytes, proto: str, remote_addr: tuple, ctx: ServerContext):
    """Register a new multiplexed stream for an inbound public connection,
    tell the client about it, and start pumping data in both directions."""
    if not session.can_open_stream():
        try:
            pub_writer.close()
        except Exception:
            pass
        return
    stream_id = session.alloc_stream_id()
    stream = StreamState(stream_id=stream_id, tunnel_id=tunnel.tunnel_id, public_writer=pub_writer)
    stream.send_queue = OutboundBuffer()
    session.streams[stream_id] = stream
    tunnel.connection_count += 1

    meta = json.dumps({
        "tunnel_id": tunnel.tunnel_id,
        "proto": proto,
        "remote_addr": f"{remote_addr[0]}:{remote_addr[1]}",
    }).encode()
    try:
        await session.send_frame(FrameType.STREAM_OPEN, stream_id, meta)
    except Exception:
        session.streams.pop(stream_id, None)
        pub_writer.close()
        return

    if initial_data:
        try:
            await send_stream_data(session, stream, initial_data)
        except Exception:
            await abort_stream(session, stream, notify=False)
            return

    stream.writer_task = session.spawn(_stream_writer_loop(session, stream))
    stream.pump_task = session.spawn(pump_public_to_client(session, stream, pub_reader, ctx))


# =============================================================================
# HTTP(S) public listener
# =============================================================================

_HOST_RE = re.compile(rb"^Host:\s*([^\r\n]+)\r\n", re.IGNORECASE | re.MULTILINE)


class _HeaderTooLarge(Exception):
    pass


def extract_host(header_bytes: bytes) -> Optional[str]:
    m = _HOST_RE.search(header_bytes)
    if not m:
        return None
    host = m.group(1).decode(errors="replace").strip()
    return host.split(":")[0].lower()


def _status_text(status: int) -> str:
    return {200: "OK", 301: "Moved Permanently", 303: "See Other", 400: "Bad Request",
            401: "Unauthorized", 404: "Not Found", 413: "Payload Too Large",
            415: "Unsupported Media Type", 429: "Too Many Requests",
            431: "Request Header Fields Too Large", 502: "Bad Gateway",
            503: "Service Unavailable"}.get(status, "Error")


async def send_http_error(writer: asyncio.StreamWriter, status: int, reason: str,
                          retry_after: int | None = None):
    body = f"<html><body><h1>{status} {reason}</h1></body></html>".encode()
    extra = f"Retry-After: {retry_after}\r\n" if retry_after else ""
    resp = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\n"
        f"{extra}"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    try:
        writer.write(resp)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def is_root_domain(host: str, wildcard_domain: str) -> bool:
    h = host.lower()
    w = wildcard_domain.lower()
    return h == w or h in ("localhost", "127.0.0.1")


async def send_server_response(writer: asyncio.StreamWriter, ctx: ServerContext, req_path: str,
                              method: str = "GET", headers: dict | None = None, body: bytes = b"",
                              secure: bool = False):
    status, response_body, content_type, extra_headers = dashboard_mod.build_response(
        ctx, req_path, method, headers or {}, body, secure=secure,
        peer=(writer.get_extra_info("peername") or ("?", 0))[0],
    )
    resp = (
        f"HTTP/1.1 {status} {_status_text(status)}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"X-Content-Type-Options: nosniff\r\n"
        f"X-Frame-Options: DENY\r\n"
        f"Referrer-Policy: no-referrer\r\n"
        f"Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n"
        f"Content-Length: {len(response_body)}\r\n"
        f"{extra_headers}"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + response_body
    try:
        writer.write(resp)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _read_http_head(reader: asyncio.StreamReader) -> bytes:
    """Read a bounded request head. Raises _HeaderTooLarge / ConnectionError."""
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError as e:
        raise _HeaderTooLarge from e
    except asyncio.IncompleteReadError as e:
        raise ConnectionError from e
    if len(data) > MAX_HTTP_HEADER_BYTES:
        raise _HeaderTooLarge
    first_line = data.split(b"\r\n", 1)[0]
    if len(first_line) > MAX_HTTP_REQUEST_LINE:
        raise _HeaderTooLarge
    return data


def _parse_request(header_bytes: bytes) -> tuple[str, str, dict]:
    try:
        request_line = header_bytes.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = request_line.split()
        req_path = parts[1] if len(parts) >= 2 else "/"
        method = parts[0].upper() if parts else "GET"
    except Exception:
        req_path, method = "/", "GET"
    request_headers = {}
    for header_line in header_bytes.split(b"\r\n")[1:]:
        if not header_line:
            break
        if b":" in header_line:
            key, value = header_line.decode("latin-1").split(":", 1)
            request_headers[key.strip().lower()] = value.strip()
    return req_path, method, request_headers


async def _handle_root_request(reader, writer, ctx, header_bytes, req_path, method,
                               request_headers, host, is_https):
    secure = bool(is_https or ctx.advertise_https)
    # /health is always answered, even when a TLS redirect would otherwise
    # apply, so orchestrators can probe the HTTP listener unauthenticated.
    path_only = req_path.split("?", 1)[0]
    if path_only != "/health" and not is_https and ctx.https_listener:
        redirect = f"https://{host}{req_path}"
        resp = (
            f"HTTP/1.1 301 Moved Permanently\r\nLocation: {redirect}\r\n"
            f"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode()
        try:
            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
        return
    request_body = b""
    if method == "POST":
        try:
            body_size = int(request_headers.get("content-length", "0"))
        except ValueError:
            body_size = -1
        if body_size < 0 or body_size > MAX_HTTP_BODY_BYTES:
            await send_http_error(writer, 413, "Payload Too Large")
            return
        if body_size:
            try:
                request_body = await asyncio.wait_for(reader.readexactly(body_size), timeout=5)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                await send_http_error(writer, 400, "Bad Request")
                return
    await send_server_response(writer, ctx, req_path, method, request_headers, request_body,
                               secure=secure)


def _prune_reconnect_hints(ctx: ServerContext, now: float):
    """Drop hints once they are well past their wait window.

    An expired hint is retained briefly (for the same grace period) so a name
    known to be mid-outage returns 503 rather than regressing to an
    "unknown host" 404. Bounded and monotonic; never a permanent map.
    """
    grace = int(ctx.config.get("http_reconnect_grace_seconds", 0) or 0)
    retention = max(grace, 1)
    expired = [k for k, expiry in ctx.reconnect_hints.items()
               if expiry + retention <= now]
    for k in expired:
        ctx.reconnect_hints.pop(k, None)


def _record_reconnect_hint(ctx: ServerContext, subdomain: str):
    """Remember that `subdomain` just vanished unexpectedly (not by explicit
    close/handoff), so a short-lived reconnect can be served without a 404."""
    grace = int(ctx.config.get("http_reconnect_grace_seconds", 0) or 0)
    if grace <= 0 or not subdomain:
        return
    now = time.monotonic()
    _prune_reconnect_hints(ctx, now)
    if subdomain not in ctx.reconnect_hints and len(ctx.reconnect_hints) >= MAX_RECONNECT_HINTS:
        # Bounded: drop the oldest hint that isn't the one being refreshed.
        for k in list(ctx.reconnect_hints):
            if k != subdomain:
                ctx.reconnect_hints.pop(k, None)
                break
    ctx.reconnect_hints[subdomain] = now + grace


def _notify_reconnect_waiters(ctx: ServerContext, subdomain: str):
    event = ctx.reconnect_events.get(subdomain)
    if event is not None:
        event.set()


def _caller_gone(reader, writer) -> bool:
    """Best-effort detection that the HTTP caller is no longer there.

    A peer FIN (half-close) is deliberately *not* treated as gone: an HTTP
    client may legitimately close its write half while waiting for the
    response. We only act on a locally closing transport or a reader that has
    recorded an error. A silently dead peer is bounded by the grace deadline
    and the eventual failed write, not by this check.
    """
    if writer is not None:
        try:
            if writer.is_closing():
                return True
            transport = getattr(writer, "transport", None)
            if transport is not None and transport.is_closing():
                return True
        except Exception:
            pass
    if reader is not None:
        try:
            if reader.exception() is not None:
                return True
        except Exception:
            pass
    return False


async def _wait_for_reconnect(ctx: ServerContext, subdomain: str,
                              reader=None, writer=None) -> str:
    """Park an inbound HTTP request while a recently-lost host reconnects.

    Returns "ready" when a tunnel is registered again, "unknown" when there
    is no recent-disconnect hint (-> 404), and "unavailable" when the hinted
    outage has already outlived its wait window, the deadline expires, the
    caller disappears, or the waiter budget is exceeded (-> 503).

    The request head is already in memory and its body is never read here, so
    there is no application-level accumulation or replay. All timing is
    monotonic and bounded.
    """
    grace = int(ctx.config.get("http_reconnect_grace_seconds", 0) or 0)
    if grace <= 0:
        return "unknown"
    loop = asyncio.get_running_loop()
    now = loop.time()
    expiry = ctx.reconnect_hints.get(subdomain)
    if expiry is None:
        return "unknown"
    if expiry <= now:
        # Known outage whose wait window already elapsed -> 503, not 404.
        return "unavailable"
    if ctx.reconnect_waiters_total >= int(ctx.config.get("http_reconnect_max_waiters", 0) or 0):
        return "unavailable"
    if ctx.reconnect_waiters_by_name.get(subdomain, 0) >= int(
            ctx.config.get("http_reconnect_max_waiters_per_name", 0) or 0):
        return "unavailable"

    event = ctx.reconnect_events.get(subdomain)
    if event is None:
        event = asyncio.Event()
        ctx.reconnect_events[subdomain] = event
    ctx.reconnect_waiters_by_name[subdomain] = ctx.reconnect_waiters_by_name.get(subdomain, 0) + 1
    ctx.reconnect_waiters_total += 1
    try:
        deadline = min(now + grace, expiry)
        while True:
            if _caller_gone(reader, writer):
                return "unavailable"
            # Clear-before-check: the only writer sets the registry first and
            # then the event, so we can never miss a registration.
            event.clear()
            entry = ctx.by_subdomain.get(subdomain)
            if entry is not None and entry[0].alive:
                return "ready"
            remaining = deadline - loop.time()
            if remaining <= 0:
                return "unavailable"
            try:
                await asyncio.wait_for(event.wait(), timeout=min(remaining, 0.5))
            except asyncio.TimeoutError:
                pass
    finally:
        # Cancellation (client went away) must release the quota.
        ctx.reconnect_waiters_total -= 1
        left = ctx.reconnect_waiters_by_name.get(subdomain, 1) - 1
        if left > 0:
            ctx.reconnect_waiters_by_name[subdomain] = left
        else:
            ctx.reconnect_waiters_by_name.pop(subdomain, None)
            ctx.reconnect_events.pop(subdomain, None)


async def handle_public_http_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  ctx: ServerContext, is_https: bool = False):
    """Admission-controlled entry point for public HTTP(S) connections."""
    max_active = int(ctx.limits.get("max_pending_http_connections", 256))
    # Bound *all* in-flight public HTTP connections (including slowloris
    # senders that have not finished their headers yet), not just waiters.
    if ctx.active_http >= max_active:
        await send_http_error(writer, 503, "Service Unavailable", retry_after=2)
        return
    ctx.active_http += 1
    try:
        await _serve_public_http(reader, writer, ctx, is_https)
    finally:
        ctx.active_http -= 1


async def _serve_public_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                             ctx: ServerContext, is_https: bool):
    try:
        header_bytes = await asyncio.wait_for(_read_http_head(reader), timeout=10)
    except _HeaderTooLarge:
        await send_http_error(writer, 431, "Request Header Fields Too Large")
        return
    except (asyncio.TimeoutError, ConnectionError, OSError):
        try:
            writer.close()
        except Exception:
            pass
        return

    req_path, method, request_headers = _parse_request(header_bytes)
    host = extract_host(header_bytes)
    if not host:
        await send_http_error(writer, 400, "Bad Request (missing Host header)")
        return

    # Only answer as proxy server/dashboard if the request targets the root
    # configured domain (or localhost/127.0.0.1).
    if is_root_domain(host, ctx.config["wildcard_domain"]):
        await _handle_root_request(reader, writer, ctx, header_bytes, req_path, method,
                                   request_headers, host, is_https)
        return

    wildcard = ctx.config["wildcard_domain"].lower()
    if host.endswith("." + wildcard):
        subdomain = host[:-len("." + wildcard)]
    else:
        subdomain = host

    entry = ctx.by_subdomain.get(subdomain)
    if entry is not None and not entry[0].alive:
        # The owner is already being torn down but has not published its
        # reconnect hint yet (cleanup may be waiting for the claim lock).
        # Publishing the hint here and parking avoids racing cleanup with an
        # immediate 502; with grace disabled keep the old immediate failure.
        if int(ctx.config.get("http_reconnect_grace_seconds", 0) or 0) > 0:
            _record_reconnect_hint(ctx, subdomain)
            entry = None
    if entry is None:
        # Unknown names must be an immediate 404, before any cap, quota or
        # wait. Only a known recent outage is allowed to park the request.
        outcome = await _wait_for_reconnect(ctx, subdomain, reader, writer)
        if outcome == "unknown":
            await send_http_error(writer, 404, "No tunnel registered for this host")
            return
        if outcome != "ready":
            await send_http_error(writer, 503, "Service Unavailable", retry_after=2)
            return
        # Race-safe: always re-read the registry after waking instead of
        # holding a stale owner reference.
        entry = ctx.by_subdomain.get(subdomain)
        if entry is None:
            await send_http_error(writer, 503, "Service Unavailable", retry_after=2)
            return

    session, tunnel_id = entry
    if not session.alive:
        await send_http_error(writer, 502, "Tunnel client is offline")
        return
    tunnel = session.tunnels.get(tunnel_id)
    if not tunnel:
        await send_http_error(writer, 502, "Tunnel no longer registered")
        return
    if not session.can_open_stream():
        await send_http_error(writer, 503, "Service Unavailable", retry_after=2)
        return

    await open_new_stream(session, tunnel, reader, writer, header_bytes, "http",
                          writer.get_extra_info("peername") or ("?", 0), ctx)


# =============================================================================
# TCP public listener (one per registered TCP tunnel)
# =============================================================================

async def handle_public_tcp_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  ctx: ServerContext, port: int):
    peer = writer.get_extra_info("peername") or ("?", 0)
    entry = ctx.by_port.get(port)
    if not entry:
        writer.close()
        return
    session, tunnel_id = entry
    if not session.alive:
        writer.close()
        return
    tunnel = session.tunnels.get(tunnel_id)
    if not tunnel or not session.can_open_stream():
        writer.close()
        return
    await open_new_stream(session, tunnel, reader, writer, b"", "tcp", peer, ctx)


# =============================================================================
# UDP public listener (one per registered UDP tunnel)
# =============================================================================

async def handle_udp_public_datagram(session: ClientSession, tunnel: TunnelInfo,
                                     data: bytes, remote_addr: tuple, ctx: ServerContext):
    """Forward one inbound public UDP datagram to the owning client.

    Each distinct public peer (remote_addr) gets its own multiplexed stream
    so replies can be routed back to the correct address. Datagrams ride in
    UDP_DATAGRAM frames and are *never* charged against TCP flow control.
    """
    if len(data) > UDP_MAX_DATAGRAM:
        return
    if tunnel.udp_streams is None:
        tunnel.udp_streams = {}
    sid = tunnel.udp_streams.get(remote_addr)
    stream = session.streams.get(sid) if sid is not None else None

    if stream is None:
        if not session.can_open_stream():
            return
        if len(tunnel.udp_streams) >= int(ctx.limits.get("udp_max_peers_per_tunnel", 128)):
            return
        sid = session.alloc_stream_id()
        stream = StreamState(stream_id=sid, tunnel_id=tunnel.tunnel_id, public_writer=None,
                             udp_remote_addr=remote_addr)
        session.streams[sid] = stream
        tunnel.udp_streams[remote_addr] = sid
        tunnel.connection_count += 1
        meta = json.dumps({
            "tunnel_id": tunnel.tunnel_id,
            "proto": "udp",
            "remote_addr": f"{remote_addr[0]}:{remote_addr[1]}",
        }).encode()
        try:
            await session.send_frame(FrameType.STREAM_OPEN, sid, meta)
        except Exception:
            session.streams.pop(sid, None)
            tunnel.udp_streams.pop(remote_addr, None)
            return

    stream.last_activity = time.monotonic()
    # An empty datagram is a real datagram (and commonly a keepalive), so it
    # is forwarded too.
    try:
        await session.send_frame(FrameType.UDP_DATAGRAM, stream.stream_id, data)
        stream.bytes_in += len(data)
        session.bytes_in += len(data)
        tunnel.bytes_in += len(data)
    except Exception:
        pass


def _bind_udp_socket(bind_host: str, port: int) -> Optional[socket.socket]:
    """Bind a non-blocking UDP socket. Done synchronously before the tunnel
    is announced so a client never sees a 'ready' tunnel that has no socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    try:
        sock.bind((bind_host, port))
    except OSError as e:
        log.error("UDP bind failed on %s:%s: %s", bind_host, port, e)
        sock.close()
        return None
    return sock


async def serve_udp_tunnel(session: ClientSession, tunnel: TunnelInfo, ctx: ServerContext,
                           sock: socket.socket):
    """Pump datagrams from an already-bound UDP socket to the client."""
    loop = asyncio.get_running_loop()
    tunnel.udp_sock = sock
    try:
        while session.alive and tunnel.tunnel_id in session.tunnels:
            try:
                data, remote_addr = await loop.sock_recvfrom(sock, 65535)
            except (OSError, ConnectionError):
                break
            try:
                await handle_udp_public_datagram(session, tunnel, data, remote_addr, ctx)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("UDP datagram handling failed")
    except asyncio.CancelledError:
        raise
    finally:
        try:
            sock.close()
        except Exception:
            pass


# =============================================================================
# Control-connection: tunnel lifecycle handlers
# =============================================================================

async def _send_tunnel_open_response(session: ClientSession, payload: dict):
    try:
        await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID,
                                  json.dumps(payload).encode())
    except Exception:
        pass


async def _reject_tunnel_claim(session: ClientSession, tunnel_id: str, error: str,
                                reason: Optional[str] = None):
    resp = {"tunnel_id": tunnel_id, "status": "error", "error": error}
    if reason:
        resp["reason"] = reason
    await _send_tunnel_open_response(session, resp)


def _entry_owner(entry, session: ClientSession, tunnel_id: str) -> bool:
    """True if `entry` (session, tunnel_id) still belongs to that exact pair."""
    return entry is not None and entry[0] is session and entry[1] == tunnel_id


def _same_process(old_session: ClientSession, old_tunnel: Optional[TunnelInfo],
                  session: ClientSession, instance_id: Optional[str]) -> bool:
    old_instance = old_tunnel.instance_id if old_tunnel is not None else None
    return (
        old_session.client_id == session.client_id
        and (instance_id is None or old_instance is None or instance_id == old_instance)
    )


async def resolve_claim_conflict(session: ClientSession, ctx: ServerContext, entry,
                                 label: str, kind: str, mode: str,
                                 instance_id: Optional[str]):
    """Decide what to do when `label` (a public name: subdomain or port) is
    already registered to `entry` = (other_session, other_tunnel_id).

    Ownership follows the mode stored on the *existing* tunnel:

      lease   -> the newcomer is refused, nothing else changes.
      handoff -> the newcomer takes the name; the previous owner's tunnel is
                 revoked and it is told why ("handed off to a new client").

    Exception: a reconnect of the *same client process* (same client_id and
    same instance id) always reclaims its own previous registration, even a
    leased one, because the server may not have noticed the old TCP
    connection dying yet.

    Returns None when the caller may retry the allocation, or a
    (error_message, reason_code) tuple when the claim must be refused.
    """
    old_session, old_tunnel_id = entry
    old_tunnel = old_session.tunnels.get(old_tunnel_id)
    old_mode = old_tunnel.mode if old_tunnel is not None else TUNNEL_MODE_HANDOFF

    if _same_process(old_session, old_tunnel, session, instance_id):
        log.info("Reclaiming %s '%s' for reconnecting client %s",
                 kind, label, session.client_id[:8])
        # Only notify when the old registration lives on a different
        # connection -- notifying the very connection that is re-claiming
        # would make the client think it had lost the tunnel.
        notify = old_session is not session
        await close_tunnel(old_session, old_tunnel_id, ctx,
                           reason="reclaimed" if notify else None,
                           message=f"Tunnel '{label}' was reclaimed by the same client reconnecting")
        return None

    if old_mode == TUNNEL_MODE_LEASE:
        log.info("Refused %s '%s' for client %s: leased by client %s",
                 kind, label, session.client_id[:8], old_session.client_id[:8])
        return (
            f"{kind} '{label}' is leased to another client and cannot be taken over; "
            f"choose a different name or wait for the lease holder to disconnect",
            "leased",
        )

    if mode == TUNNEL_MODE_LEASE:
        log.info("Refused lease on %s '%s' for client %s: already in use by client %s",
                 kind, label, session.client_id[:8], old_session.client_id[:8])
        return (
            f"{kind} '{label}' is already in use by another client and lease mode does not "
            f"take over existing tunnels; reconnect without --lease to hand the name over",
            "in_use",
        )

    log.info("Handing off %s '%s' from client %s to client %s",
             kind, label, old_session.client_id[:8], session.client_id[:8])
    ctx.log_event(f"Handed off {kind} '{label}' from client {old_session.client_id[:8]} "
                  f"to client {session.client_id[:8]} (handoff mode)")
    await close_tunnel(old_session, old_tunnel_id, ctx, reason="handoff",
                       message=f"Tunnel '{label}' was handed off to a new client")
    return None


async def claim_public_name(session: ClientSession, ctx: ServerContext, requested,
                            allocate, registry: dict, kind: str, mode: str,
                            instance_id: Optional[str]):
    """Reserve a public name for a new tunnel.

    `requested` is the name the client asked for (None = pick one). Returns
    (granted_name, error, reason); `granted_name` is None on failure.
    """
    granted = allocate(ctx, requested)
    if granted is not None and (requested is None or granted == requested):
        return granted, None, None
    if not requested:
        return None, f"no {kind}s available", "exhausted"

    entry = registry.get(requested)
    if entry is None:
        # Nothing registered under that name: either it was freed between the
        # two calls, or the port is held by an unrelated local process.
        granted = allocate(ctx, requested)
        if granted is not None and granted == requested:
            return granted, None, None
        return None, f"{kind} '{requested}' is already in use", "in_use"

    conflict = await resolve_claim_conflict(session, ctx, entry, requested, kind,
                                            mode, instance_id)
    if conflict is not None:
        error, reason = conflict
        return None, error, reason

    granted = allocate(ctx, requested)
    if granted is None or granted != requested:
        return None, f"{kind} '{requested}' is already in use", "in_use"
    return granted, None, None


def _save_tunnel(ctx: ServerContext, tunnel: TunnelInfo, session: ClientSession):
    """Best-effort bookkeeping. Routing is in memory, so a DB failure must
    never take down a live route (and never leaves a half-written row)."""
    try:
        ctx.storage.save_tunnel(tunnel.tunnel_id, session.client_id, tunnel.type,
                                tunnel.subdomain, tunnel.remote_port)
    except Exception:
        log.exception("Failed to persist tunnel %s (route stays live)", tunnel.tunnel_id[:8])


async def handle_tunnel_open(session: ClientSession, frame, ctx: ServerContext):
    try:
        req = json.loads(frame.payload.decode())
    except Exception:
        await session.send_frame(FrameType.ERROR, CONTROL_STREAM_ID,
                                  json.dumps({"error": "malformed TUNNEL_OPEN_REQUEST"}).encode())
        return
    if not isinstance(req, dict):
        await session.send_frame(FrameType.ERROR, CONTROL_STREAM_ID,
                                  json.dumps({"error": "malformed TUNNEL_OPEN_REQUEST"}).encode())
        return

    tunnel_id = req.get("tunnel_id")
    if not isinstance(tunnel_id, str) or not tunnel_id or len(tunnel_id) > 128:
        tunnel_id = secrets.token_hex(8)
    ttype = req.get("type")
    mode = str(req.get("mode") or TUNNEL_MODE_HANDOFF).lower()
    instance_id = req.get("instance_id")
    if instance_id is not None and not isinstance(instance_id, str):
        instance_id = None

    # A client may advertise protocol capabilities per tunnel. Only explicit
    # advertisement turns on STREAM_EOF handling for this session.
    caps = req.get("capabilities")
    if isinstance(caps, list) and STREAM_CAPABILITY in caps:
        session.supports_stream_eof = True

    if ttype not in ("http", "tcp", "udp"):
        await _reject_tunnel_claim(session, tunnel_id,
                                    "type must be 'http', 'tcp' or 'udp'", "invalid")
        return
    if mode not in TUNNEL_MODES:
        await _reject_tunnel_claim(session, tunnel_id,
                                    f"mode must be one of: {', '.join(TUNNEL_MODES)}", "invalid")
        return

    # Name claims are serialised: allocate + lease check + eviction must be
    # atomic, otherwise two racing clients could both pass the check.
    async with ctx.claim_lock:
        # Duplicate tunnel id: never silently overwrite (which would orphan
        # the previous registration and collide in the DB).
        existing = ctx.tunnel_id_owner.get(tunnel_id)
        if existing is not None:
            other_session, _ = existing
            other_tunnel = other_session.tunnels.get(tunnel_id)
            if other_session is not session and _same_process(
                    other_session, other_tunnel, session, instance_id):
                await close_tunnel(other_session, tunnel_id, ctx, reason="reclaimed",
                                   message=f"Tunnel '{tunnel_id[:8]}' was reclaimed by the same client reconnecting")
            else:
                await _reject_tunnel_claim(
                    session, tunnel_id,
                    f"tunnel_id '{tunnel_id[:8]}' is already active on another connection",
                    "duplicate")
                return

        if len(session.tunnels) >= int(ctx.limits.get("max_tunnels_per_client", 32)):
            await _reject_tunnel_claim(
                session, tunnel_id,
                f"client already has the maximum of {ctx.limits.get('max_tunnels_per_client')} tunnels",
                "limit")
            return

        if ttype == "http":
            requested = req.get("subdomain")
            if requested is not None:
                requested = str(requested).strip().lower() or None
            subdomain, error, reason = await claim_public_name(
                session, ctx, requested, allocate_subdomain, ctx.by_subdomain,
                "subdomain", mode, instance_id,
            )
            if subdomain is None:
                await _reject_tunnel_claim(session, tunnel_id, error, reason)
                return
            if not session.alive:
                return

            tunnel = TunnelInfo(tunnel_id=tunnel_id, type="http", mode=mode,
                                instance_id=instance_id, subdomain=subdomain,
                                supports_stream_eof=session.supports_stream_eof)
            session.tunnels[tunnel_id] = tunnel
            ctx.tunnel_id_owner[tunnel_id] = (session, tunnel_id)
            ctx.by_subdomain[subdomain] = (session, tunnel_id)
            _save_tunnel(ctx, tunnel, session)
            _notify_reconnect_waiters(ctx, subdomain)
            ctx.reconnect_hints.pop(subdomain, None)

            scheme = "https" if ctx.advertise_https else "http"
            public_url = f"{scheme}://{subdomain}.{ctx.config['wildcard_domain']}"
            resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "http",
                    "subdomain": subdomain, "public_url": public_url, "mode": mode}
            ctx.log_event(f"Client {session.client_id[:8]} opened HTTP tunnel "
                          f"{public_url} ({mode} mode)")

        elif ttype == "tcp":
            preferred = req.get("remote_port")
            port, error, reason = await claim_public_name(
                session, ctx, preferred, allocate_tcp_port, ctx.by_port,
                "TCP port", mode, instance_id,
            )
            if port is None:
                await _reject_tunnel_claim(session, tunnel_id, error, reason)
                return
            if not session.alive:
                return

            try:
                tcp_server = await asyncio.start_server(
                    lambda r, w, p=port: handle_public_tcp_conn(r, w, ctx, p),
                    ctx.config["tcp"].get("bind_host", "0.0.0.0"), port,
                )
            except OSError as e:
                await _reject_tunnel_claim(session, tunnel_id, f"bind failed: {e}", "bind_failed")
                return
            if not session.alive:
                tcp_server.close()
                return

            tunnel = TunnelInfo(tunnel_id=tunnel_id, type="tcp", mode=mode,
                                instance_id=instance_id, remote_port=port,
                                tcp_server=tcp_server,
                                supports_stream_eof=session.supports_stream_eof)
            session.tunnels[tunnel_id] = tunnel
            ctx.tunnel_id_owner[tunnel_id] = (session, tunnel_id)
            ctx.by_port[port] = (session, tunnel_id)
            _save_tunnel(ctx, tunnel, session)

            resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "tcp",
                    "remote_port": port, "public_host": ctx.config["wildcard_domain"],
                    "mode": mode}
            ctx.log_event(f"Client {session.client_id[:8]} opened TCP tunnel on port "
                          f"{port} ({mode} mode)")

        else:  # udp
            preferred = req.get("remote_port")
            port, error, reason = await claim_public_name(
                session, ctx, preferred, allocate_udp_port, ctx.by_udp_port,
                "UDP port", mode, instance_id,
            )
            if port is None:
                await _reject_tunnel_claim(session, tunnel_id, error, reason)
                return
            if not session.alive:
                return

            bind_host = ctx.config["udp"].get("bind_host", "0.0.0.0")
            udp_sock = _bind_udp_socket(bind_host, port)
            if udp_sock is None:
                await _reject_tunnel_claim(session, tunnel_id,
                                            f"UDP bind failed on {bind_host}:{port}", "bind_failed")
                return

            tunnel = TunnelInfo(tunnel_id=tunnel_id, type="udp", mode=mode,
                                instance_id=instance_id, remote_port=port,
                                udp_sock=udp_sock, udp_streams={},
                                supports_stream_eof=session.supports_stream_eof)
            session.tunnels[tunnel_id] = tunnel
            ctx.tunnel_id_owner[tunnel_id] = (session, tunnel_id)
            ctx.by_udp_port[port] = (session, tunnel_id)
            _save_tunnel(ctx, tunnel, session)

            tunnel.serve_task = session.spawn(serve_udp_tunnel(session, tunnel, ctx, udp_sock))

            resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "udp",
                    "remote_port": port, "public_host": ctx.config["wildcard_domain"],
                    "mode": mode}
            ctx.log_event(f"Client {session.client_id[:8]} opened UDP tunnel on port "
                          f"{port} ({mode} mode)")

        await _send_tunnel_open_response(session, resp)


async def close_tunnel(session: ClientSession, tunnel_id: str, ctx: ServerContext,
                       reason: Optional[str] = None, message: Optional[str] = None,
                       tombstone: bool = False):
    """Unregister a tunnel and free its public name.

    When `reason` is given the owning client is told about the revocation
    with a TUNNEL_CLOSE frame carrying that reason ("handoff", "reclaimed"),
    so it can report an informative message instead of silently going quiet.

    `tombstone` records a short reconnect hint for an HTTP host that vanished
    unexpectedly (client connection lost), so inbound requests can be held
    briefly instead of failing with a transient 404. Explicit closes and
    handoffs never tombstone.
    """
    tunnel = session.tunnels.pop(tunnel_id, None)
    if not tunnel:
        return

    if reason:
        payload = json.dumps({
            "tunnel_id": tunnel_id,
            "reason": reason,
            "message": message or f"Tunnel {tunnel_id[:8]} was closed by the server",
        }).encode()
        try:
            # Short budget: this recipient is a different, possibly-stalled
            # session and may be revoked while the global claim lock is held.
            await session.send_frame(FrameType.TUNNEL_CLOSE, CONTROL_STREAM_ID, payload,
                                     timeout=CONTROL_NOTIFY_TIMEOUT)
        except Exception:
            pass

    # Only free a registry slot if it still points at *this* tunnel -- after a
    # handoff the name already belongs to the new owner and must not be stolen
    # back by the old session's late cleanup.
    if tunnel.type == "http" and tunnel.subdomain:
        if _entry_owner(ctx.by_subdomain.get(tunnel.subdomain), session, tunnel_id):
            ctx.by_subdomain.pop(tunnel.subdomain, None)
            if tombstone and reason is None:
                _record_reconnect_hint(ctx, tunnel.subdomain)
    if tunnel.type == "tcp" and tunnel.remote_port is not None:
        if _entry_owner(ctx.by_port.get(tunnel.remote_port), session, tunnel_id):
            ctx.by_port.pop(tunnel.remote_port, None)
    if tunnel.type == "udp" and tunnel.remote_port is not None:
        if _entry_owner(ctx.by_udp_port.get(tunnel.remote_port), session, tunnel_id):
            ctx.by_udp_port.pop(tunnel.remote_port, None)

    if _entry_owner(ctx.tunnel_id_owner.get(tunnel_id), session, tunnel_id):
        ctx.tunnel_id_owner.pop(tunnel_id, None)

    # Tear down the data plane BEFORE waiting on the listener. Finalizing the
    # streams closes their public sockets, so Server.wait_closed() (which in
    # 3.12 waits for live connections) does not block on a half-open stream.
    # The TUNNEL_CLOSE (if any) already told the client to drop them, so no
    # per-stream notification is needed here.
    for sid, stream in list(session.streams.items()):
        if stream.tunnel_id == tunnel_id:
            await _finalize_stream(session, stream)

    if tunnel.type == "tcp" and tunnel.tcp_server is not None:
        tunnel.tcp_server.close()
        try:
            await asyncio.wait_for(tunnel.tcp_server.wait_closed(), timeout=5)
        except (asyncio.TimeoutError, Exception):
            pass
    if tunnel.type == "udp":
        if tunnel.serve_task is not None and tunnel.serve_task is not asyncio.current_task():
            tunnel.serve_task.cancel()
            await asyncio.gather(tunnel.serve_task, return_exceptions=True)
        if tunnel.udp_sock is not None:
            try:
                tunnel.udp_sock.close()
            except Exception:
                pass

    try:
        ctx.storage.delete_tunnel(tunnel_id)
    except Exception:
        log.exception("Failed to delete tunnel %s from storage", tunnel_id[:8])
    ctx.log_event(f"Tunnel {tunnel_id[:8]} closed" + (f" ({reason})" if reason else ""))


async def handle_tunnel_close(session: ClientSession, frame, ctx: ServerContext):
    try:
        req = json.loads(frame.payload.decode())
        tunnel_id = req["tunnel_id"]
    except Exception:
        return
    if not isinstance(req, dict) or not isinstance(tunnel_id, str):
        return
    async with ctx.claim_lock:
        await close_tunnel(session, tunnel_id, ctx)


# =============================================================================
# Control-connection: stream data / close / window-update handlers
# =============================================================================

async def handle_stream_data(session: ClientSession, frame, ctx: ServerContext):
    """Client -> public payload. Never awaits the public destination drain.

    The session reader only enqueues, bounded by the per-stream receive
    credit we granted; small frames are coalesced so fragmentation cannot
    trip a frame-count limit. A peer that sends beyond its credit is flooding
    and has the stream aborted.
    """
    stream = session.streams.get(frame.stream_id)
    if stream is None or stream.closed or stream.is_udp:
        return
    if stream.client_eof:
        return  # nothing may follow the sender's EOF
    n = len(frame.payload)
    if n == 0:
        return
    if n > stream.recv_credit:
        log.warning("Client %s exceeded receive credit on stream %s; aborting",
                    session.client_id[:8], frame.stream_id)
        await abort_stream(session, stream, notify=True)
        return
    stream.recv_credit -= n
    stream.last_activity = time.monotonic()
    if not stream.send_queue.put(frame.payload):
        await abort_stream(session, stream, notify=True)


async def handle_stream_close_from_client(session: ClientSession, frame, ctx: ServerContext):
    stream = session.streams.get(frame.stream_id)
    if stream is None:
        return
    if stream.is_udp:
        # A UDP peer stream has no half-close: this is a full abort.
        await abort_stream(session, stream, notify=False)
        return
    if session.supports_stream_eof:
        # Modern peer: STREAM_CLOSE is a full abort.
        await abort_stream(session, stream, notify=False)
        return
    # Legacy peer: STREAM_CLOSE doubles as EOF; drain queued data first so a
    # response body is never truncated.
    stream.client_eof = True
    stream.half_close = False
    stream.last_activity = time.monotonic()
    _signal_stream_eof(session, stream)


async def handle_stream_eof_from_client(session: ClientSession, frame, ctx: ServerContext):
    stream = session.streams.get(frame.stream_id)
    if stream is None or stream.closed or stream.is_udp:
        return
    stream.client_eof = True
    stream.half_close = True
    stream.last_activity = time.monotonic()
    _signal_stream_eof(session, stream)


def _signal_stream_eof(session: ClientSession, stream: StreamState, ctx: ServerContext = None):
    """Tell the writer to flush and half/full-close; defer finalization.

    Finalizing here (as the old code did when server_eof was already set)
    would cancel the writer before queued response bytes were flushed.
    """
    if stream.send_queue is not None:
        stream.send_queue.signal_eof()


async def handle_udp_datagram_from_client(session: ClientSession, frame, ctx: ServerContext):
    """Client -> server: forward a datagram to the public UDP peer.

    UDP is never flow-controlled by TCP credit, and empty datagrams are
    forwarded verbatim.
    """
    stream = session.streams.get(frame.stream_id)
    if stream is None or not stream.is_udp:
        return
    tunnel = session.tunnels.get(stream.tunnel_id)
    if tunnel is None or tunnel.udp_sock is None:
        return
    stream.last_activity = time.monotonic()
    n = len(frame.payload)
    stream.bytes_out += n
    session.bytes_out += n
    tunnel.bytes_out += n
    try:
        await asyncio.get_running_loop().sock_sendto(
            tunnel.udp_sock, frame.payload, stream.udp_remote_addr)
    except (OSError, ConnectionError):
        pass


def handle_window_update(session: ClientSession, frame):
    if len(frame.payload) != 4:
        return
    increment = int.from_bytes(frame.payload, "big")
    stream = session.streams.get(frame.stream_id)
    if stream is None or stream.is_udp:
        return
    # Reject nonsensical / oversized increments; replenish() caps the window.
    if increment <= 0 or increment > MAX_WINDOW_CREDIT:
        return
    stream.send_window.replenish(increment)


# =============================================================================
# Control connection: accept / handshake / main dispatch loop
# =============================================================================

async def client_loop(session: ClientSession, ctx: ServerContext):
    while True:
        frame = await read_frame(session.reader)
        session.last_seen = time.time()
        session.last_seen_mono = time.monotonic()

        if frame.type == FrameType.PING:
            if frame.stream_id != CONTROL_STREAM_ID:
                raise ProtocolError("PING must use the control stream")
            await session.send_frame(FrameType.PONG, CONTROL_STREAM_ID)
        elif frame.type == FrameType.PONG:
            if frame.stream_id != CONTROL_STREAM_ID:
                raise ProtocolError("PONG must use the control stream")
            pass
        elif frame.type == FrameType.TUNNEL_OPEN_REQUEST:
            if frame.stream_id != CONTROL_STREAM_ID:
                raise ProtocolError("TUNNEL_OPEN_REQUEST must use stream 0")
            await handle_tunnel_open(session, frame, ctx)
        elif frame.type == FrameType.TUNNEL_CLOSE:
            if frame.stream_id != CONTROL_STREAM_ID:
                raise ProtocolError("TUNNEL_CLOSE must use stream 0")
            await handle_tunnel_close(session, frame, ctx)
        elif frame.type == FrameType.STREAM_DATA:
            if frame.stream_id == CONTROL_STREAM_ID:
                raise ProtocolError("STREAM_DATA on the control stream")
            await handle_stream_data(session, frame, ctx)
        elif frame.type == FrameType.STREAM_CLOSE:
            if frame.stream_id == CONTROL_STREAM_ID:
                raise ProtocolError("STREAM_CLOSE on the control stream")
            await handle_stream_close_from_client(session, frame, ctx)
        elif frame.type == FrameType.STREAM_EOF:
            if frame.stream_id == CONTROL_STREAM_ID:
                raise ProtocolError("STREAM_EOF on the control stream")
            await handle_stream_eof_from_client(session, frame, ctx)
        elif frame.type == FrameType.STREAM_WINDOW_UPDATE:
            handle_window_update(session, frame)
        elif frame.type == FrameType.UDP_DATAGRAM:
            if frame.stream_id == CONTROL_STREAM_ID:
                raise ProtocolError("UDP_DATAGRAM on the control stream")
            await handle_udp_datagram_from_client(session, frame, ctx)
        elif frame.type == FrameType.ERROR:
            log.warning("Client %s reported error: %s", session.client_id[:8], frame.payload[:200])
        else:
            log.warning("Unknown frame type %s from client %s", frame.type, session.client_id[:8])


async def heartbeat_loop(session: ClientSession, ctx: ServerContext):
    interval = ctx.config["heartbeat_interval_seconds"]
    timeout = ctx.config["heartbeat_timeout_seconds"]
    while session.alive:
        await asyncio.sleep(interval)
        if time.monotonic() - session.last_seen_mono > timeout:
            log.warning("Client %s heartbeat timeout; closing connection", session.client_id[:8])
            try:
                session.writer.close()
            except Exception:
                pass
            return
        try:
            await session.send_frame(FrameType.PING, CONTROL_STREAM_ID)
        except Exception:
            return


async def cleanup_client(session: ClientSession, ctx: ServerContext, *, tombstone: bool = True):
    """Idempotent session teardown; concurrent callers serialise on a lock."""
    async with session._cleanup_lock:
        if session._cleaned:
            return
        session.alive = False
        # Closing tunnels drops their streams and frees public names. A client
        # that vanished without an explicit close leaves a short reconnect hint.
        # Serialise with name claims so a claim cannot install a dead session.
        async with ctx.claim_lock:
            for tunnel_id in list(session.tunnels.keys()):
                await close_tunnel(session, tunnel_id, ctx, tombstone=tombstone)
        for stream in list(session.streams.values()):
            await _finalize_stream(session, stream)

        # Cancel and *await* every task this session owns so nothing (heartbeat,
        # stream pump, UDP server, writer) lingers after the session is gone.
        tasks = [t for t in session.tasks if not t.done() and t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        session.tasks.clear()
        session.streams.clear()

        sessions = ctx.clients.get(session.client_id, set())
        sessions.discard(session)
        if not sessions:
            ctx.clients.pop(session.client_id, None)
        try:
            session.writer.close()
            await session.writer.wait_closed()
        except Exception:
            pass
        session._cleaned = True
        ctx.log_event(f"Client {session.client_id[:8]} disconnected")
        log.info("Client %s disconnected and cleaned up", session.client_id[:8])


async def handle_control_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                    ctx: ServerContext):
    addr = writer.get_extra_info("peername") or ("?", 0)
    max_clients = int(ctx.limits.get("max_clients", 128))
    # Bound unauthenticated handshakes so slowloris-style clients cannot
    # accumulate before HELLO.
    if ctx.pending_control >= max_clients:
        try:
            writer.close()
        except Exception:
            pass
        return
    ctx.pending_control += 1
    session = None
    try:
        try:
            version, ftype, stream_id, length = await asyncio.wait_for(
                read_frame_header(reader), timeout=10)
        except Exception:
            try:
                writer.close()
            except Exception:
                pass
            return

        # Require exactly a 72-byte HELLO on the control stream *before*
        # reading any payload, so a bogus 16 MiB length is never buffered.
        if ftype != FrameType.HELLO or stream_id != CONTROL_STREAM_ID or length != HELLO_PAYLOAD_LEN:
            try:
                writer.write(encode_frame(FrameType.HELLO_FAIL, CONTROL_STREAM_ID,
                                           json.dumps({"error": "expected HELLO"}).encode()))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return
        try:
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=10)
        except Exception:
            writer.close()
            return
        frame = Frame(version=version, type=ftype, stream_id=stream_id, payload=payload)

        ok, client_id, reason = verify_hello_payload(frame.payload, ctx.config["shared_secret"],
                                                     ctx.seen_nonces)
        if not ok:
            log.warning("Rejected HELLO from %s: %s", addr[0], reason)
            try:
                writer.write(encode_frame(FrameType.HELLO_FAIL, CONTROL_STREAM_ID,
                                           json.dumps({"error": reason}).encode()))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return

        if ctx.total_sessions() >= max_clients:
            log.warning("Refusing client %s: server at capacity (%d)", client_id[:8], max_clients)
            try:
                # ERROR (not HELLO_FAIL) so a client never treats capacity as
                # a permanent authentication failure: it is retryable.
                writer.write(encode_frame(FrameType.ERROR, CONTROL_STREAM_ID, json.dumps({
                    "error": "server at capacity",
                    "reason": "capacity",
                    "retryable": True,
                }).encode()))
                await writer.drain()
            except Exception:
                pass
            writer.close()
            return

        # A single user may run multiple client processes from the same
        # machine (they share a client_id via the persisted state file) --
        # keep them all. Which session wins a contested tunnel name is
        # decided at tunnel-open time by the ownership mode.
        existing_sessions = ctx.clients.get(client_id, set())
        session = ClientSession(client_id, reader, writer, ctx.limits)
        existing_sessions.add(session)
        ctx.clients[client_id] = existing_sessions
        try:
            ctx.storage.upsert_client(client_id)
        except Exception:
            log.exception("Failed to record client %s", client_id[:8])

        resp = json.dumps({
            "client_id": client_id,
            "heartbeat_interval": ctx.config["heartbeat_interval_seconds"],
            "server_version": 1,
            "capabilities": list(SERVER_CAPABILITIES),
        }).encode()
        try:
            await session.send_frame(FrameType.HELLO_OK, CONTROL_STREAM_ID, resp)
        except Exception:
            existing_sessions.discard(session)
            if not existing_sessions:
                ctx.clients.pop(client_id, None)
            return

        ctx.log_event(f"Client {client_id[:8]} connected from {addr[0]}")
        log.info("Client %s authenticated from %s", client_id[:8], addr[0])

        session.spawn(heartbeat_loop(session, ctx))
        try:
            await client_loop(session, ctx)
        except (asyncio.IncompleteReadError, ConnectionError, ProtocolError, OSError) as e:
            log.info("Client %s connection ended: %s", client_id[:8], e)
        except Exception:
            log.exception("Unexpected error in client loop for %s", client_id[:8])
    finally:
        ctx.pending_control -= 1
        if session is not None:
            await cleanup_client(session, ctx)
        else:
            # Unauthenticated/partial connection: make sure its transport is
            # closed so a graceful shutdown never waits on it.
            try:
                writer.close()
            except Exception:
                pass


# =============================================================================
# Background maintenance tasks
# =============================================================================

def _prune_nonces(ctx: ServerContext):
    # Entries store their own expiry (HELLO timestamp + allowed skew), so a
    # replay is rejected for exactly as long as the timestamp would be
    # acceptable -- no shorter, no longer.
    now = time.time()
    stale_keys = [k for k, expiry in ctx.seen_nonces.items() if expiry <= now]
    for k in stale_keys:
        ctx.seen_nonces.pop(k, None)


async def _reap_idle_udp(ctx: ServerContext, now: float):
    """Close idle UDP peers. `now` must be time.monotonic()."""
    idle_timeout = int(ctx.limits.get("udp_idle_timeout", 60))
    for sessions in list(ctx.clients.values()):
        for session in list(sessions):
            for sid, stream in list(session.streams.items()):
                if stream.is_udp and now - stream.last_activity > idle_timeout:
                    # Full abort (STREAM_CLOSE) so the client tears down its
                    # local datagram endpoint instead of leaking the stream.
                    await abort_stream(session, stream, notify=True)


def _touch_active_records(ctx: ServerContext):
    for sessions in list(ctx.clients.values()):
        for session in list(sessions):
            try:
                ctx.storage.touch_client(session.client_id)
                ctx.storage.touch_tunnels_for_client(session.client_id)
            except Exception:
                log.exception("Failed to touch storage for client %s", session.client_id[:8])


async def maintenance_loop(ctx: ServerContext):
    while True:
        await asyncio.sleep(60)
        _prune_nonces(ctx)
        _prune_reconnect_hints(ctx, time.monotonic())
        await _reap_idle_udp(ctx, time.monotonic())
        _touch_active_records(ctx)
        try:
            ctx.storage.purge_stale(ctx.config["stale_grace_seconds"])
        except Exception:
            log.exception("storage purge failed")


# =============================================================================
# Startup / main
# =============================================================================

def setup_logging(ctx: ServerContext):
    cfg = ctx.config["logging"]
    level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    if cfg.get("file"):
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(cfg["file"])
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fileh = logging.FileHandler(cfg["file"])
        fileh.setFormatter(fmt)
        root.addHandler(fileh)

    dq = DequeLogHandler(ctx)
    dq.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    root.addHandler(dq)


def _load_ssl_context(config: dict) -> Optional[ssl.SSLContext]:
    """Load the TLS context from cert files. Returns None if unavailable."""
    if config.get("http_only"):
        return None
    tls = config["tls"]
    cert_path, key_path = tls.get("cert_path"), tls.get("key_path")
    if not cert_path or not key_path:
        return None
    if not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        log.warning("TLS certificates not found (%s / %s) -- serving HTTP only. "
                    "Provision them with certbot or set HTTP_ONLY=true.",
                    cert_path, key_path)
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx
    except (ssl.SSLError, OSError) as e:
        log.warning("Could not load TLS certificates: %s -- serving HTTP only.", e)
        return None


def _control_cert_paths(config: dict) -> tuple[Optional[str], Optional[str]]:
    control = config["control"]
    return (control.get("cert_path") or config["tls"].get("cert_path"),
            control.get("key_path") or config["tls"].get("key_path"))


def _load_control_ssl_context(config: dict) -> Optional[ssl.SSLContext]:
    """Build the control-channel TLS context when CONTROL_TLS is enabled.

    Native control TLS is optional and off by default (existing plaintext
    clients keep working), but when explicitly requested a missing or
    unreadable certificate is a startup error rather than a silent downgrade.
    """
    control = config["control"]
    if not control.get("tls"):
        return None
    cert_path, key_path = _control_cert_paths(config)
    if not cert_path or not key_path or not (os.path.isfile(cert_path) and os.path.isfile(key_path)):
        raise RuntimeError(
            "CONTROL_TLS is enabled but the control certificate/key could not be found "
            f"({cert_path} / {key_path}). Set CONTROL_CERT_PATH and CONTROL_KEY_PATH."
        )
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx
    except (ssl.SSLError, OSError) as e:
        raise RuntimeError(f"CONTROL_TLS enabled but control certificates failed to load: {e}")


async def cert_reload_loop(ctx: ServerContext, ssl_ctx: ssl.SSLContext,
                           cert_path: Optional[str] = None,
                           key_path: Optional[str] = None,
                           interval: float = 60.0):
    """Reload TLS certs in place when certbot renews them.

    Reusable for both the public and control contexts (they may use the same
    cert files but are distinct SSLContext objects, so each must reload). The
    initial mtime is captured *before* the first sleep, so an unchanged cert
    does not trigger a pointless reload on startup.
    """
    cert_path = cert_path or ctx.config["tls"].get("cert_path")
    key_path = key_path or ctx.config["tls"].get("key_path")
    if not cert_path or not key_path:
        return
    last_mtime = -1.0
    try:
        last_mtime = max(os.path.getmtime(cert_path), os.path.getmtime(key_path))
    except OSError:
        pass
    while True:
        await asyncio.sleep(interval)
        try:
            m = max(os.path.getmtime(cert_path), os.path.getmtime(key_path))
        except OSError:
            continue
        if m != last_mtime:
            try:
                ssl_ctx.load_cert_chain(cert_path, key_path)
                last_mtime = m
                log.info("TLS certificates reloaded from %s", cert_path)
            except (ssl.SSLError, OSError) as e:
                log.warning("TLS cert reload failed for %s: %s", cert_path, e)


async def run():
    config = load_config()
    validate_config(config)
    # Production startup requires a genuinely strong JWT key. (validate_config
    # keeps a lower bound so in-process unit fixtures remain usable.)
    if len(str(config.get("jwt_secret") or "")) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters long for production use.")

    # Create database directory if it doesn't exist
    db_path = config["storage"]["db_path"]
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    ctx = ServerContext(config)
    setup_logging(ctx)
    servers: list = []
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _control_conn(reader, writer):
        ctx.spawn_accepted(handle_control_connection(reader, writer, ctx), writer)

    def _http_conn(reader, writer):
        ctx.spawn_accepted(handle_public_http_conn(reader, writer, ctx, is_https=False), writer)

    def _request_stop():
        log.info("Shutdown signal received")
        stop_event.set()

    def _signal_handler(signum, frame):
        # Signal handlers run on the main thread but outside the event
        # loop's normal scheduling; call_soon_threadsafe is the correct,
        # safe way to wake up a waiting coroutine from here. This works
        # identically on POSIX and Windows (unlike loop.add_signal_handler,
        # which raises NotImplementedError on Windows).
        try:
            loop.call_soon_threadsafe(_request_stop)
        except RuntimeError:
            pass  # loop already closed/closing

    try:
        # The public TLS context is built once and reused for every request
        # (no disk access per connection). Whether we *advertise* https is
        # derived from the effective listener state, not just the config flag:
        # with HTTP_ONLY=false but no usable certificate we still serve http
        # URLs, while an explicit upstream terminator (EXTERNAL_SSL=true) may
        # advertise https and set Secure cookies.
        ssl_ctx = _load_ssl_context(config)
        if (ssl_ctx is None and not config.get("http_only") and not config.get("external_ssl")
                and not config.get("allow_http_fallback")):
            raise RuntimeError(
                "No usable TLS certificate found and HTTP_ONLY is false. Set HTTP_ONLY=true "
                "for a plaintext deployment, EXTERNAL_SSL=true if TLS is terminated upstream, "
                "or ALLOW_HTTP_FALLBACK=true to accept a plaintext fallback."
            )
        ctx.ssl_context = ssl_ctx
        ctx.https_listener = ssl_ctx is not None
        ctx.advertise_https = bool(not config.get("http_only") and (ssl_ctx is not None
                                                                    or config.get("external_ssl")))

        control_ssl_ctx = _load_control_ssl_context(config)
        if control_ssl_ctx is None:
            log.warning("Control channel is running WITHOUT TLS (set CONTROL_TLS=true and provide "
                        "certificates to encrypt it; use a private network until then).")

        control_cfg = config["control"]
        control_server = await asyncio.start_server(
            _control_conn, control_cfg["host"], control_cfg["port"], ssl=control_ssl_ctx,
        )
        servers.append(control_server)
        log.info("Control channel listening on %s:%s (tls=%s)",
                 control_cfg["host"], control_cfg["port"], control_ssl_ctx is not None)

        http_cfg = config["http"]
        http_server = await asyncio.start_server(
            _http_conn, http_cfg["host"], http_cfg["port"],
        )
        servers.append(http_server)
        log.info("Public HTTP listening on %s:%s", http_cfg["host"], http_cfg["port"])

        ctx.spawn(control_server.serve_forever())
        ctx.spawn(http_server.serve_forever())
        ctx.spawn(maintenance_loop(ctx))

        public_reload_started = False
        if ssl_ctx is not None:
            https_cfg = config["https"]
            https_server = await asyncio.start_server(
                lambda r, w: ctx.spawn_accepted(
                    handle_public_http_conn(r, w, ctx, is_https=True), w),
                https_cfg["host"], https_cfg["port"], ssl=ssl_ctx,
            )
            servers.append(https_server)
            log.info("Public HTTPS listening on %s:%s", https_cfg["host"], https_cfg["port"])
            ctx.spawn(https_server.serve_forever())
            ctx.spawn(cert_reload_loop(ctx, ssl_ctx))
            public_reload_started = True
            log.info("Dashboard available at https://%s/ (apex domain only)",
                     config["wildcard_domain"])
        else:
            log.info("Dashboard available at http://%s:%s (HTTP-only mode)",
                     config["dashboard"]["host"], config["dashboard"]["port"])
            ctx.spawn(dashboard_mod.serve_dashboard(ctx))

        # Reload the control context too: it may share the public cert files
        # but is a distinct SSLContext, so a renewal must be applied to both.
        if control_ssl_ctx is not None:
            if not (public_reload_started and control_ssl_ctx is ssl_ctx):
                control_cert, control_key = _control_cert_paths(config)
                ctx.spawn(cert_reload_loop(ctx, control_ssl_ctx, control_cert, control_key))

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _signal_handler)
            except (ValueError, OSError, AttributeError):
                # ValueError: not called from the main thread.
                # AttributeError: signal doesn't exist on this platform
                #   (defensive; SIGINT/SIGTERM both exist on Windows and POSIX).
                pass

        await stop_event.wait()
    finally:
        log.info("Shutting down...")
        # Stop accepting, cancel every owned task, and await them *before*
        # closing storage. This also runs on a startup failure so the DB
        # connection is never leaked.
        for server in servers:
            try:
                server.close()
            except Exception:
                pass
        for sessions in list(ctx.clients.values()):
            for session in list(sessions):
                session.alive = False
                try:
                    session.writer.close()
                except Exception:
                    pass
        all_tasks = [t for t in ctx.tasks if not t.done()]
        for t in all_tasks:
            t.cancel()
        # Close any accepted transports so cancelled handlers can finish and
        # Server.wait_closed() (which in 3.12 waits on live connections) returns.
        leftover = list(ctx.accepted_writers)
        for writer in leftover:
            try:
                writer.close()
            except Exception:
                pass
        if all_tasks:
            await asyncio.gather(*all_tasks, return_exceptions=True)
        if leftover:
            await asyncio.gather(*(w.wait_closed() for w in leftover), return_exceptions=True)
        ctx.accepted_writers.clear()
        for server in servers:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, Exception):
                pass
        for sessions in list(ctx.clients.values()):
            for session in list(sessions):
                try:
                    await cleanup_client(session, ctx, tombstone=False)
                except Exception:
                    log.exception("session cleanup failed during shutdown")
        ctx.storage.close()
        log.info("Shutdown complete")


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        # RuntimeErrors raised during startup (missing/placeholder secret,
        # invalid config, missing control certs, etc.) are deliberately
        # written to be read directly by the operator -- show just the
        # message, not a full traceback, so the actionable part isn't
        # buried under stack frames.
        print(f"\nStartup failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
