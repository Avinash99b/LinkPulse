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
    HTTP_HOST            - Public HTTP host (default: 0.0.0.0)
    HTTP_PORT            - Public HTTP port (default: 80)
    WILDCARD_DOMAIN      - Required, wildcard domain for tunnels
    TCP_PORT_MIN         - TCP port range minimum (default: 20000)
    TCP_PORT_MAX         - TCP port range maximum (default: 20100)
    DASHBOARD_HOST       - Dashboard host (default: 0.0.0.0)
    DASHBOARD_PORT       - Dashboard port (default: 8080)
    HTTP_ONLY            - If true, use http:// URLs (default: true)
    HEARTBEAT_INTERVAL   - Heartbeat interval in seconds (default: 20)
    HEARTBEAT_TIMEOUT    - Heartbeat timeout in seconds (default: 60)
    STALE_GRACE_SECONDS  - Stale client cleanup grace period (default: 300)
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
    FrameType,
    INITIAL_WINDOW,
    MAX_FRAME_PAYLOAD,
    ProtocolError,
    encode_frame,
    read_frame,
    verify_hello_payload,
)
from storage import Storage
import dashboard as dashboard_mod

log = logging.getLogger("proxy")

WINDOW_UPDATE_THRESHOLD = INITIAL_WINDOW // 2


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

    def replenish(self, n: int):
        self.available += n
        if self.available > 0:
            self._event.set()

    async def wait(self):
        await self._event.wait()


# =============================================================================
# Per-stream / per-tunnel / per-client state
# =============================================================================

@dataclass
class StreamState:
    """One multiplexed logical connection (one HTTP request-connection or
    one raw TCP connection, or one UDP peer) riding on a client's control
    connection."""
    stream_id: int
    tunnel_id: str
    public_writer: asyncio.StreamWriter  # None for UDP streams
    udp_remote_addr: Optional[tuple] = None  # (ip, port) for UDP streams
    send_window: FlowWindow = field(default_factory=FlowWindow)
    unacked_recv_bytes: int = 0
    closed: bool = False
    bytes_in: int = 0   # public -> client
    bytes_out: int = 0  # client -> public


@dataclass
class TunnelInfo:
    tunnel_id: str
    type: str  # "http" | "tcp" | "udp"
    subdomain: Optional[str] = None
    remote_port: Optional[int] = None
    tcp_server: Optional[asyncio.base_events.Server] = None
    udp_sock: Optional[socket.socket] = None
    udp_streams: Optional[dict] = None  # remote addr -> stream_id
    connection_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


class ClientSession:
    def __init__(self, client_id: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.client_id = client_id
        self.reader = reader
        self.writer = writer
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.tunnels: dict[str, TunnelInfo] = {}
        self.streams: dict[int, StreamState] = {}
        self._next_stream_id = 1
        self._write_lock = asyncio.Lock()
        self.alive = True
        self.bytes_in = 0   # public -> client, aggregate
        self.bytes_out = 0  # client -> public, aggregate

    def alloc_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id = (self._next_stream_id + 1) & 0xFFFFFFFF
        if self._next_stream_id == 0:
            self._next_stream_id = 1
        return sid

    async def send_frame(self, ftype: int, stream_id: int, payload: bytes = b""):
        data = encode_frame(ftype, stream_id, payload)
        async with self._write_lock:
            self.writer.write(data)
            await self.writer.drain()


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
        self.seen_nonces: dict[bytes, int] = {}
        self.start_time = time.time()
        self.recent_logs: deque[str] = deque(maxlen=200)
        self._used_ports_lock = asyncio.Lock()

    def log_event(self, msg: str):
        self.recent_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")


# =============================================================================
# Config
# =============================================================================

DEFAULT_CONFIG = {
    "shared_secret": "CHANGE_ME",
    "control": {"host": "0.0.0.0", "port": 9000, "tls": False},
    "http": {"host": "0.0.0.0", "port": 80},
    "https": {"host": "0.0.0.0", "port": 443},
    "wildcard_domain": "linkpulse.avinash9.in",
    "tcp": {"port_range": [10000, 65535], "bind_host": "0.0.0.0"},
    "udp": {"port_range": [10000, 65535], "bind_host": "0.0.0.0"},
    "dashboard": {"host": "0.0.0.0", "port": 8081},
    "http_only": False,
    "tls": {
        "cert_path": "/etc/letsencrypt/live/linkpulse.avinash9.in/fullchain.pem",
        "key_path": "/etc/letsencrypt/live/linkpulse.avinash9.in/privkey.pem",
    },
    "heartbeat_interval_seconds": 20,
    "heartbeat_timeout_seconds": 60,
    "stale_grace_seconds": 300,
    "storage": {"db_path": "/data/tunnel_proxy.db"},
    "logging": {"level": "INFO", "file": "/var/log/tunnel-proxy/tunnel_proxy.log"},
}


def load_config() -> dict:
    """Load configuration from environment variables with defaults."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy

    # Required environment variables
    if "SHARED_SECRET" in os.environ:
        cfg["shared_secret"] = os.environ["SHARED_SECRET"]
    if "WILDCARD_DOMAIN" in os.environ:
        cfg["wildcard_domain"] = os.environ["WILDCARD_DOMAIN"]

    # Optional environment variables with defaults
    if "CONTROL_HOST" in os.environ:
        cfg["control"]["host"] = os.environ["CONTROL_HOST"]
    if "CONTROL_PORT" in os.environ:
        cfg["control"]["port"] = int(os.environ["CONTROL_PORT"])
    if "HTTP_HOST" in os.environ:
        cfg["http"]["host"] = os.environ["HTTP_HOST"]
    if "HTTP_PORT" in os.environ:
        cfg["http"]["port"] = int(os.environ["HTTP_PORT"])
    if "HTTPS_HOST" in os.environ:
        cfg["https"]["host"] = os.environ["HTTPS_HOST"]
    if "HTTPS_PORT" in os.environ:
        cfg["https"]["port"] = int(os.environ["HTTPS_PORT"])
    if "TCP_PORT_MIN" in os.environ:
        cfg["tcp"]["port_range"][0] = int(os.environ["TCP_PORT_MIN"])
    if "TCP_PORT_MAX" in os.environ:
        cfg["tcp"]["port_range"][1] = int(os.environ["TCP_PORT_MAX"])
    if "UDP_PORT_MIN" in os.environ:
        cfg["udp"]["port_range"][0] = int(os.environ["UDP_PORT_MIN"])
    if "UDP_PORT_MAX" in os.environ:
        cfg["udp"]["port_range"][1] = int(os.environ["UDP_PORT_MAX"])
    if "CERT_PATH" in os.environ:
        cfg["tls"]["cert_path"] = os.environ["CERT_PATH"]
    if "KEY_PATH" in os.environ:
        cfg["tls"]["key_path"] = os.environ["KEY_PATH"]
    if "DASHBOARD_HOST" in os.environ:
        cfg["dashboard"]["host"] = os.environ["DASHBOARD_HOST"]
    if "DASHBOARD_PORT" in os.environ:
        cfg["dashboard"]["port"] = int(os.environ["DASHBOARD_PORT"])
    if "HTTP_ONLY" in os.environ:
        cfg["http_only"] = os.environ["HTTP_ONLY"].lower() in ("true", "1", "yes")
    if "HEARTBEAT_INTERVAL" in os.environ:
        cfg["heartbeat_interval_seconds"] = int(os.environ["HEARTBEAT_INTERVAL"])
    if "HEARTBEAT_TIMEOUT" in os.environ:
        cfg["heartbeat_timeout_seconds"] = int(os.environ["HEARTBEAT_TIMEOUT"])
    if "STALE_GRACE_SECONDS" in os.environ:
        cfg["stale_grace_seconds"] = int(os.environ["STALE_GRACE_SECONDS"])
    if "DB_PATH" in os.environ:
        cfg["storage"]["db_path"] = os.environ["DB_PATH"]
    if "LOG_LEVEL" in os.environ:
        cfg["logging"]["level"] = os.environ["LOG_LEVEL"]
    if "LOG_FILE" in os.environ:
        cfg["logging"]["file"] = os.environ["LOG_FILE"]

    # Default TLS paths follow the wildcard domain if not overridden
    if "CERT_PATH" not in os.environ:
        cfg["tls"]["cert_path"] = f"/etc/letsencrypt/live/{cfg['wildcard_domain']}/fullchain.pem"
        cfg["tls"]["key_path"] = f"/etc/letsencrypt/live/{cfg['wildcard_domain']}/privkey.pem"

    return cfg


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


def allocate_tcp_port(ctx: ServerContext, preferred: Optional[int] = None) -> Optional[int]:
    lo, hi = ctx.config["tcp"]["port_range"]
    if preferred is not None and lo <= preferred <= hi and preferred not in ctx.by_port:
        if _port_is_bindable(preferred, socket.SOCK_STREAM):
            return preferred
    candidates = [p for p in range(lo, hi + 1) if p not in ctx.by_port]
    random.shuffle(candidates)
    for p in candidates:
        if _port_is_bindable(p, socket.SOCK_STREAM):
            return p
    return None


def allocate_udp_port(ctx: ServerContext, preferred: Optional[int] = None) -> Optional[int]:
    lo, hi = ctx.config["udp"]["port_range"]
    if preferred is not None and lo <= preferred <= hi and preferred not in ctx.by_udp_port:
        if _port_is_bindable(preferred, socket.SOCK_DGRAM):
            return preferred
    candidates = [p for p in range(lo, hi + 1) if p not in ctx.by_udp_port]
    random.shuffle(candidates)
    for p in candidates:
        if _port_is_bindable(p, socket.SOCK_DGRAM):
            return p
    return None


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
    """Chunk `data` into <= MAX_FRAME_PAYLOAD frames, respecting flow control."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        await stream.send_window.wait()
        chunk = view[offset: offset + MAX_FRAME_PAYLOAD]
        chunk = chunk[: max(1, min(len(chunk), stream.send_window.available))] if stream.send_window.available > 0 else chunk
        await session.send_frame(FrameType.STREAM_DATA, stream.stream_id, bytes(chunk))
        stream.send_window.consume(len(chunk))
        stream.bytes_in += len(chunk)
        session.bytes_in += len(chunk)
        tunnel = session.tunnels.get(stream.tunnel_id)
        if tunnel:
            tunnel.bytes_in += len(chunk)
        offset += len(chunk)


async def pump_public_to_client(session: ClientSession, stream: StreamState,
                                 pub_reader: asyncio.StreamReader, ctx: ServerContext):
    """Read from the public-facing socket and forward as STREAM_DATA frames."""
    try:
        while True:
            await stream.send_window.wait()
            chunk = await pub_reader.read(MAX_FRAME_PAYLOAD)
            if not chunk:
                break
            await send_stream_data(session, stream, chunk)
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        if not stream.closed:
            stream.closed = True
            try:
                await session.send_frame(FrameType.STREAM_CLOSE, stream.stream_id)
            except Exception:
                pass
        session.streams.pop(stream.stream_id, None)
        try:
            stream.public_writer.close()
        except Exception:
            pass


async def open_new_stream(session: ClientSession, tunnel: TunnelInfo,
                           pub_reader: asyncio.StreamReader, pub_writer: asyncio.StreamWriter,
                           initial_data: bytes, proto: str, remote_addr: tuple, ctx: ServerContext):
    """Register a new multiplexed stream for an inbound public connection,
    tell the client about it, and start pumping data in both directions."""
    stream_id = session.alloc_stream_id()
    stream = StreamState(stream_id=stream_id, tunnel_id=tunnel.tunnel_id, public_writer=pub_writer)
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
            pass

    await pump_public_to_client(session, stream, pub_reader, ctx)


# =============================================================================
# HTTP(S) public listener
# =============================================================================

_HOST_RE = re.compile(rb"^Host:\s*([^\r\n]+)\r\n", re.IGNORECASE | re.MULTILINE)


def extract_host(header_bytes: bytes) -> Optional[str]:
    m = _HOST_RE.search(header_bytes)
    if not m:
        return None
    host = m.group(1).decode(errors="replace").strip()
    return host.split(":")[0].lower()


async def send_http_error(writer: asyncio.StreamWriter, status: int, reason: str):
    body = f"<html><body><h1>{status} {reason}</h1></body></html>".encode()
    resp = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\n"
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


async def send_server_response(writer: asyncio.StreamWriter, ctx: ServerContext, req_path: str):
    status, body, content_type = dashboard_mod.build_response(ctx, req_path)
    status_text = "OK" if status == 200 else "Not Found"
    resp = (
        f"HTTP/1.1 {status} {status_text}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Access-Control-Allow-Origin: *\r\n"
        f"Connection: close\r\n\r\n"
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


async def handle_public_http_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx: ServerContext, is_https: bool = False):
    peer = writer.get_extra_info("peername") or ("?", 0)
    try:
        header_bytes = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        writer.close()
        return

    # Extract the request path for redirect/dashboard handling
    try:
        request_line = header_bytes.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = request_line.split()
        req_path = parts[1] if len(parts) >= 2 else "/"
        method = parts[0] if parts else "GET"
    except Exception:
        req_path = "/"
        method = "GET"

    host = extract_host(header_bytes)
    if not host:
        await send_http_error(writer, 400, "Bad Request (missing Host header)")
        return

    # Only answer as proxy server/dashboard if request is targeting the root configured domain (or localhost/127.0.0.1).
    if is_root_domain(host, ctx.config["wildcard_domain"]):
        if not is_https and not ctx.config.get("http_only") and _load_ssl_context(ctx.config) is not None:
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
            writer.close()
            return
        await send_server_response(writer, ctx, req_path)
        return

    wildcard = ctx.config["wildcard_domain"].lower()
    if host.endswith("." + wildcard):
        subdomain = host[:-len("." + wildcard)]
    else:
        subdomain = host

    entry = ctx.by_subdomain.get(subdomain)
    if not entry:
        await send_http_error(writer, 404, "No tunnel registered for this host")
        return
    session, tunnel_id = entry
    if not session.alive:
        await send_http_error(writer, 502, "Tunnel client is offline")
        return
    tunnel = session.tunnels.get(tunnel_id)
    if not tunnel:
        await send_http_error(writer, 502, "Tunnel no longer registered")
        return

    await open_new_stream(session, tunnel, reader, writer, header_bytes, "http", peer, ctx)


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
    if not tunnel:
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
    so replies can be routed back to the correct address."""
    sid = tunnel.udp_streams.get(remote_addr)
    stream = session.streams.get(sid) if sid is not None else None

    if sid is None or stream is None:
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

    if data:
        try:
            await send_stream_data(session, stream, data)
        except Exception:
            pass


async def serve_udp_tunnel(session: ClientSession, tunnel: TunnelInfo, ctx: ServerContext,
                           bind_host: str, port: int):
    """Bind a UDP socket for a tunnel and pump datagrams to the client."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    try:
        sock.bind((bind_host, port))
    except OSError as e:
        log.error("UDP bind failed on %s:%s: %s", bind_host, port, e)
        return
    tunnel.udp_sock = sock
    try:
        while session.alive and tunnel.tunnel_id in session.tunnels:
            try:
                data, remote_addr = await loop.sock_recvfrom(sock, MAX_FRAME_PAYLOAD)
            except (OSError, ConnectionError):
                break
            await handle_udp_public_datagram(session, tunnel, data, remote_addr, ctx)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# =============================================================================
# Control-connection: tunnel lifecycle handlers
# =============================================================================

async def handle_tunnel_open(session: ClientSession, frame, ctx: ServerContext):
    try:
        req = json.loads(frame.payload.decode())
    except Exception:
        await session.send_frame(FrameType.ERROR, CONTROL_STREAM_ID,
                                  json.dumps({"error": "malformed TUNNEL_OPEN_REQUEST"}).encode())
        return

    tunnel_id = req.get("tunnel_id") or secrets.token_hex(8)
    ttype = req.get("type")

    if ttype not in ("http", "tcp", "udp"):
        resp = {"tunnel_id": tunnel_id, "status": "error", "error": "type must be 'http', 'tcp' or 'udp'"}
        await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())
        return

    if ttype == "http":
        requested = req.get("subdomain")
        subdomain = allocate_subdomain(ctx, requested)
        if subdomain is None:
            reason = "subdomain already in use" if requested else "could not allocate a subdomain"
            resp = {"tunnel_id": tunnel_id, "status": "error", "error": reason}
            await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())
            return

        tunnel = TunnelInfo(tunnel_id=tunnel_id, type="http", subdomain=subdomain)
        session.tunnels[tunnel_id] = tunnel
        ctx.by_subdomain[subdomain] = (session, tunnel_id)
        ctx.storage.save_tunnel(tunnel_id, session.client_id, "http", subdomain, None)

        scheme = "https" if not ctx.config.get("http_only") else "http"
        public_url = f"{scheme}://{subdomain}.{ctx.config['wildcard_domain']}"
        resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "http", "public_url": public_url}
        ctx.log_event(f"Client {session.client_id[:8]} opened HTTP tunnel {public_url}")

    elif ttype == "tcp":
        preferred = req.get("remote_port")
        port = allocate_tcp_port(ctx, preferred)
        if port is None:
            resp = {"tunnel_id": tunnel_id, "status": "error", "error": "no TCP ports available"}
            await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())
            return

        try:
            tcp_server = await asyncio.start_server(
                lambda r, w, p=port: handle_public_tcp_conn(r, w, ctx, p),
                ctx.config["tcp"].get("bind_host", "0.0.0.0"), port,
            )
        except OSError as e:
            resp = {"tunnel_id": tunnel_id, "status": "error", "error": f"bind failed: {e}"}
            await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())
            return

        tunnel = TunnelInfo(tunnel_id=tunnel_id, type="tcp", remote_port=port, tcp_server=tcp_server)
        session.tunnels[tunnel_id] = tunnel
        ctx.by_port[port] = (session, tunnel_id)
        ctx.storage.save_tunnel(tunnel_id, session.client_id, "tcp", None, port)

        resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "tcp",
                "remote_port": port, "public_host": ctx.config["wildcard_domain"]}
        ctx.log_event(f"Client {session.client_id[:8]} opened TCP tunnel on port {port}")

    else:  # udp
        preferred = req.get("remote_port")
        port = allocate_udp_port(ctx, preferred)
        if port is None:
            resp = {"tunnel_id": tunnel_id, "status": "error", "error": "no UDP ports available"}
            await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())
            return

        tunnel = TunnelInfo(tunnel_id=tunnel_id, type="udp", remote_port=port, udp_streams={})
        session.tunnels[tunnel_id] = tunnel
        ctx.by_udp_port[port] = (session, tunnel_id)
        ctx.storage.save_tunnel(tunnel_id, session.client_id, "udp", None, port)

        bind_host = ctx.config["udp"].get("bind_host", "0.0.0.0")
        asyncio.create_task(serve_udp_tunnel(session, tunnel, ctx, bind_host, port))

        resp = {"tunnel_id": tunnel_id, "status": "ok", "type": "udp",
                "remote_port": port, "public_host": ctx.config["wildcard_domain"]}
        ctx.log_event(f"Client {session.client_id[:8]} opened UDP tunnel on port {port}")

    await session.send_frame(FrameType.TUNNEL_OPEN_RESPONSE, CONTROL_STREAM_ID, json.dumps(resp).encode())


async def close_tunnel(session: ClientSession, tunnel_id: str, ctx: ServerContext):
    tunnel = session.tunnels.pop(tunnel_id, None)
    if not tunnel:
        return
    if tunnel.type == "http" and tunnel.subdomain:
        ctx.by_subdomain.pop(tunnel.subdomain, None)
    if tunnel.type == "tcp":
        if tunnel.remote_port is not None:
            ctx.by_port.pop(tunnel.remote_port, None)
        if tunnel.tcp_server is not None:
            tunnel.tcp_server.close()
            try:
                await tunnel.tcp_server.wait_closed()
            except Exception:
                pass
    if tunnel.type == "udp":
        if tunnel.remote_port is not None:
            ctx.by_udp_port.pop(tunnel.remote_port, None)
        if tunnel.udp_sock is not None:
            try:
                tunnel.udp_sock.close()
            except Exception:
                pass
        # Abort any in-flight UDP streams belonging to this tunnel.
        for sid, stream in list(session.streams.items()):
            if stream.tunnel_id == tunnel_id:
                session.streams.pop(sid, None)
    ctx.storage.delete_tunnel(tunnel_id)
    # Abort any in-flight streams belonging to this tunnel.
    for sid, stream in list(session.streams.items()):
        if stream.tunnel_id == tunnel_id:
            try:
                stream.public_writer.close()
            except Exception:
                pass
            session.streams.pop(sid, None)
    ctx.log_event(f"Tunnel {tunnel_id[:8]} closed")


async def handle_tunnel_close(session: ClientSession, frame, ctx: ServerContext):
    try:
        req = json.loads(frame.payload.decode())
        tunnel_id = req["tunnel_id"]
    except Exception:
        return
    await close_tunnel(session, tunnel_id, ctx)


# =============================================================================
# Control-connection: stream data / close / window-update handlers
# =============================================================================

async def handle_stream_data(session: ClientSession, frame, ctx: ServerContext):
    stream = session.streams.get(frame.stream_id)
    if stream is None or stream.closed:
        return  # stream already gone on our side; ignore stray data
    try:
        stream.public_writer.write(frame.payload)
        await stream.public_writer.drain()
    except (ConnectionError, OSError):
        stream.closed = True
        session.streams.pop(frame.stream_id, None)
        try:
            await session.send_frame(FrameType.STREAM_CLOSE, frame.stream_id)
        except Exception:
            pass
        return

    n = len(frame.payload)
    stream.bytes_out += n
    session.bytes_out += n
    tunnel = session.tunnels.get(stream.tunnel_id)
    if tunnel:
        tunnel.bytes_out += n

    stream.unacked_recv_bytes += n
    if stream.unacked_recv_bytes >= WINDOW_UPDATE_THRESHOLD:
        increment = stream.unacked_recv_bytes
        stream.unacked_recv_bytes = 0
        try:
            await session.send_frame(
                FrameType.STREAM_WINDOW_UPDATE, frame.stream_id, increment.to_bytes(4, "big")
            )
        except Exception:
            pass


async def handle_stream_close_from_client(session: ClientSession, frame, ctx: ServerContext):
    stream = session.streams.pop(frame.stream_id, None)
    if stream is None:
        return
    stream.closed = True
    if stream.udp_remote_addr is not None:
        tunnel = session.tunnels.get(stream.tunnel_id)
        if tunnel is not None and tunnel.udp_streams is not None:
            tunnel.udp_streams.pop(stream.udp_remote_addr, None)
    try:
        stream.public_writer.close()
    except Exception:
        pass


async def handle_udp_datagram_from_client(session: ClientSession, frame, ctx: ServerContext):
    """Client -> server: forward a datagram to the public UDP peer."""
    stream = session.streams.get(frame.stream_id)
    if stream is None or stream.udp_remote_addr is None:
        return  # unknown stream or not a UDP stream; ignore
    tunnel = session.tunnels.get(stream.tunnel_id)
    if tunnel is None or tunnel.udp_sock is None:
        return
    n = len(frame.payload)
    stream.bytes_out += n
    session.bytes_out += n
    if tunnel:
        tunnel.bytes_out += n
    try:
        await asyncio.get_running_loop().sock_sendto(tunnel.udp_sock, frame.payload, stream.udp_remote_addr)
    except (OSError, ConnectionError):
        pass


def handle_window_update(session: ClientSession, frame):
    stream = session.streams.get(frame.stream_id)
    if stream is None or len(frame.payload) != 4:
        return
    increment = int.from_bytes(frame.payload, "big")
    stream.send_window.replenish(increment)


# =============================================================================
# Control connection: accept / handshake / main dispatch loop
# =============================================================================

async def client_loop(session: ClientSession, ctx: ServerContext):
    while True:
        frame = await read_frame(session.reader)
        session.last_seen = time.time()

        if frame.type == FrameType.PING:
            await session.send_frame(FrameType.PONG, CONTROL_STREAM_ID)
        elif frame.type == FrameType.PONG:
            pass
        elif frame.type == FrameType.TUNNEL_OPEN_REQUEST:
            await handle_tunnel_open(session, frame, ctx)
        elif frame.type == FrameType.TUNNEL_CLOSE:
            await handle_tunnel_close(session, frame, ctx)
        elif frame.type == FrameType.STREAM_DATA:
            await handle_stream_data(session, frame, ctx)
        elif frame.type == FrameType.STREAM_CLOSE:
            await handle_stream_close_from_client(session, frame, ctx)
        elif frame.type == FrameType.STREAM_WINDOW_UPDATE:
            handle_window_update(session, frame)
        elif frame.type == FrameType.UDP_DATAGRAM:
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
        if time.time() - session.last_seen > timeout:
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


async def cleanup_client(session: ClientSession, ctx: ServerContext):
    session.alive = False
    for tunnel_id in list(session.tunnels.keys()):
        await close_tunnel(session, tunnel_id, ctx)
    for stream in list(session.streams.values()):
        try:
            stream.public_writer.close()
        except Exception:
            pass
    session.streams.clear()
    sessions = ctx.clients.get(session.client_id, set())
    sessions.discard(session)
    if not sessions:
        ctx.clients.pop(session.client_id, None)
    try:
        session.writer.close()
    except Exception:
        pass
    ctx.log_event(f"Client {session.client_id[:8]} disconnected")
    log.info("Client %s disconnected and cleaned up", session.client_id[:8])


async def handle_control_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx: ServerContext):
    addr = writer.get_extra_info("peername") or ("?", 0)
    try:
        frame = await asyncio.wait_for(read_frame(reader), timeout=10)
    except Exception:
        writer.close()
        return

    if frame.type != FrameType.HELLO:
        try:
            writer.write(encode_frame(FrameType.HELLO_FAIL, CONTROL_STREAM_ID,
                                       json.dumps({"error": "expected HELLO"}).encode()))
            await writer.drain()
        except Exception:
            pass
        writer.close()
        return

    ok, client_id, reason = verify_hello_payload(frame.payload, ctx.config["shared_secret"], ctx.seen_nonces)
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

    # If this client_id already has live sessions, keep them (support multiple connections per client_id)
    existing_sessions = ctx.clients.get(client_id, set())

    session = ClientSession(client_id, reader, writer)
    existing_sessions.add(session)
    ctx.clients[client_id] = existing_sessions
    ctx.storage.upsert_client(client_id)

    resp = json.dumps({
        "client_id": client_id,
        "heartbeat_interval": ctx.config["heartbeat_interval_seconds"],
        "server_version": 1,
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

    hb_task = asyncio.create_task(heartbeat_loop(session, ctx))
    try:
        await client_loop(session, ctx)
    except (asyncio.IncompleteReadError, ConnectionError, ProtocolError, OSError) as e:
        log.info("Client %s connection ended: %s", client_id[:8], e)
    except Exception:
        log.exception("Unexpected error in client loop for %s", client_id[:8])
    finally:
        hb_task.cancel()
        await cleanup_client(session, ctx)


# =============================================================================
# Background maintenance tasks
# =============================================================================

async def nonce_and_stale_cleanup_loop(ctx: ServerContext):
    from protocol import HELLO_TIMESTAMP_SKEW_SECONDS
    while True:
        await asyncio.sleep(60)
        cutoff = time.time() - HELLO_TIMESTAMP_SKEW_SECONDS - 5
        stale_keys = [k for k, ts in ctx.seen_nonces.items() if ts < cutoff]
        for k in stale_keys:
            ctx.seen_nonces.pop(k, None)
        ctx.storage.purge_stale(ctx.config["stale_grace_seconds"])


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


async def cert_reload_loop(ctx: ServerContext, ssl_ctx: ssl.SSLContext):
    """Reload TLS certs in place when certbot renews them."""
    tls = ctx.config["tls"]
    cert_path, key_path = tls.get("cert_path"), tls.get("key_path")
    last_mtime = -1.0
    while True:
        await asyncio.sleep(3600)
        try:
            m = max(os.path.getmtime(cert_path), os.path.getmtime(key_path))
        except OSError:
            continue
        if m != last_mtime:
            try:
                ssl_ctx.load_cert_chain(cert_path, key_path)
                last_mtime = m
                log.info("TLS certificates reloaded (renewal)")
            except (ssl.SSLError, OSError) as e:
                log.warning("TLS cert reload failed: %s", e)


async def run():
    config = load_config()

    # Create database directory if it doesn't exist
    db_path = config["storage"]["db_path"]
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    ctx = ServerContext(config)
    setup_logging(ctx)

    if config["shared_secret"] == "CHANGE_ME":
        log.warning("shared_secret is still the default placeholder -- set SHARED_SECRET environment variable!")

    ssl_ctx = _load_ssl_context(config)

    control_cfg = config["control"]
    control_server = await asyncio.start_server(
        lambda r, w: handle_control_connection(r, w, ctx),
        control_cfg["host"], control_cfg["port"],
    )
    log.info("Control channel listening on %s:%s (tls=%s)",
              control_cfg["host"], control_cfg["port"], control_cfg.get("tls", False))

    http_cfg = config["http"]
    http_server = await asyncio.start_server(
        lambda r, w: handle_public_http_conn(r, w, ctx, is_https=False), http_cfg["host"], http_cfg["port"]
    )
    log.info("Public HTTP listening on %s:%s", http_cfg["host"], http_cfg["port"])

    tasks = [
        asyncio.create_task(control_server.serve_forever()),
        asyncio.create_task(http_server.serve_forever()),
        asyncio.create_task(nonce_and_stale_cleanup_loop(ctx)),
    ]

    https_server = None
    if ssl_ctx is not None:
        https_cfg = config["https"]
        https_server = await asyncio.start_server(
            lambda r, w: handle_public_http_conn(r, w, ctx, is_https=True),
            https_cfg["host"], https_cfg["port"], ssl=ssl_ctx,
        )
        log.info("Public HTTPS listening on %s:%s", https_cfg["host"], https_cfg["port"])
        tasks.append(asyncio.create_task(https_server.serve_forever()))
        tasks.append(asyncio.create_task(cert_reload_loop(ctx, ssl_ctx)))
        log.info("Dashboard available at https://%s/ (apex domain only)",
                 config["wildcard_domain"])
    else:
        log.info("Dashboard available at http://%s:%s (HTTP-only mode)",
                 config["dashboard"]["host"], config["dashboard"]["port"])
        tasks.append(asyncio.create_task(dashboard_mod.serve_dashboard(ctx)))

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

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

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, OSError, AttributeError):
            # ValueError: not called from the main thread.
            # AttributeError: signal doesn't exist on this platform
            #   (defensive; SIGINT/SIGTERM both exist on Windows and POSIX).
            pass

    await stop_event.wait()

    log.info("Shutting down...")
    for t in tasks:
        t.cancel()
    for sessions in ctx.clients.values():
        for session in sessions:
            try:
                session.writer.close()
            except Exception:
                pass
    control_server.close()
    http_server.close()
    if https_server is not None:
        https_server.close()
    await asyncio.gather(*tasks, return_exceptions=True)
    ctx.storage.close()
    log.info("Shutdown complete")


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        # RuntimeErrors raised during startup (missing certbot, disabled
        # auto_provision with no cert present, etc.) are deliberately
        # written to be read directly by the operator -- show just the
        # message, not a full traceback, so the actionable part isn't
        # buried under stack frames.
        print(f"\nStartup failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
