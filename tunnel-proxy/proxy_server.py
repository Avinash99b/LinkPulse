#!/usr/bin/env python3
"""
proxy_server.py -- Self-hosted tunneling proxy server (ngrok-alike).

The client talks to the server over a single WebSocket connection
(RFC 6455, stdlib implementation in ws.py) which replaces the old custom
binary TCP protocol. One authenticated, multiplexed WebSocket carries all
control-plane traffic AND all tunneled stream data:

    public HTTP(s)/TCP traffic  ->  proxy_server opens a stream on the
                                    client's WebSocket connection; stream
                                    data rides binary WebSocket messages.

Public exposure is a single HTTP port (the WebSocket endpoint shares it):
  * GET /ws          -> WebSocket control/data endpoint (for clients)
  * GET /health      -> health check
  * other requests   -> Host-header-routed HTTP tunnels
TCP tunnels still allocate their own public TCP port (or a preferred one),
one listener per registered tunnel, and any client may register multiple
TCP (and multiple HTTP) tunnels concurrently.

Run:
    python3 proxy_server.py

Configuration via environment variables:
    SHARED_SECRET        - Required, shared secret for client authentication
    WILDCARD_DOMAIN      - Required, wildcard domain for tunnels
    HTTP_HOST            - Public HTTP host (default: 0.0.0.0)
    HTTP_PORT            - Public HTTP port (default: 8080)
    WS_PATH              - WebSocket endpoint path (default: /ws)
    TCP_PORT_MIN         - TCP port range minimum (default: 20000)
    TCP_PORT_MAX         - TCP port range maximum (default: 20100)
    DASHBOARD_HOST       - Dashboard host (default: 0.0.0.0)
    DASHBOARD_PORT       - Dashboard port (default: 8081)
    HTTP_ONLY            - If true, use http:// URLs (default: true)
    HEARTBEAT_INTERVAL   - Heartbeat (WS ping) interval in seconds (default: 20)
    HEARTBEAT_TIMEOUT    - Heartbeat timeout in seconds (default: 60)
    STALE_GRACE_SECONDS  - Stale client cleanup grace period (default: 300)
    DB_PATH              - SQLite database path (default: /data/tunnel_proxy.db)
    LOG_LEVEL            - Logging level (default: INFO)
    LOG_FILE             - Log file path (default: /var/log/tunnel-proxy/tunnel_proxy.log)

See README.md for the full architecture / message protocol write-up.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import secrets
import signal
import socket
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from protocol import (
    DEFAULT_WS_PATH,
    HELLO_TIMESTAMP_SKEW_SECONDS,
    INITIAL_WINDOW,
    MAX_FRAME_PAYLOAD,
    SERVER_VERSION,
    encode_stream_data,
    new_tunnel_id,
    parse_stream_data,
    verify_hello_payload,
)
from ws import (
    CLOSE_ABORTED,
    CLOSE_PROTOCOL_ERROR,
    WebSocketConnection,
    WebSocketProtocolError,
    build_accept,
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
    sender must await() until a window_update (replenish()) arrives from the
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
    one raw TCP connection) riding on a client's WebSocket control pipe."""
    stream_id: int
    tunnel_id: str
    public_writer: asyncio.StreamWriter
    send_window: FlowWindow = field(default_factory=FlowWindow)
    unacked_recv_bytes: int = 0
    closed: bool = False
    bytes_in: int = 0   # public -> client
    bytes_out: int = 0  # client -> public


@dataclass
class TunnelInfo:
    tunnel_id: str
    type: str  # "http" | "tcp"
    subdomain: Optional[str] = None
    remote_port: Optional[int] = None
    tcp_server: Optional[asyncio.base_events.Server] = None
    connection_count: int = 0
    bytes_in: int = 0
    bytes_out: int = 0


class ClientSession:
    def __init__(self, client_id: str, ws: WebSocketConnection):
        self.client_id = client_id
        self.ws = ws
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.tunnels: dict[str, TunnelInfo] = {}
        self.streams: dict[int, StreamState] = {}
        self._next_stream_id = 1
        self.alive = True
        self.bytes_in = 0    # public -> client, aggregate
        self.bytes_out = 0   # client -> public, aggregate

    def alloc_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id = (self._next_stream_id + 1) & 0xFFFFFFFF
        if self._next_stream_id == 0:
            self._next_stream_id = 1
        return sid

    async def send_json(self, msg: dict):
        await self.ws.send_text(json.dumps(msg, ensure_ascii=True))

    async def send_stream_binary(self, stream_id: int, payload: bytes):
        await self.ws.send_binary(encode_stream_data(stream_id, payload))


# =============================================================================
# Server context (holds all shared state)
# =============================================================================


class ServerContext:
    def __init__(self, config: dict):
        self.config = config
        self.storage = Storage(config["storage"]["db_path"])
        self.clients: dict[str, set][ClientSession] = {}
        self.by_subdomain: dict[str, tuple[ClientSession, str]] = {}
        self.by_port: dict[int, tuple[ClientSession, str]] = {}
        self.seen_nonces: dict[bytes, int] = {}
        self.start_time = time.time()
        self.recent_logs: deque[str] = deque(maxlen=200)
        self.session_tasks: set = set()  # in-flight WS session handlers

    def log_event(self, msg: str):
        self.recent_logs.append("[%s] %s" % (time.strftime("%H:%M:%S"), msg))


# =============================================================================
# Config
# =============================================================================

DEFAULT_CONFIG = {
    "shared_secret": "CHANGE_ME",
    "http": {"host": "0.0.0.0", "port": 8080},
    "wildcard_domain": "forwarding.example.com",
    "tcp": {"port_range": [20000, 20100]},
    "dashboard": {"host": "0.0.0.0", "port": 8081},
    "http_only": True,
    "heartbeat_interval_seconds": 20,
    "heartbeat_timeout_seconds": 60,
    "stale_grace_seconds": 300,
    "ws_path": DEFAULT_WS_PATH,
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
    if "HTTP_HOST" in os.environ:
        cfg["http"]["host"] = os.environ["HTTP_HOST"]
    if "HTTP_PORT" in os.environ:
        cfg["http"]["port"] = int(os.environ["HTTP_PORT"])
    if "WS_PATH" in os.environ:
        cfg["ws_path"] = os.environ["WS_PATH"]
    if "TCP_PORT_MIN" in os.environ:
        cfg["tcp"]["port_range"][0] = int(os.environ["TCP_PORT_MIN"])
    if "TCP_PORT_MAX" in os.environ:
        cfg["tcp"]["port_range"][1] = int(os.environ["TCP_PORT_MAX"])
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


def _port_is_bindable(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform == "win32":
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
        if _port_is_bindable(preferred):
            return preferred
    candidates = [p for p in range(lo, hi + 1) if p not in ctx.by_port]
    random.shuffle(candidates)
    for p in candidates:
        if _port_is_bindable(p):
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
# Stream data plumbing (public socket <-> WebSocket control pipe)
# =============================================================================


async def send_stream_data(session: ClientSession, stream: StreamState, data: bytes):
    """Chunk `data` into <= MAX_FRAME_PAYLOAD binary messages, respecting the
    per-stream send window."""
    view = memoryview(data)
    offset = 0
    total = len(view)
    while offset < total:
        await stream.send_window.wait()
        avail = stream.send_window.available
        chunk_len = min(total - offset, MAX_FRAME_PAYLOAD)
        if avail > 0:
            chunk_len = min(chunk_len, avail)
        if chunk_len <= 0:
            chunk_len = 1
        chunk = bytes(view[offset:offset + chunk_len])
        stream.send_window.consume(len(chunk))
        await session.send_stream_binary(stream.stream_id, chunk)
        stream.bytes_in += len(chunk)
        session.bytes_in += len(chunk)
        tunnel = session.tunnels.get(stream.tunnel_id)
        if tunnel:
            tunnel.bytes_in += len(chunk)
        offset += len(chunk)


async def pump_public_to_client(session: ClientSession, stream: StreamState,
                                pub_reader: asyncio.StreamReader, ctx: ServerContext):
    """Read from the public-facing socket and forward as binary messages."""
    try:
        while True:
            chunk = await pub_reader.read(MAX_FRAME_PAYLOAD)
            if not chunk:
                break
            await send_stream_data(session, stream, chunk)
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    except asyncio.CancelledError:
        pass
    finally:
        if not stream.closed:
            stream.closed = True
            try:
                await session.send_json({"type": "close_stream", "stream_id": stream.stream_id})
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
    tell the client about it (stream_open), then start pumping data."""
    stream_id = session.alloc_stream_id()
    stream = StreamState(stream_id=stream_id, tunnel_id=tunnel.tunnel_id, public_writer=pub_writer)
    session.streams[stream_id] = stream
    tunnel.connection_count += 1
    log.debug("open stream=%s tunnel=%s proto=%s", stream_id, tunnel.tunnel_id[:8], proto)

    try:
        await session.send_json({
            "type": "stream_open",
            "stream_id": stream_id,
            "tunnel_id": tunnel.tunnel_id,
            "proto": proto,
            "remote_addr": "%s:%s" % (remote_addr[0], remote_addr[1]),
        })
    except Exception:
        session.streams.pop(stream_id, None)
        tunnel.connection_count -= 1
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

_HEALTH_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n"
    b"Connection: close\r\n\r\nhealthy\n"
)


async def send_http_error(writer, status: int, reason: str):
    body = ("<html><body><h1>%d %s</h1></body></html>" % (status, reason)).encode()
    resp = (
        "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n" % (status, reason, len(body))
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


def _parse_request_head(head_block: bytes):
    """Parse an HTTP request head into (method, path, headers_dict)."""
    lines = head_block.decode("latin-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) < 2:
        return None, None, {}
    method, path = parts[0], parts[1]
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return method, path, headers


async def handle_public_http_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                  ctx: ServerContext):
    peer = writer.get_extra_info("peername") or ("?", 0)
    try:
        head_block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        writer.close()
        return

    method, path, headers = _parse_request_head(head_block)
    if method is None:
        writer.close()
        return

    # WebSocket control-plane endpoint.
    if method == "GET" and path.rstrip("/") == ctx.config["ws_path"].rstrip("/"):
        upgrade = (headers.get("upgrade") or "").lower()
        key = headers.get("sec-websocket-key")
        if upgrade == "websocket" and key:
            accept = build_accept(key)
            resp = (
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            try:
                writer.write(resp)
                await writer.drain()
            except Exception:
                writer.close()
                return
            conn = WebSocketConnection(reader, writer, is_server=True)
            task = asyncio.ensure_future(handle_ws_session(conn, peer, ctx))
            ctx.session_tasks.add(task)
            task.add_done_callback(ctx.session_tasks.discard)
            return
        else:
            await send_http_error(writer, 400, "Bad Request (invalid WebSocket upgrade)")
            return

    # Health check endpoint.
    if path == "/health" or path.startswith("/health"):
        try:
            writer.write(_HEALTH_RESPONSE)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
        return

    # Host-based HTTP tunnel routing.
    host_hdr = headers.get("host")
    if not host_hdr:
        await send_http_error(writer, 400, "Bad Request (missing Host header)")
        return
    host = host_hdr.split(":")[0].lower()
    wildcard = ctx.config["wildcard_domain"]
    if host.endswith(wildcard):
        subdomain = host[: -(len(wildcard) + 1)] if host != wildcard else host
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

    await open_new_stream(session, tunnel, reader, writer, head_block, "http", peer, ctx)


# =============================================================================
# TCP public listener (one per registered TCP tunnel)
# =============================================================================


async def handle_public_tcp_conn(reader, writer, ctx: ServerContext, port: int):
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
# Control: tunnel lifecycle handlers (JSON control messages)
# =============================================================================


async def handle_tunnel_open(session: ClientSession, msg: dict, ctx: ServerContext):
    tunnel_id = msg.get("tunnel_id") or new_tunnel_id()
    ttype = msg.get("kind")

    async def respond(**kw):
        payload = {"type": "open_tunnel_response", "tunnel_id": tunnel_id}
        payload.update(kw)
        await session.send_json(payload)

    if ttype not in ("http", "tcp"):
        await respond(status="error", error="type must be 'http' or 'tcp'")
        return

    if ttype == "http":
        requested = msg.get("subdomain")
        subdomain = allocate_subdomain(ctx, requested)
        if subdomain is None:
            reason = "subdomain already in use" if requested else "could not allocate a subdomain"
            await respond(status="error", error=reason)
            return

        tunnel = TunnelInfo(tunnel_id=tunnel_id, type="http", subdomain=subdomain)
        session.tunnels[tunnel_id] = tunnel
        ctx.by_subdomain[subdomain] = (session, tunnel_id)
        ctx.storage.save_tunnel(tunnel_id, session.client_id, "http", subdomain, None)

        public_url = "http://%s.%s" % (subdomain, ctx.config["wildcard_domain"])
        await respond(status="ok", kind="http", public_url=public_url)
        ctx.log_event("Client %s opened HTTP tunnel %s" % (session.client_id[:8], public_url))
        return

    # tcp
    preferred = msg.get("remote_port")
    if preferred is not None:
        try:
            preferred = int(preferred)
        except (TypeError, ValueError):
            preferred = None
    port = allocate_tcp_port(ctx, preferred)
    if port is None:
        await respond(status="error", error="no TCP ports available")
        return

    try:
        tcp_server = await asyncio.start_server(
            lambda r, w, p=port: handle_public_tcp_conn(r, w, ctx, p),
            ctx.config["tcp"].get("bind_host", "0.0.0.0"), port,
        )
    except OSError as e:
        await respond(status="error", error="bind failed: %s" % e)
        return

    tunnel = TunnelInfo(tunnel_id=tunnel_id, type="tcp", remote_port=port, tcp_server=tcp_server)
    session.tunnels[tunnel_id] = tunnel
    ctx.by_port[port] = (session, tunnel_id)
    ctx.storage.save_tunnel(tunnel_id, session.client_id, "tcp", None, port)

    await respond(status="ok", kind="tcp", remote_port=port,
                  public_url="tcp://%s:%s" % (ctx.config["wildcard_domain"], port))
    ctx.log_event("Client session opened TCP tunnel on port %d" % port)


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
    ctx.storage.delete_tunnel(tunnel_id)
    # Abort any in-flight streams belonging to this tunnel.
    for sid, stream in list(session.streams.items()):
        if stream.tunnel_id == tunnel_id:
            try:
                stream.public_writer.close()
            except Exception:
                pass
            session.streams.pop(sid, None)
    ctx.log_event("Tunnel %s closed" % tunnel_id[:8])


async def handle_tunnel_close(session: ClientSession, msg: dict, ctx: ServerContext):
    tunnel_id = msg.get("tunnel_id")
    if tunnel_id:
        await close_tunnel(session, tunnel_id, ctx)


# =============================================================================
# Control: stream data / close / window-update handlers
# =============================================================================


async def handle_stream_data(session: ClientSession, payload: bytes, ctx: ServerContext):
    stream_id, data = parse_stream_data(payload)
    if stream_id is None:
        return  # malformed: ignore
    stream = session.streams.get(stream_id)
    if stream is None or stream.closed:
        log.debug("stream %s gone; drop %d bytes", stream_id, len(data))
        return  # stream already gone on our side; ignore stray data
    try:
        stream.public_writer.write(data)
        await stream.public_writer.drain()
    except (ConnectionError, OSError):
        stream.closed = True
        session.streams.pop(stream_id, None)
        try:
            await session.send_json({"type": "close_stream", "stream_id": stream_id})
        except Exception:
            pass
        return

    n = len(data)
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
            await session.send_json({"type": "window_update", "stream_id": stream_id,
                                     "increment": increment})
        except Exception:
            pass


async def handle_close_stream_from_client(session: ClientSession, msg: dict, ctx: ServerContext):
    stream = session.streams.pop(msg.get("stream_id"), None)
    if stream is None:
        return
    stream.closed = True
    try:
        stream.public_writer.close()
    except Exception:
        pass


async def handle_window_update(session: ClientSession, msg: dict, ctx: ServerContext):
    stream = session.streams.get(msg.get("stream_id"))
    if stream is None:
        return
    try:
        increment = int(msg.get("increment", 0))
    except (TypeError, ValueError):
        return
    if increment > 0:
        stream.send_window.replenish(increment)


# =============================================================================
# Control connection: WebSocket accept / auth / main dispatch loop
# =============================================================================


async def _wait_for_hello(ws: WebSocketConnection) -> dict:
    """Wait for the first control message (must be a text `hello`)."""
    while True:
        kind, payload = await asyncio.wait_for(ws.recv(), timeout=10)
        if kind in ("text", "binary"):
            try:
                msg = json.loads(payload) if isinstance(payload, str) else {}
            except (ValueError, TypeError):
                raise WebSocketProtocolError("hello must be a JSON object")
            return msg
        if kind in ("close", "error"):
            raise WebSocketProtocolError("connection closed before hello")


async def handle_ws_session(ws: WebSocketConnection, addr: tuple, ctx: ServerContext):
    try:
        hello = await _wait_for_hello(ws)
    except (asyncio.TimeoutError, WebSocketProtocolError, ConnectionError, OSError):
        try:
            await ws.close(CLOSE_PROTOCOL_ERROR)
        except Exception:
            pass
        return

    if str(hello.get("type")) != "hello":
        try:
            await ws.send_text(json.dumps({"type": "hello_fail",
                                           "message": "expected hello message"}))
            await ws.close(CLOSE_PROTOCOL_ERROR)
        except Exception:
            pass
        return

    sign_hex = hello.get("sign")
    if not isinstance(sign_hex, str):
        try:
            await ws.send_text(json.dumps({"type": "hello_fail",
                                           "message": "missing sign"}))
            await ws.close(CLOSE_PROTOCOL_ERROR)
        except Exception:
            pass
        return
    try:
        sign = bytes.fromhex(sign_hex)
    except ValueError:
        try:
            await ws.send_text(json.dumps({"type": "hello_fail",
                                           "message": "malformed sign"}))
            await ws.close(CLOSE_PROTOCOL_ERROR)
        except Exception:
            pass
        return

    ok, client_id, reason = verify_hello_payload(sign, ctx.config["shared_secret"],
                                                 ctx.seen_nonces)
    if not ok:
        log.warning("Rejected WS HELLO from %s: %s", addr[0], reason)
        try:
            await ws.send_text(json.dumps({"type": "hello_fail", "message": reason}))
            await ws.close(CLOSE_PROTOCOL_ERROR)
        except Exception:
            pass
        return

    # Client may hold multiple live sessions (per client_id).
    existing = ctx.clients.get(client_id, set())
    session = ClientSession(client_id, ws)
    existing.add(session)
    ctx.clients[client_id] = existing
    ctx.storage.upsert_client(client_id)

    try:
        await session.send_json({
            "type": "hello_ok",
            "client_id": client_id,
            "heartbeat_interval": ctx.config["heartbeat_interval_seconds"],
            "server_version": SERVER_VERSION,
        })
    except Exception:
        existing.discard(session)
        if not existing:
            ctx.clients.pop(client_id, None)
        return

    ctx.log_event("Client %s connected from %s" % (client_id[:8], addr[0]))
    log.info("Client %s authenticated from %s", client_id[:8], addr[0])

    hb_task = asyncio.create_task(heartbeat_loop(session, ctx))
    try:
        await client_loop(session, ctx)
    except (asyncio.TimeoutError, ConnectionError, WebSocketProtocolError, OSError) as e:
        log.info("Client %s connection ended: %s", client_id[:8], type(e).__name__)
    except asyncio.CancelledError:
        pass
    except Exception:
        log.exception("Unexpected error in client loop for %s", client_id[:8])
    finally:
        hb_task.cancel()
        await cleanup_client(session, ctx)


async def client_loop(session: ClientSession, ctx: ServerContext):
    """Main message dispatch loop for an authenticated WebSocket session."""
    timeout = ctx.config["heartbeat_timeout_seconds"]
    while True:
        try:
            kind, payload = await asyncio.wait_for(session.ws.recv(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("Client %s heartbeat timeout; closing connection",
                        session.client_id[:8])
            break
        session.last_seen = time.time()

        if kind == "close":
            break
        if kind == "error":
            log.warning("Client %s websocket error: %s", session.client_id[:8], payload)
            break
        if kind in ("ping", "pong"):
            continue
        if kind == "binary":
            try:
                await handle_stream_data(session, payload, ctx)
            except (ConnectionError, OSError):
                break
            continue

        # text control messages
        try:
            msg = json.loads(payload)
        except (ValueError, TypeError):
            log.warning("Client %s sent invalid JSON", session.client_id[:8])
            continue
        if not isinstance(msg, dict):
            continue
        mtype = msg.get("type")
        if mtype == "open_tunnel":
            await handle_tunnel_open(session, msg, ctx)
        elif mtype == "close_tunnel":
            await handle_tunnel_close(session, msg, ctx)
        elif mtype == "close_stream":
            await handle_close_stream_from_client(session, msg, ctx)
        elif mtype == "window_update":
            await handle_window_update(session, msg, ctx)
        elif mtype == "error":
            log.warning("Client %s reported error: %s", session.client_id[:8],
                        str(msg.get("message"))[:200])
        elif mtype == "heartbeat":
            await session.send_json({"type": "heartbeat_ack"})
        else:
            log.warning("Unknown message type %r from client %s", mtype,
                        session.client_id[:8])


async def heartbeat_loop(session: ClientSession, ctx: ServerContext):
    interval = ctx.config["heartbeat_interval_seconds"]
    timeout = ctx.config["heartbeat_timeout_seconds"]
    while session.alive:
        await asyncio.sleep(interval)
        if time.time() - session.last_seen > timeout:
            log.warning("Client %s heartbeat timeout; closing connection",
                        session.client_id[:8])
            try:
                await session.ws.close(CLOSE_ABORTED)
            except Exception:
                pass
            return
        try:
            await session.ws.ping()
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
        await session.ws.close(CLOSE_ABORTED)
    except Exception:
        pass
    ctx.log_event("Client %s disconnected" % session.client_id[:8])
    log.info("Client %s disconnected and cleaned up", session.client_id[:8])


async def close_all_sessions(ctx: ServerContext):
    """Gracefully tear down every live WebSocket session and wait for the
    per-session cleanup (which touches SQLite) to finish."""
    for sessions in ctx.clients.values():
        for session in sessions:
            try:
                await session.ws.close(CLOSE_ABORTED)
            except Exception:
                pass
    if ctx.session_tasks:
        await asyncio.gather(*list(ctx.session_tasks), return_exceptions=True)


# =============================================================================
# Background maintenance tasks
# =============================================================================


async def nonce_and_stale_cleanup_loop(ctx: ServerContext):
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
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                            "%Y-%m-%d %H:%M:%S")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    if cfg.get("file"):
        log_dir = os.path.dirname(cfg["file"])
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fileh = logging.FileHandler(cfg["file"])
        fileh.setFormatter(fmt)
        root.addHandler(fileh)

    dq = DequeLogHandler(ctx)
    dq.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    root.addHandler(dq)


async def start_services(ctx: ServerContext):
    """Start all listener backends. Returns (tasks, http_server).

    The single http_server entry point serves HTTP tunnels, /health and the
    WebSocket control-plane endpoint (ctx.config["ws_path"]). The dashboard
    listens on its own port; TCP tunnels bind their own allocated ports.
    """
    http_cfg = ctx.config["http"]
    http_server = await asyncio.start_server(
        lambda r, w: handle_public_http_conn(r, w, ctx), http_cfg["host"], http_cfg["port"]
    )
    log.info("Public HTTP + WebSocket (%s) listening on %s:%s",
             ctx.config["ws_path"], http_cfg["host"], http_cfg["port"])

    tasks = [
        asyncio.create_task(http_server.serve_forever()),
        asyncio.create_task(dashboard_mod.serve_dashboard(ctx)),
        asyncio.create_task(nonce_and_stale_cleanup_loop(ctx)),
    ]
    return tasks, http_server


async def run():
    config = load_config()

    db_path = config["storage"]["db_path"]
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    ctx = ServerContext(config)
    setup_logging(ctx)

    if config["shared_secret"] == "CHANGE_ME":
        log.warning("shared_secret is still the default placeholder -- "
                    "set SHARED_SECRET environment variable!")

    tasks, http_server = await start_services(ctx)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_stop():
        log.info("Shutdown signal received")
        stop_event.set()

    def _signal_handler(signum, frame):
        try:
            loop.call_soon_threadsafe(_request_stop)
        except RuntimeError:
            pass

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, OSError, AttributeError):
            pass

    await stop_event.wait()

    log.info("Shutting down...")
    for t in tasks:
        t.cancel()
    http_server.close()
    await close_all_sessions(ctx)
    await asyncio.gather(*tasks, return_exceptions=True)
    ctx.storage.close()
    log.info("Shutdown complete")


def main():
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        print("\nStartup failed: %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()