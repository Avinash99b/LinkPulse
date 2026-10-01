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
    my_proxy tcp 22
    my_proxy tcp 25565
    my_proxy start tunnels.json

Run `my_proxy --help` / `my_proxy http --help` etc. for all options.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

# =============================================================================
# PROTOCOL -- verbatim reproduction of the server's protocol.py.
#
# This section MUST stay byte-for-byte compatible with the server. Do not
# "improve" or reinterpret anything here; it defines the wire format the
# server already speaks.
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


def encode_frame(frame_type: int, stream_id: int, payload: bytes = b"", version: int = PROTO_VERSION) -> bytes:
    if len(payload) > MAX_ALLOWED_LENGTH:
        raise ValueError("payload exceeds MAX_ALLOWED_LENGTH")
    header = struct.pack(_HEADER_FMT, PROTO_MAGIC, version, int(frame_type), stream_id, len(payload))
    return header + payload


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    header = await reader.readexactly(HEADER_LEN)
    magic, version, ftype, stream_id, length = struct.unpack(_HEADER_FMT, header)
    if magic != PROTO_MAGIC:
        raise ProtocolError(f"bad magic bytes: {magic!r}")
    if length > MAX_ALLOWED_LENGTH:
        raise ProtocolError(f"frame length {length} exceeds maximum {MAX_ALLOWED_LENGTH}")
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


@dataclasses.dataclass
class TunnelRuntime:
    spec: TunnelSpec
    status: str = "pending"     # pending | active | error
    public_url: Optional[str] = None
    error: Optional[str] = None
    connection_count: int = 0
    bytes_in: int = 0    # local backend -> public internet
    bytes_out: int = 0   # public internet -> local backend
    latencies_ms: deque = dataclasses.field(default_factory=lambda: deque(maxlen=50))

    def avg_latency_ms(self) -> Optional[float]:
        if not self.latencies_ms:
            return None
        return sum(self.latencies_ms) / len(self.latencies_ms)


@dataclasses.dataclass
class ClientStream:
    stream_id: int
    tunnel_id: str
    local_reader: asyncio.StreamReader
    local_writer: asyncio.StreamWriter
    udp_transport: object = None   # asyncio.DatagramTransport for udp streams
    send_window: FlowWindow = dataclasses.field(default_factory=FlowWindow)
    unacked_recv_bytes: int = 0
    closed: bool = False
    opened_at: float = dataclasses.field(default_factory=time.time)
    first_byte_recorded: bool = False


@dataclasses.dataclass
class PendingStream:
    """A stream the server has opened (STREAM_OPEN received) but whose
    local backend connection hasn't finished establishing yet. STREAM_DATA
    frames can legitimately arrive in this window (e.g. the server sends
    the buffered HTTP request bytes right after STREAM_OPEN) -- they must
    be queued here rather than dropped, then replayed once the local
    connection is ready."""
    tunnel_id: str
    buffered: list = dataclasses.field(default_factory=list)
    closed: bool = False


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
                 log_file_path: Optional[str] = None):
        self.specs = specs
        self.server_host = server_host
        self.server_port = server_port
        self.secret = secret
        self.grace_time = grace_time
        self.state_file = state_file
        self.log = log
        self.recent_logs = recent_logs
        self.mode = mode
        self.target_str = target_str
        self.dashboard_addr = dashboard_addr
        self.log_file_path = log_file_path

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._write_lock = asyncio.Lock()

        if client_id:
            self.client_id = client_id
            self._client_id_bytes = bytes.fromhex(client_id)
        else:
            self.client_id = None
            self._client_id_bytes = self._load_client_id()
            if self._client_id_bytes != NULL_CLIENT_ID:
                self.client_id = self._client_id_bytes.hex()

        self.tunnels: dict[str, TunnelRuntime] = {t.tunnel_id: TunnelRuntime(spec=t) for t in specs}
        self.streams: dict[int, ClientStream] = {}
        self.pending_streams: dict[int, PendingStream] = {}

        self.process_start_time = time.time()
        self.connected_since: Optional[float] = None
        self.status = "connecting"   # connecting | connected | reconnecting | disconnected | stopped
        self.reconnect_count = 0
        self._first_failure_time: Optional[float] = None
        self._shutdown_requested = False
        self._heartbeat_interval = 20  # overwritten by server's HELLO_OK value
        self._save_state("connecting")

    # -- persistence of client_id across reconnects/restarts -----------------

    def _load_client_id(self) -> bytes:
        if not self.state_file or not self.state_file.exists():
            return NULL_CLIENT_ID
        try:
            data = json.loads(self.state_file.read_text())
            if "client_id" in data and data["client_id"]:
                return bytes.fromhex(data["client_id"])
            return NULL_CLIENT_ID
        except Exception:
            return NULL_CLIENT_ID

    def _save_state(self, status: Optional[str] = None):
        if status:
            self.status = status
        
        cid_hex = self.client_id or (self._client_id_bytes.hex() if self._client_id_bytes != NULL_CLIENT_ID else None)
        tunnels_info = []
        public_urls = []
        for runtime in self.tunnels.values():
            info = {
                "tunnel_id": runtime.spec.tunnel_id,
                "type": runtime.spec.type,
                "status": runtime.status,
                "public_url": runtime.public_url,
                "local_destination": f"{runtime.spec.local_host}:{runtime.spec.local_port}",
            }
            tunnels_info.append(info)
            if runtime.public_url:
                public_urls.append(runtime.public_url)

        data = {
            "client_id": cid_hex,
            "pid": os.getpid(),
            "start_time": _proc_start_time(os.getpid()),
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

        # Write to self.state_file if configured
        target_files = []
        if self.state_file:
            target_files.append(self.state_file)
        if cid_hex:
            managed_file = _get_clients_dir() / f"{cid_hex}.json"
            if not self.state_file or managed_file.resolve() != self.state_file.resolve():
                target_files.append(managed_file)

        for sf in target_files:
            try:
                sf.parent.mkdir(parents=True, exist_ok=True)
                tmp = sf.with_suffix(".tmp")
                tmp.write_text(json.dumps(data, indent=2))
                tmp.replace(sf)
            except OSError as e:
                self.log.warning("Could not persist state to %s: %s", sf, e)

    def _save_client_id(self, client_id_hex: str):
        self.client_id = client_id_hex
        self._client_id_bytes = bytes.fromhex(client_id_hex)
        self._save_state()

    # -- logging helper (also feeds the dashboard's recent-logs list) --------

    def _log(self, level: int, msg: str, *args):
        self.log.log(level, msg, *args)
        try:
            self.recent_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg % args if args else msg}")
        except Exception:
            self.recent_logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    # -- outbound frame helper ------------------------------------------------

    async def _send(self, ftype: int, stream_id: int, payload: bytes = b""):
        data = encode_frame(ftype, stream_id, payload)
        async with self._write_lock:
            self.writer.write(data)
            await self.writer.drain()

    # =========================================================================
    # Top-level run loop: connect, serve, reconnect with backoff, or give up
    # after the grace period elapses with the server still unreachable.
    # =========================================================================

    async def run(self):
        backoff = 0.5
        max_backoff = 10.0
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
                if elapsed >= self.grace_time:
                    self._log(logging.ERROR,
                               "Server unreachable for %.0fs (grace period %.0fs) -- giving up.",
                               elapsed, self.grace_time)
                    self.status = "disconnected"
                    self._save_state("disconnected")
                    sys.exit(1)
                self._log(logging.WARNING, "Connection issue (%s); retrying in %.1fs "
                          "(unreachable for %.0fs / %.0fs grace period)",
                          e, backoff, elapsed, self.grace_time)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
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
        self._save_state("stopped")
        if self.writer is not None:
            for tunnel_id in list(self.tunnels.keys()):
                try:
                    await self._send(FrameType.TUNNEL_CLOSE, CONTROL_STREAM_ID,
                                      json.dumps({"tunnel_id": tunnel_id}).encode())
                except Exception:
                    pass
            try:
                self.writer.close()
            except Exception:
                pass

    # =========================================================================
    # One connection lifetime: connect, HELLO, register tunnels, dispatch loop
    # =========================================================================

    async def _connect_and_serve(self, first_attempt: bool):
        print("Connecting to %s:%s..." % (self.server_host, self.server_port), file=sys.stderr)
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.server_host, self.server_port), timeout=10
        )

        hello = build_hello_payload(self.secret, self._client_id_bytes)
        await self._send(FrameType.HELLO, CONTROL_STREAM_ID, hello)

        frame = await asyncio.wait_for(read_frame(self.reader), timeout=10)
        if frame.type == FrameType.HELLO_FAIL:
            try:
                reason = json.loads(frame.payload.decode()).get("error", "unknown reason")
            except Exception:
                reason = "unknown reason"
            raise AuthError(reason)
        if frame.type != FrameType.HELLO_OK:
            raise ProtocolError(f"expected HELLO_OK, got frame type {frame.type}")

        info = json.loads(frame.payload.decode())
        self.client_id = info["client_id"]
        self._client_id_bytes = bytes.fromhex(self.client_id)
        self._save_client_id(self.client_id)
        self._heartbeat_interval = info.get("heartbeat_interval", 20)

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

        # Close out any stream state left over from a previous connection --
        # those streams cannot be resumed (see protocol reconnect semantics).
        for stream in list(self.streams.values()):
            try:
                stream.local_writer.close()
            except Exception:
                pass
        self.streams.clear()
        self.pending_streams.clear()

        # (Re-)register every configured tunnel. Re-requesting the same
        # tunnel_id/subdomain/remote_port after a reconnect is how a stable
        # public URL is recovered, per the protocol's reconnect semantics.
        for runtime in self.tunnels.values():
            runtime.status = "pending"
            await self._request_tunnel_open(runtime.spec)

        watchdog_task = asyncio.create_task(self._inactivity_watchdog())
        try:
            await self._dispatch_loop()
        finally:
            watchdog_task.cancel()
            for stream in list(self.streams.values()):
                try:
                    stream.local_writer.close()
                except Exception:
                    pass
            self.streams.clear()
            self.pending_streams.clear()
            try:
                self.writer.close()
            except Exception:
                pass

    async def _request_tunnel_open(self, spec: TunnelSpec):
        req = {"tunnel_id": spec.tunnel_id, "type": spec.type}
        if spec.type == "http" and spec.subdomain:
            req["subdomain"] = spec.subdomain
        if spec.type in ("tcp", "udp") and spec.remote_port:
            req["remote_port"] = spec.remote_port
        await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(req).encode())

    # =========================================================================
    # Inbound frame dispatch
    # =========================================================================

    async def _dispatch_loop(self):
        self._last_frame_at = time.time()
        while True:
            frame = await read_frame(self.reader)
            self._last_frame_at = time.time()

            if frame.type == FrameType.PING:
                await self._send(FrameType.PONG, CONTROL_STREAM_ID)
            elif frame.type == FrameType.PONG:
                pass
            elif frame.type == FrameType.TUNNEL_OPEN_RESPONSE:
                self._handle_tunnel_open_response(frame)
            elif frame.type == FrameType.STREAM_OPEN:
                self._handle_stream_open(frame)
            elif frame.type == FrameType.STREAM_DATA:
                await self._route_stream_data(frame)
            elif frame.type == FrameType.STREAM_CLOSE:
                await self._route_stream_close(frame)
            elif frame.type == FrameType.STREAM_WINDOW_UPDATE:
                self._handle_window_update(frame)
            elif frame.type == FrameType.UDP_DATAGRAM:
                await self._route_udp_datagram(frame)
            elif frame.type == FrameType.ERROR:
                self._log(logging.WARNING, "Server error: %s", frame.payload[:200])
            else:
                self._log(logging.WARNING, "Unknown frame type %s from server", frame.type)

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
            if time.time() - self._last_frame_at > timeout:
                self._log(logging.WARNING, "No data from server in %.0fs; reconnecting", timeout)
                try:
                    self.writer.close()
                except Exception:
                    pass
                return

    def _handle_tunnel_open_response(self, frame):
        try:
            resp = json.loads(frame.payload.decode())
        except Exception:
            self._log(logging.WARNING, "Malformed TUNNEL_OPEN_RESPONSE: %r", frame.payload[:200])
            return
        tunnel_id = resp.get("tunnel_id")
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None:
            return
        if resp.get("status") == "ok":
            runtime.status = "active"
            runtime.error = None
            if resp.get("type") == "http":
                runtime.public_url = resp.get("public_url")
                self._log(logging.INFO, "HTTP tunnel ready: %s -> %s:%s",
                          runtime.public_url, runtime.spec.local_host, runtime.spec.local_port)
            else:
                port = resp.get("remote_port")
                host = resp.get("public_host", self.server_host)
                scheme = "udp" if resp.get("type") == "udp" else "tcp"
                runtime.public_url = f"{scheme}://{host}:{port}"
                runtime.spec.remote_port = port
                self._log(logging.INFO, "%s tunnel ready: %s -> %s:%s",
                          scheme.upper(), runtime.public_url, runtime.spec.local_host, runtime.spec.local_port)
        else:
            runtime.status = "error"
            runtime.error = resp.get("error", "unknown error")
            self._log(logging.ERROR, "Tunnel %s failed: %s", tunnel_id[:8], runtime.error)
        self._save_state()

    def _handle_stream_open(self, frame):
        """Synchronous: register the pending stream immediately (so any
        STREAM_DATA that arrives before the local connection finishes has
        somewhere to be buffered), then kick off the actual local connect
        in the background."""
        try:
            meta = json.loads(frame.payload.decode())
        except Exception:
            self._log(logging.WARNING, "Malformed STREAM_OPEN: %r", frame.payload[:200])
            return
        tunnel_id = meta.get("tunnel_id")
        proto = meta.get("proto", "tcp")
        self.pending_streams[frame.stream_id] = PendingStream(tunnel_id=tunnel_id)
        if proto == "udp":
            asyncio.create_task(self._establish_udp_stream(frame.stream_id, tunnel_id))
        else:
            asyncio.create_task(self._establish_stream(frame.stream_id, tunnel_id))

    async def _establish_stream(self, stream_id: int, tunnel_id: str):
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None:
            self.pending_streams.pop(stream_id, None)
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
            self.pending_streams.pop(stream_id, None)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        stream = ClientStream(stream_id=stream_id, tunnel_id=tunnel_id,
                               local_reader=local_reader, local_writer=local_writer)
        self.streams[stream_id] = stream
        runtime.connection_count += 1

        # Replay any STREAM_DATA that arrived while we were still connecting.
        pending = self.pending_streams.pop(stream_id, None)
        if pending:
            for payload in pending.buffered:
                if not await self._write_to_local(stream, payload):
                    return  # local write failed; already torn down
            if pending.closed:
                await self._route_stream_close_now(stream)
                return

        await self._pump_local_to_server(stream)

    async def _establish_udp_stream(self, stream_id: int, tunnel_id: str):
        runtime = self.tunnels.get(tunnel_id)
        if runtime is None:
            self.pending_streams.pop(stream_id, None)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

        spec = runtime.spec
        loop = asyncio.get_running_loop()

        class _UdpProtocol(asyncio.DatagramProtocol):
            def __init__(self, client, sid):
                self.client = client
                self.sid = sid

            def connection_made(self, transport):
                stream = self.client.streams.get(self.sid)
                if stream is not None:
                    stream.udp_transport = transport
                pending = self.client.pending_streams.pop(self.sid, None)
                if pending:
                    for payload in pending.buffered:
                        self.client._udp_send_now(self.sid, payload)
                    if pending.closed:
                        asyncio.create_task(self.client._route_stream_close_now(
                            self.client.streams.get(self.sid)))

            def datagram_received(self, data, addr):
                asyncio.create_task(self.client._udp_send_to_server(self.sid, data))

            def error_received(self, exc):
                self.client._log(logging.WARNING, "Local UDP %s:%s error for tunnel %s: %s",
                                 spec.local_host, spec.local_port, tunnel_id[:8], exc)

            def connection_lost(self, exc):
                stream = self.client.streams.get(self.sid)
                if stream is not None and not stream.closed:
                    asyncio.create_task(self.client._route_stream_close_now(stream))

        stream = ClientStream(stream_id=stream_id, tunnel_id=tunnel_id,
                               local_reader=None, local_writer=None)
        self.streams[stream_id] = stream
        runtime.connection_count += 1

        try:
            await asyncio.wait_for(
                loop.create_datagram_endpoint(lambda: _UdpProtocol(self, stream_id),
                                              remote_addr=(spec.local_host, spec.local_port)),
                timeout=10)
        except (OSError, asyncio.TimeoutError) as e:
            self._log(logging.WARNING, "Local UDP %s:%s unreachable for tunnel %s: %s",
                      spec.local_host, spec.local_port, tunnel_id[:8], e)
            self.streams.pop(stream_id, None)
            self.pending_streams.pop(stream_id, None)
            await self._safe_send(FrameType.STREAM_CLOSE, stream_id)
            return

    def _udp_send_now(self, stream_id: int, payload: bytes):
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed or stream.udp_transport is None:
            return
        try:
            stream.udp_transport.sendto(payload)
        except (OSError, ConnectionError):
            pass
        runtime = self.tunnels.get(stream.tunnel_id)
        if runtime is not None:
            runtime.bytes_out += len(payload)

    async def _udp_send_to_server(self, stream_id: int, payload: bytes):
        stream = self.streams.get(stream_id)
        if stream is None or stream.closed:
            return
        if not await self._safe_send(FrameType.UDP_DATAGRAM, stream_id, payload):
            return
        runtime = self.tunnels.get(stream.tunnel_id)
        if runtime is not None:
            runtime.bytes_in += len(payload)
            runtime.latencies_ms.append(max(1.0, (time.time() - stream.opened_at) * 1000))

    async def _route_udp_datagram(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            self._udp_send_now(frame.stream_id, frame.payload)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            pending.buffered.append(frame.payload)
        # else: stream unknown to us (already closed on our side) -- ignore.

    async def _route_stream_data(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            await self._write_to_local(stream, frame.payload)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            pending.buffered.append(frame.payload)
        # else: stream unknown to us (already closed on our side) -- ignore.

    async def _route_stream_close(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is not None:
            await self._route_stream_close_now(stream)
            return
        pending = self.pending_streams.get(frame.stream_id)
        if pending is not None:
            pending.closed = True

    async def _route_stream_close_now(self, stream: ClientStream):
        self.streams.pop(stream.stream_id, None)
        stream.closed = True
        if stream.udp_transport is not None:
            try:
                stream.udp_transport.close()
            except Exception:
                pass
        try:
            stream.local_writer.close()
        except Exception:
            pass

    async def _pump_local_to_server(self, stream: ClientStream):
        """Read from the local backend and forward as STREAM_DATA frames,
        chunked to MAX_FRAME_PAYLOAD and respecting this stream's flow
        control window -- mirrors the server's send_stream_data exactly."""
        try:
            while True:
                await stream.send_window.wait()
                chunk = await stream.local_reader.read(MAX_FRAME_PAYLOAD)
                if not chunk:
                    break
                await self._send_stream_data(stream, chunk)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            if not stream.closed:
                stream.closed = True
                await self._safe_send(FrameType.STREAM_CLOSE, stream.stream_id)
            self.streams.pop(stream.stream_id, None)
            try:
                stream.local_writer.close()
            except Exception:
                pass

    async def _send_stream_data(self, stream: ClientStream, data: bytes):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            await stream.send_window.wait()
            chunk = view[offset: offset + MAX_FRAME_PAYLOAD]
            if stream.send_window.available > 0:
                chunk = chunk[: max(1, min(len(chunk), stream.send_window.available))]
            await self._send(FrameType.STREAM_DATA, stream.stream_id, bytes(chunk))
            stream.send_window.consume(len(chunk))

            if not stream.first_byte_recorded:
                stream.first_byte_recorded = True
                latency_ms = (time.time() - stream.opened_at) * 1000
                runtime = self.tunnels.get(stream.tunnel_id)
                if runtime is not None:
                    runtime.latencies_ms.append(latency_ms)

            runtime = self.tunnels.get(stream.tunnel_id)
            if runtime is not None:
                runtime.bytes_in += len(chunk)
            offset += len(chunk)

    async def _write_to_local(self, stream: ClientStream, payload: bytes) -> bool:
        """Write server->client payload to the local backend socket, doing
        the receive-side flow-control accounting (unacked bytes + periodic
        WINDOW_UPDATE) exactly as the server does on its own receive side.
        Returns False (and tears the stream down) on a local write error."""
        if stream.closed:
            return False
        try:
            stream.local_writer.write(payload)
            await stream.local_writer.drain()
        except (ConnectionError, OSError):
            self.streams.pop(stream.stream_id, None)
            stream.closed = True
            await self._safe_send(FrameType.STREAM_CLOSE, stream.stream_id)
            return False

        n = len(payload)
        runtime = self.tunnels.get(stream.tunnel_id)
        if runtime is not None:
            runtime.bytes_out += n

        stream.unacked_recv_bytes += n
        if stream.unacked_recv_bytes >= WINDOW_UPDATE_THRESHOLD:
            increment = stream.unacked_recv_bytes
            stream.unacked_recv_bytes = 0
            await self._safe_send(FrameType.STREAM_WINDOW_UPDATE, stream.stream_id, increment.to_bytes(4, "big"))
        return True

    def _handle_window_update(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None or len(frame.payload) != 4:
            return
        increment = int.from_bytes(frame.payload, "big")
        stream.send_window.replenish(increment)

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
            tunnels.append({
                "tunnel_id": runtime.spec.tunnel_id,
                "type": spec.type,
                "status": runtime.status,
                "public_url": runtime.public_url,
                "error": runtime.error,
                "local_destination": f"{spec.local_host}:{spec.local_port}",
                "connections": runtime.connection_count,
                "bytes_in": runtime.bytes_in,
                "bytes_out": runtime.bytes_out,
                "avg_latency_ms": runtime.avg_latency_ms(),
            })
        return {
            "status": self.status,
            "server": f"{self.server_host}:{self.server_port}",
            "client_id": self.client_id,
            "process_uptime_seconds": round(now - self.process_start_time),
            "connected_since": self.connected_since,
            "connected_for_seconds": round(now - self.connected_since) if self.connected_since and self.status == "connected" else None,
            "reconnect_count": self.reconnect_count,
            "active_streams": len(self.streams) + len(self.pending_streams),
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
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #262b36; }
  th { color:#8a90a2; font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
  .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; background:#26314a; color:#8fb3ff; margin-right:4px; }
  .tag.tcp { background:#312a1a; color:#e8b96a; }
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
<h1><span class="dot" id="statusdot"></span> my_proxy <span id="statustext" style="font-weight:400;color:#8a90a2;font-size:14px;"></span></h1>
<div class="sub" id="subtitle">loading...</div>

<div class="grid" id="summary-cards"></div>

<section>
  <h2>Tunnels</h2>
  <div id="tunnels"></div>
</section>

<section>
  <h2>Recent Log Messages</h2>
  <div id="log"></div>
</section>

<script>
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
  try { data = await (await fetch('/api/stats')).json(); } catch (e) { return; }

  document.getElementById('statusdot').className = 'dot ' + data.status;
  document.getElementById('statustext').textContent = data.status;
  document.getElementById('subtitle').textContent =
    `server ${data.server} \u00b7 process uptime ${fmtDuration(data.process_uptime_seconds)} \u00b7 connected for ${fmtDuration(data.connected_for_seconds)} \u00b7 reconnects: ${data.reconnect_count}`;

  let bytesIn = 0, bytesOut = 0, conns = 0;
  data.tunnels.forEach(t => { bytesIn += t.bytes_in; bytesOut += t.bytes_out; conns += t.connections; });

  const cards = [
    ["Status", data.status],
    ["Uptime", fmtDuration(data.process_uptime_seconds)],
    ["Reconnects", data.reconnect_count],
    ["Active tunnels", data.tunnels.filter(t => t.status === 'active').length],
    ["Active streams", data.active_streams],
    ["Total connections", conns],
    ["Bytes in", fmtBytes(bytesIn)],
    ["Bytes out", fmtBytes(bytesOut)],
  ];
  document.getElementById('summary-cards').innerHTML = cards.map(([l,v]) =>
    `<div class="card"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');

  const tunnelsEl = document.getElementById('tunnels');
  if (!data.tunnels.length) {
    tunnelsEl.innerHTML = '<div class="empty">No tunnels configured.</div>';
  } else {
    tunnelsEl.innerHTML = `
      <table>
        <thead><tr>
          <th>Status</th><th>Protocol</th><th>Public URL</th><th>Local destination</th>
          <th>Connections</th><th>Bytes in</th><th>Bytes out</th><th>Avg latency</th>
        </tr></thead>
        <tbody>
        ${data.tunnels.map(t => `
          <tr>
            <td><span class="tag ${t.status === 'error' ? 'error' : (t.status === 'pending' ? 'pending' : '')}">${t.status}</span></td>
            <td><span class="tag ${t.type}">${t.type}</span></td>
            <td>${t.public_url ? `<a href="${t.public_url}" target="_blank">${t.public_url}</a>` : (t.error || '-')}</td>
            <td>${t.local_destination}</td>
            <td>${t.connections}</td>
            <td>${fmtBytes(t.bytes_in)}</td>
            <td>${fmtBytes(t.bytes_out)}</td>
            <td>${t.avg_latency_ms !== null && t.avg_latency_ms !== undefined ? t.avg_latency_ms.toFixed(0) + ' ms' : '-'}</td>
          </tr>`).join('')}
        </tbody>
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


async def _handle_dashboard_conn(reader, writer, client: TunnelClient):
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        while True:
            h = await asyncio.wait_for(reader.readline(), timeout=5)
            if h in (b"\r\n", b""):
                break
        try:
            _, path, _ = request_line.decode(errors="replace").split(None, 2)
        except ValueError:
            writer.close()
            return

        if path.startswith("/api/stats"):
            body = json.dumps(client.stats_snapshot()).encode()
            content_type = "application/json"
        elif path == "/" or path.startswith("/?"):
            body = _DASHBOARD_HTML.encode()
            content_type = "text/html; charset=utf-8"
        else:
            body = b"not found"
            header = (f"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
            writer.write(header + body)
            await writer.drain()
            writer.close()
            return

        header = (f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n"
                  f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        writer.write(header + body)
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


async def serve_dashboard(client: TunnelClient, host: str, port: int, log: logging.Logger):
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


def _proc_start_time(pid: int) -> Optional[int]:
    """Read the process start time (field 22 of /proc/<pid>/stat, in clock
    ticks since boot). This value is stable for the lifetime of a process
    and changes if the PID is reused, making it a reliable PID-reuse guard.
    Returns None on platforms/filesystems where it cannot be determined."""
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


def _is_pid_alive(pid: int, expected_start_time: Optional[int] = None) -> bool:
    """Check if process with given PID exists and is actively running (not
    zombie). If expected_start_time is provided, the PID must also refer to a
    process that started at that time -- otherwise the original process has
    exited and the PID has been reused by something else."""
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
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
        if actual is not None and actual != expected_start_time:
            return False
    return True


def _verify_client_process(pid: int, state: dict) -> bool:
    """Verify that the process with PID is actually a LinkPulse client
    to prevent PID reuse from affecting unrelated processes.

    Primary guard is the process start time recorded when the client was
    launched: if the PID now belongs to a process that started at a different
    time, it has been reused and is not our client. Command-line matching is
    used only as a secondary confirmation -- never as an unconditional pass --
    so an unrelated Python process that happens to reuse the PID is rejected.
    """
    expected_start = state.get("start_time")
    if not _is_pid_alive(pid, expected_start):
        return False
    if expected_start is not None:
        return True

    # Legacy state files without a recorded start time: fall back to the best
    # available heuristic. A process is accepted only if it is actually one of
    # our launchers (name match) and, when a client_id is known, the launcher
    # command line references this client's state file / id.
    cid = state.get("client_id", "")
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    if proc_cmdline.exists():
        try:
            cmdline = proc_cmdline.read_bytes().decode("utf-8", errors="ignore").replace("\x00", " ")
        except (OSError, PermissionError):
            return True
        if not any(k in cmdline for k in ("my_proxy", "linkpulse")):
            return False
        if cid and cid in cmdline:
            return True
        state_file = state.get("state_file", "")
        if state_file and state_file in cmdline:
            return True
        return False
    return True


def _find_client_state_file(client_id_or_prefix: str) -> tuple[Optional[Path], Optional[str]]:
    """Find the client state file matching client_id or unambiguous prefix.
    Returns (Path, None) on match, (None, error_message) on failure."""
    clients_dir = _get_clients_dir()
    if not clients_dir.exists():
        return None, f"Client '{client_id_or_prefix}' not found."

    exact = clients_dir / f"{client_id_or_prefix}.json"
    if exact.is_file():
        return exact, None

    matches = []
    for f in clients_dir.glob("*.json"):
        if f.stem.startswith(client_id_or_prefix):
            matches.append(f)

    if len(matches) == 1:
        return matches[0], None
    elif len(matches) > 1:
        names = ", ".join(m.stem for m in matches[:5])
        return None, f"Ambiguous client ID prefix '{client_id_or_prefix}' matches multiple clients: {names}"
    else:
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

    client_files = sorted(clients_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
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
        rows.append((cid, pid_str, mode, target, server, status))

    headers = ("CLIENT ID", "PID", "MODE", "TARGET", "SERVER", "STATUS")
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
                    candidate = json.loads(resp.read().decode())
                    # Guard against multiple clients sharing the default
                    # dashboard port: only trust stats that belong to this
                    # client (all clients default to 127.0.0.1:4040, so the
                    # first one to bind would otherwise answer for all).
                    if candidate.get("client_id") == cid:
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
    print(f"PID:             {pid if pid else '-'}")
    print(f"Status:          {status}")
    print(f"Mode:            {mode}")
    print(f"Local target:    {target}")
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


def _cli_clients_delete(client_id: str) -> None:
    state_file, err = _find_client_state_file(client_id)
    if err or not state_file:
        print(f"Error: {err or 'Client not found.'}", file=sys.stderr)
        sys.exit(1)

    data = _read_client_state(state_file)
    cid = data.get("client_id", state_file.stem)
    pid = data.get("pid")
    expected_start = data.get("start_time")

    if isinstance(pid, int) and pid > 0 and _verify_client_process(pid, data):
        print(f"Stopping client {cid} (PID {pid})...")
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

        # Wait up to 3 seconds for graceful shutdown
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not _is_pid_alive(pid, expected_start):
                break
            time.sleep(0.1)

        # Escalate to SIGKILL if still running
        if _is_pid_alive(pid, expected_start):
            try:
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.2)
            except OSError:
                pass

        try:
            state_file.unlink(missing_ok=True)
        except OSError as e:
            print(f"Error removing state file: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Client {cid} stopped and removed.")
    else:
        try:
            state_file.unlink(missing_ok=True)
        except OSError as e:
            print(f"Error removing state file: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Client {cid} (stopped) removed.")


def _spawn_detached(args: argparse.Namespace, mode: str, target_str: str,
                    log_file_path: Optional[str] = None) -> None:
    """Spawn a background client process and return immediately."""
    clients_dir = _get_clients_dir()
    logs_dir = _get_logs_dir()
    clients_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    client_id = getattr(args, "client_id", None) or uuid.uuid4().hex
    state_file = Path(args.state_file) if args.state_file else (clients_dir / f"{client_id}.json")
    # A child launched in detached mode always persists its managed state in
    # the clients dir, so `clients list/info/delete` can find it.
    managed_state_file = clients_dir / f"{client_id}.json"
    log_file = Path(log_file_path) if log_file_path else (logs_dir / f"{client_id}.log")

    if getattr(sys, "frozen", False):
        # PyInstaller --onefile: sys.executable points inside the ephemeral
        # temp extraction dir (/tmp/_MEIxxxx/...) which is deleted when the
        # parent exits. sys.argv[0] is the stable on-disk path the user
        # actually invoked (e.g. /home/user/bin/linkpulse).
        cmd = [os.path.abspath(sys.argv[0])]
    else:
        cmd = [sys.executable, str(Path(__file__).resolve())]

    # Forward args without -d / --detach
    child_args = []
    for arg in sys.argv[1:]:
        if arg in ("-d", "--detach"):
            continue
        child_args.append(arg)

    child_args.extend([
        "--daemon-child",
        "--client-id", client_id,
        "--state-file", str(state_file),
        "--log-file", str(log_file),
    ])

    initial_data = {
        "client_id": client_id,
        "pid": 0,
        "status": "starting",
        "mode": mode,
        "target": target_str,
        "server": args.server,
        "dashboard": None if args.no_dashboard else args.dashboard,
        "started_at": time.time(),
        "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "log_file": str(log_file),
        "state_file": str(managed_state_file),
        "public_urls": [],
        "cmdline": [mode, target_str],
    }
    managed_state_file.write_text(json.dumps(initial_data, indent=2))

    env = os.environ.copy()
    if getattr(sys, "frozen", False):
        # PyInstaller --onefile bootloader pollutes the environment with
        # variables that bind the child to the parent's ephemeral temp
        # extraction directory.  When the parent exits it deletes that
        # directory, so the child crashes importing base_library.zip.
        #
        # Strip every PyInstaller-internal variable so the child performs
        # a completely independent extraction into its own temp dir.
        for key in list(env):
            if key.startswith("_PYI_") or key == "_MEIPASS2":
                del env[key]
        # The bootloader also prepends the temp dir to LD_LIBRARY_PATH.
        # Restore the original value (saved by the bootloader) so the
        # child's linker doesn't reference the now-deleted parent dir.
        orig_ldpath = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig_ldpath is not None:
            env["LD_LIBRARY_PATH"] = orig_ldpath
        else:
            env.pop("LD_LIBRARY_PATH", None)

    log_fd = open(log_file, "a", encoding="utf-8")
    try:
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            proc = subprocess.Popen(
                cmd + child_args,
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                close_fds=True,
                env=env,
            )
        else:
            proc = subprocess.Popen(
                cmd + child_args,
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
                env=env,
            )
    finally:
        log_fd.close()

    initial_data["pid"] = proc.pid
    initial_data["start_time"] = _proc_start_time(proc.pid)
    initial_data["status"] = "running"
    managed_state_file.write_text(json.dumps(initial_data, indent=2))

    print("LinkPulse client started in background.")
    print(f"  Client ID:   {client_id}")
    print(f"  PID:         {proc.pid}")
    print(f"  Mode:        {mode}")
    print(f"  Target:      {target_str}")
    print(f"  Server:      {args.server}")
    print(f"  Log file:    {log_file}")
    print(f"  State file:  {state_file}")
    sys.exit(0)


def _parse_host_port(s: str, default_host: str = "127.0.0.1", default_port: int = 9000) -> tuple[str, int]:
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return (host or default_host), int(port)
    # If only hostname provided, use default control port (9000)
    return s, default_port


def _normalize_server_address(s: str, default_port: int = 9000) -> str:
    """Normalize server address - strip protocol/prefix, append default control port if no port specified."""
    # Strip protocol prefix
    if s.startswith("https://"):
        s = s[8:]
    elif s.startswith("http://"):
        s = s[7:]
    # Strip trailing slash
    s = s.rstrip("/")
    # If no port specified, append default
    if ":" not in s:
        s = f"{s}:{default_port}"
    return s


def _parse_target(s: str) -> tuple[str, int]:
    """Parse an http/tcp target: either 'PORT' (-> localhost:PORT) or
    'HOST:PORT'."""
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, int(port)
    return "localhost", int(s)


def _build_arg_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-d", "--detach", action="store_true",
                        help="run client in background (detached mode)")
    common.add_argument("--server", default=os.environ.get("MY_PROXY_SERVER", DEFAULT_SERVER),
                         help=f"proxy control server as host:port (default: {DEFAULT_SERVER}, env MY_PROXY_SERVER)")
    common.add_argument("--token", default=os.environ.get("MY_PROXY_TOKEN"),
                         help="shared secret for authentication (env MY_PROXY_TOKEN)")
    common.add_argument("--grace-time", type=float, default=DEFAULT_GRACE_TIME,
                         help=f"seconds to keep retrying before giving up if the server is unreachable (default: {DEFAULT_GRACE_TIME})")
    common.add_argument("--dashboard", default=os.environ.get("MY_PROXY_DASHBOARD", DEFAULT_DASHBOARD),
                         help=f"local dashboard address (default: {DEFAULT_DASHBOARD})")
    common.add_argument("--no-dashboard", action="store_true", help="disable the local dashboard")
    common.add_argument("--state-file", default=None,
                         help=f"path to persist client ID across restarts (default: {DEFAULT_STATE_FILE})")
    common.add_argument("--client-id", default=None, help=argparse.SUPPRESS)
    common.add_argument("--log-file", default=None, help=argparse.SUPPRESS)
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
  linkpulse tcp 22 --remote-port 20022              Expose localhost:22 via TCP tunnel
  linkpulse tcp 22 -d                               Expose localhost:22 in background
  linkpulse start tunnels.json                      Open multiple tunnels from config
  linkpulse clients list                            List running LinkPulse clients
  linkpulse clients info <client-id>                Show details for a client
  linkpulse clients delete <client-id>              Stop and remove a client
  linkpulse authtoken <secret>                      Save authentication token
  linkpulse server proxy.example.com:9000           Save server address
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

    return parser


def _load_start_config(path: str, cli_args: argparse.Namespace) -> tuple[list[TunnelSpec], argparse.Namespace]:
    with open(path) as f:
        cfg = json.load(f)

    # File values are defaults; explicit CLI flags win. argparse doesn't
    # tell us "was this explicitly passed", so we only let the file fill in
    # values that are still at their hard-coded default / None.
    if cfg.get("server") and cli_args.server == DEFAULT_SERVER:
        cli_args.server = _normalize_server_address(cfg["server"])
    if cfg.get("token") and cli_args.token is None:
        cli_args.token = cfg["token"]

    specs = []
    for t in cfg.get("tunnels", []):
        ttype = t["type"]
        host, port = _parse_target(str(t["local"]))
        if ttype == "http":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                     local_host=host, local_port=port,
                                     subdomain=t.get("subdomain")))
        elif ttype == "tcp":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="tcp",
                                     local_host=host, local_port=port,
                                     remote_port=t.get("remote_port")))
        elif ttype == "udp":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="udp",
                                     local_host=host, local_port=port,
                                     remote_port=t.get("remote_port")))
        else:
            raise ValueError(f"unknown tunnel type in config: {ttype!r}")
    return specs, cli_args


def _load_saved_token() -> Optional[str]:
    """Load the saved auth token from the config file."""
    try:
        if DEFAULT_TOKEN_FILE.exists():
            data = json.loads(DEFAULT_TOKEN_FILE.read_text())
            return data.get("token")
    except Exception:
        pass
    return None


def _load_saved_server() -> Optional[str]:
    """Load the saved server address from the config file."""
    try:
        if DEFAULT_TOKEN_FILE.exists():
            data = json.loads(DEFAULT_TOKEN_FILE.read_text())
            return data.get("server")
    except Exception:
        pass
    return None


def _save_config(token: Optional[str] = None, server: Optional[str] = None) -> None:
    """Save the auth token and/or server address to the config file."""
    try:
        data = {}
        if DEFAULT_TOKEN_FILE.exists():
            data = json.loads(DEFAULT_TOKEN_FILE.read_text())
        if token is not None:
            data["token"] = token
        if server is not None:
            data["server"] = server
        DEFAULT_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_TOKEN_FILE.write_text(json.dumps(data, indent=2))
        if token is not None:
            print(f"Saved auth token to {DEFAULT_TOKEN_FILE}")
        if server is not None:
            print(f"Saved server address to {DEFAULT_TOKEN_FILE}")
    except OSError as e:
        print(f"Error saving config: {e}", file=sys.stderr)
        sys.exit(1)


def _setup_logging(level: str, recent_logs: deque) -> logging.Logger:
    log = logging.getLogger("my_proxy")
    log.setLevel(getattr(logging, level))
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", "%H:%M:%S"))
    log.addHandler(handler)
    log.propagate = False
    return log


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

    # Load saved token if not provided via CLI or env
    if not args.token:
        args.token = _load_saved_token()

    # Load saved server if not provided via CLI or env
    if args.server == DEFAULT_SERVER:
        saved_server = _load_saved_server()
        if saved_server:
            args.server = _normalize_server_address(saved_server)

    if not args.token:
        print("Error: No shared secret provided. Pass --token, set MY_PROXY_TOKEN, or run 'linkpulse authtoken <token>'.",
              file=sys.stderr)
        sys.exit(1)

    if args.command in ("http", "tcp", "udp"):
        try:
            host, port = _parse_target(args.target)
        except ValueError:
            print(f"Error: invalid target {args.target!r}; expected PORT or HOST:PORT.",
                  file=sys.stderr)
            sys.exit(1)
        if args.command == "http":
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                 local_host=host, local_port=port, subdomain=args.subdomain)]
        else:
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type=args.command,
                                 local_host=host, local_port=port, remote_port=args.remote_port)]
    elif args.command == "start":
        try:
            specs, args = _load_start_config(args.config, args)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"Error loading config {args.config}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        raise SystemExit(f"unknown command {args.command!r}")

    if not specs:
        print("Error: No tunnels to open.", file=sys.stderr)
        sys.exit(1)

    server_host, server_port = _parse_host_port(args.server)
    state_file = Path(args.state_file) if args.state_file else DEFAULT_STATE_FILE
    dash_host, dash_port = _parse_host_port(args.dashboard, default_host="127.0.0.1", default_port=4040)

    # Only now -- after all validation -- spawn the background child, so an
    # invalid invocation (missing token, bad config, ...) fails in the
    # foreground instead of reporting a bogus successful background start.
    if getattr(args, "detach", False) and not getattr(args, "daemon_child", False):
        _spawn_detached(args, mode, target_str, log_file_path=args.log_file)
        return

    client = TunnelClient(
        specs=specs, server_host=server_host, server_port=server_port,
        secret=args.token, grace_time=args.grace_time, state_file=state_file,
        log=log, recent_logs=recent_logs,
        client_id=getattr(args, "client_id", None),
        mode=mode,
        target_str=target_str,
        dashboard_addr=None if args.no_dashboard else f"{dash_host}:{dash_port}",
        log_file_path=getattr(args, "log_file", None),
    )

    tasks = [asyncio.create_task(client.run())]
    if not args.no_dashboard:
        tasks.append(asyncio.create_task(serve_dashboard(client, dash_host, dash_port, log)))

    loop = asyncio.get_running_loop()
    shutdown_once = {"done": False}

    def _signal_handler():
        if shutdown_once["done"]:
            return
        shutdown_once["done"] = True
        log.info("Shutting down...")
        asyncio.create_task(client.request_shutdown())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await tasks[0]
    finally:
        for t in tasks[1:]:
            t.cancel()
        await asyncio.gather(*tasks[1:], return_exceptions=True)


def main():
    parser = _build_arg_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
