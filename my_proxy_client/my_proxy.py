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
                 log_file_path: Optional[str] = None,
                 retry_interval: float = 5.0):
        self.specs = specs
        self.server_host = server_host
        self.server_port = server_port
        self.secret = secret
        self.grace_time = grace_time
        self.retry_interval = max(1.0, float(retry_interval))
        self.state_file = state_file
        self.log = log
        self.recent_logs = recent_logs
        self.mode = mode
        self.target_str = target_str
        self.dashboard_addr = dashboard_addr
        self.log_file_path = log_file_path

        # Identifies *this process* to the server. client_id is shared by
        # every client process on a machine (persisted state file), so
        # without this the server cannot tell a reconnect (same instance)
        # from a competing second client (different instance).
        self.instance_id = secrets.token_hex(8)

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

        # Tunnels the server took away (handoff / closed): never re-requested.
        self._revoked_tunnel_ids: set[str] = set()
        # Background retry loops for tunnel registrations that failed (name
        # in use, lease held elsewhere, no ports free, ...).
        self._retry_tasks: dict[str, asyncio.Task] = {}
        # TUNNEL_OPEN_REQUESTs sent but not answered yet.
        self._open_inflight: set[str] = set()

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
                "mode": runtime.spec.mode,
                "status": runtime.status,
                "public_url": runtime.public_url,
                "local_destination": f"{runtime.spec.local_host}:{runtime.spec.local_port}",
            }
            tunnels_info.append(info)
            if runtime.public_url:
                public_urls.append(runtime.public_url)

        data = {
            "client_id": cid_hex,
            "instance_id": self.instance_id,
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

                await asyncio.sleep(self.retry_interval)
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
        self._cancel_all_retries_now()
        self._save_state("stopped")
        if self.writer is not None:
            for tunnel_id in list(self.tunnels.keys()):
                if tunnel_id in self._revoked_tunnel_ids:
                    continue
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
        if first_attempt or self._retry_log_count <= 1:
            # Plain stderr line (not a log record) so a foreground start always
            # shows what it is doing; retries are covered by the throttled
            # warning/error messages in run().
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
        self._retry_log_count = 0

        # Close out any stream state left over from a previous connection --
        # those streams cannot be resumed (see protocol reconnect semantics).
        for stream in list(self.streams.values()):
            try:
                stream.local_writer.close()
            except Exception:
                pass
        self.streams.clear()
        self.pending_streams.clear()

        # Any in-flight registration from the previous connection is void, and
        # so are its retry timers -- every tunnel is re-requested below.
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
        req = {"tunnel_id": spec.tunnel_id, "type": spec.type,
               "mode": spec.mode, "instance_id": self.instance_id}
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

            if frame.type == FrameType.PING:
                await self._send(FrameType.PONG, CONTROL_STREAM_ID)
            elif frame.type == FrameType.PONG:
                pass
            elif frame.type == FrameType.TUNNEL_OPEN_RESPONSE:
                self._handle_tunnel_open_response(frame)
            elif frame.type == FrameType.TUNNEL_CLOSE:
                await self._handle_tunnel_close_from_server(frame)
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
        self._open_inflight.discard(tunnel_id)
        if resp.get("status") == "ok":
            runtime.status = "active"
            runtime.error = None
            runtime.failure_count = 0
            self._cancel_retry(tunnel_id)
            mode_note = " [lease]" if runtime.spec.mode == TUNNEL_MODE_LEASE else ""
            if resp.get("type") == "http":
                runtime.public_url = resp.get("public_url")
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
        except Exception:
            info = {}
        tunnel_id = info.get("tunnel_id")
        runtime = self.tunnels.get(tunnel_id) if tunnel_id else None
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
                await self._route_stream_close_now(stream)
        for stream_id in [sid for sid, p in self.pending_streams.items() if p.tunnel_id == tunnel_id]:
            self.pending_streams.pop(stream_id, None)

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
        self.status = "stopped"
        self._save_state("stopped")
        self._cancel_all_retries_now()
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass

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
                "mode": spec.mode,
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
          <th>Status</th><th>Protocol</th><th>Mode</th><th>Public URL</th><th>Local destination</th>
          <th>Connections</th><th>Bytes in</th><th>Bytes out</th><th>Avg latency</th>
        </tr></thead>
        <tbody>
        ${data.tunnels.map(t => `
          <tr>
            <td><span class="tag ${t.status === 'error' ? 'error' : (t.status === 'pending' ? 'pending' : '')}">${t.status}</span></td>
            <td><span class="tag ${t.type}">${t.type}</span></td>
            <td><span class="tag ${t.mode === 'lease' ? 'lease' : ''}">${t.mode || 'handoff'}</span></td>
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

    client_files = list(clients_dir.glob("*.json"))
    if not client_files:
        print("No LinkPulse clients found.")
        return

    removed = 0
    skipped = 0

    for f in client_files:
        data = _read_client_state(f)
        cid = data.get("client_id", f.stem)
        pid = data.get("pid")
        expected_start = data.get("start_time")
        is_alive = (isinstance(pid, int) and pid > 0
                     and _verify_client_process(pid, data))

        if is_alive and not force:
            raw_status = data.get("status", "unknown")
            print(f"  Skipped  {cid}  (status: {raw_status}, PID {pid}) -- use -f to force")
            skipped += 1
            continue

        if is_alive:
            # --force: stop the running client
            print(f"  Stopping {cid} (PID {pid})...")
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            deadline = time.time() + 3.0
            while time.time() < deadline:
                if not _is_pid_alive(pid, expected_start):
                    break
                time.sleep(0.1)
            if _is_pid_alive(pid, expected_start):
                try:
                    os.kill(pid, signal.SIGKILL)
                    time.sleep(0.2)
                except OSError:
                    pass

        try:
            f.unlink(missing_ok=True)
        except OSError as e:
            print(f"  Error removing {cid}: {e}", file=sys.stderr)
            continue
        label = "Stopped and removed" if is_alive else "Removed"
        print(f"  {label}  {cid}")
        removed += 1

    parts = [f"{removed} client(s) removed"]
    if skipped:
        parts.append(f"{skipped} connected client(s) skipped")
    print(" | ".join(parts) + ".")


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
        # parent exits.  We need the stable on-disk path to the binary.
        #
        # sys.argv[0] may be a bare name found via PATH (e.g. "linkpulse"),
        # so os.path.abspath() would wrongly resolve it relative to cwd.
        # Use shutil.which() to honour PATH, falling back to abspath.
        import shutil
        binary = shutil.which(sys.argv[0]) or os.path.abspath(sys.argv[0])
        cmd = [binary]
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
                         help=f"after this many seconds without a server connection, retries are logged "
                              f"as errors instead of warnings (default: {DEFAULT_GRACE_TIME}); the client "
                              f"always keeps retrying and never gives up")
    common.add_argument("--retry-interval", type=float,
                         default=float(os.environ.get("MY_PROXY_RETRY_INTERVAL", DEFAULT_RETRY_INTERVAL)),
                         help=f"seconds between reconnect attempts (default: {DEFAULT_RETRY_INTERVAL}, "
                              f"env MY_PROXY_RETRY_INTERVAL); retries continue indefinitely")
    common.add_argument("--lease", action="store_true",
                         help="lease the requested name instead of taking it over: refuse to start that "
                              "tunnel if another client already holds the subdomain/port (default is "
                              "handoff mode, where the newest client wins)")
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
  linkpulse http 8080 -u api                        Request the public name "api"
  linkpulse http 8080 -u api --lease                Lease "api": never hand it off to other clients
  linkpulse tcp 22 --remote-port 20022              Expose localhost:22 via TCP tunnel
  linkpulse tcp 22 -d                               Expose localhost:22 in background
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
        raise ValueError(f"invalid mode {value!r} in {where}; expected 'handoff' or 'lease'")
    return mode


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

    # Ownership mode: --lease forces every tunnel to lease, otherwise the
    # file's top-level "mode" sets the default and each tunnel may override it.
    cli_lease = bool(getattr(cli_args, "lease", False))
    default_mode = (TUNNEL_MODE_LEASE if cli_lease
                    else _normalize_mode(cfg.get("mode", TUNNEL_MODE_HANDOFF), path))

    specs = []
    for t in cfg.get("tunnels", []):
        ttype = t["type"]
        host, port = _parse_target(str(t["local"]))
        mode = default_mode if cli_lease else _normalize_mode(t.get("mode", default_mode), path)
        if ttype == "http":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                     local_host=host, local_port=port,
                                     subdomain=t.get("subdomain"), mode=mode))
        elif ttype == "tcp":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="tcp",
                                     local_host=host, local_port=port,
                                     remote_port=t.get("remote_port"), mode=mode))
        elif ttype == "udp":
            specs.append(TunnelSpec(tunnel_id=new_tunnel_id(), type="udp",
                                     local_host=host, local_port=port,
                                     remote_port=t.get("remote_port"), mode=mode))
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
        tunnel_mode = TUNNEL_MODE_LEASE if args.lease else TUNNEL_MODE_HANDOFF
        if args.command == "http":
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type="http",
                                 local_host=host, local_port=port,
                                 subdomain=args.subdomain, mode=tunnel_mode)]
        else:
            specs = [TunnelSpec(tunnel_id=new_tunnel_id(), type=args.command,
                                 local_host=host, local_port=port,
                                 remote_port=args.remote_port, mode=tunnel_mode)]
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
        retry_interval=getattr(args, "retry_interval", DEFAULT_RETRY_INTERVAL),
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
