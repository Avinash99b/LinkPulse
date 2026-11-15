"""Shared in-process test harness for the LinkPulse regression suite.

Owned by the regression-test workstream (new files only).  It contains NO
product logic: everything here drives the *real* server handlers and the
*real* client engine, on ephemeral loopback ports, with all persistent state
redirected under a per-test temp directory.

Design rules (see the task contract):
  * never touch global user state -- callers must point XDG_CONFIG_HOME,
    LINKPULSE_STATE_DIR and LINKPULSE_LOGS_DIR at a temp dir (the ``iso_env``
    fixture in each test module does this);
  * every listener/client task is created with asyncio.create_task and torn
    down (and awaited) before the sqlite Storage is closed;
  * all network helpers use bounded timeouts so a missing feature fails fast
    instead of hanging the suite.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import itertools
import json
import logging
import os
import socket
import struct
import sys
import time
import uuid
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = ROOT / "tunnel-proxy"
CLIENT_DIR = ROOT / "my_proxy_client"
for _p in (str(SERVER_DIR), str(CLIENT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import protocol  # noqa: E402
import proxy_server as ps  # noqa: E402
import my_proxy  # noqa: E402

# A deliberately strong (non-placeholder) shared secret for tests.
STRONG_SECRET = "s3cr3t-9f2a-41c7-b0d6-strong-test-token"
WILDCARD = "tunnel.test"


# ---------------------------------------------------------------------------
# sockets / ports
# ---------------------------------------------------------------------------

def free_port(socktype: int = socket.SOCK_STREAM) -> int:
    """Pick a currently-free loopback port (not reserved)."""
    with socket.socket(socket.AF_INET, socktype) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PORT_SEQ = itertools.count()


def _default_ranges():
    """Give each in-process server its own 100-port window.

    Avoids cross-test collisions when several harness servers are alive in one
    pytest process (and keeps parallel runs safer) without probing a huge
    range inside the event loop.
    """
    base = 41000 + (next(_PORT_SEQ) % 40) * 100
    return (base, base + 99)


async def _cancel_tasks(tasks):
    """Cancel and await a set of helper tasks/transports (bounded)."""
    pending = [t for t in list(tasks) if not t.done()]
    tasks.clear()
    for t in pending:
        t.cancel()
    if pending:
        try:
            await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), timeout=5.0)
        except asyncio.TimeoutError:
            for t in pending:
                t.cancel()


# ---------------------------------------------------------------------------
# server harness
# ---------------------------------------------------------------------------

class ServerHarness:
    """A real proxy_server started in-process on ephemeral ports."""

    def __init__(self, ctx, control, http):
        self.ctx = ctx
        self.control = control
        self.http = http
        self.control_port = control.sockets[0].getsockname()[1]
        self.http_port = http.sockets[0].getsockname()[1]
        self.wildcard = ctx.config["wildcard_domain"]
        self.secret = ctx.config["shared_secret"]
        self._stopped = False

    def public_url(self, subdomain: str) -> str:
        return f"http://{subdomain}.{self.wildcard}"

    async def stop(self):
        if self._stopped:
            return
        self._stopped = True
        _dbg = os.environ.get("LP_HARNESS_DEBUG")
        _t0 = time.monotonic()

        def _mark(label):
            if _dbg:
                sys.stderr.write(f"[harness.stop] {label}: {((time.monotonic() - _t0) * 1000):.0f} ms\n")
                sys.stderr.flush()

        _mark("begin")

        # Cancel *and await* every handler task created via ctx.spawn, then any
        # per-session tasks they own, recording (not hiding) unexpected errors.
        async def _drain(tasks):
            tasks = [t for t in tasks if not t.done()]
            for t in tasks:
                t.cancel()
            if tasks:
                try:
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True), timeout=5.0)
                except asyncio.TimeoutError:
                    for t in tasks:
                        t.cancel()
                    results = []
                for result in results:
                    if (isinstance(result, Exception)
                            and not isinstance(result, asyncio.CancelledError)):
                        sys.stderr.write(f"[harness] handler teardown error: {result!r}\n")

        # 1. Stop accepting new connections.
        for srv in (self.control, self.http):
            with contextlib.suppress(Exception):
                srv.close()
        # 2. Close session writers so handlers blocked in a read wake up; a
        #    still-open control handler would otherwise make wait_closed() block
        #    until its own timeout.
        for sessions in list(self.ctx.clients.values()):
            for sess in list(sessions):
                with contextlib.suppress(Exception):
                    sess.writer.close()
        _mark("session_writers_closed")
        # 3. Cancel handlers so their cleanup (tunnel/stream teardown) runs.
        await _drain(list(self.ctx.tasks))
        _mark("ctx_tasks_drained")
        leftovers = []
        for sessions in list(self.ctx.clients.values()):
            for sess in list(sessions):
                leftovers.extend(sess.tasks)
        await _drain(leftovers)
        _mark("session_tasks_drained")
        self.ctx.tasks.clear()
        # 4. Now listeners can finish; bound the wait so a stray handler can
        #    never stall teardown indefinitely.
        for name, srv in (("control", self.control), ("http", self.http)):
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(srv.wait_closed(), timeout=3.0)
            _mark(f"{name}_closed")
        await asyncio.sleep(0)

        # 5. Only now is it safe to close storage.
        with contextlib.suppress(Exception):
            self.ctx.storage.close()
        _mark("storage_closed")


async def start_server(tmp_path, *, secret: str = STRONG_SECRET, wildcard: str = WILDCARD,
                       tcp_range=None, udp_range=None,
                       heartbeat_interval: int = 20, heartbeat_timeout: int = 60,
                       http_only: bool = True, extra_config: dict | None = None,
                       control_tls: bool = False, control_cert: str | None = None,
                       control_key: str | None = None) -> ServerHarness:
    """Start the real server handlers on ephemeral loopback ports.

    ``extra_config`` is merged into the config dict -- used by contract tests
    to set frozen knobs such as ``http_reconnect_grace_seconds``.
    """
    if tcp_range is None:
        tcp_range = _default_ranges()
    if udp_range is None:
        udp_range = _default_ranges()
    cfg = json.loads(json.dumps(ps.DEFAULT_CONFIG))
    cfg["shared_secret"] = secret
    cfg["wildcard_domain"] = wildcard
    cfg["http_only"] = http_only
    cfg["storage"]["db_path"] = str(Path(tmp_path) / f"server-{uuid.uuid4().hex[:8]}.db")
    for section in ("control", "http", "dashboard"):
        cfg[section]["host"] = "127.0.0.1"
        cfg[section]["port"] = 0
    cfg["tcp"]["port_range"] = list(tcp_range)
    cfg["tcp"]["bind_host"] = "127.0.0.1"
    cfg["udp"]["port_range"] = list(udp_range)
    cfg["udp"]["bind_host"] = "127.0.0.1"
    cfg["heartbeat_interval_seconds"] = heartbeat_interval
    cfg["heartbeat_timeout_seconds"] = heartbeat_timeout
    cfg["control"]["tls"] = bool(control_tls)
    if control_cert:
        cfg["control"]["cert_path"] = control_cert
    if control_key:
        cfg["control"]["key_path"] = control_key
    if extra_config:
        cfg.update(extra_config)

    control_ssl = None
    if control_tls:
        control_ssl = ps._load_control_ssl_context(cfg)

    ctx = ps.ServerContext(cfg)
    # Track accepted handlers as ctx tasks so teardown can cancel and await them
    # before the sqlite connection is closed.
    control = await asyncio.start_server(
        lambda r, w: ctx.spawn(ps.handle_control_connection(r, w, ctx)),
        "127.0.0.1", 0, ssl=control_ssl,
    )
    http = await asyncio.start_server(
        lambda r, w: ctx.spawn(ps.handle_public_http_conn(r, w, ctx, is_https=False)),
        "127.0.0.1", 0
    )
    return ServerHarness(ctx, control, http)


# ---------------------------------------------------------------------------
# client harness
# ---------------------------------------------------------------------------

def make_spec(type_: str, local_port: int, *, subdomain=None, remote_port=None,
              mode: str = my_proxy.TUNNEL_MODE_HANDOFF, tunnel_id=None,
              local_host: str = "127.0.0.1") -> "my_proxy.TunnelSpec":
    return my_proxy.TunnelSpec(
        tunnel_id=tunnel_id or my_proxy.new_tunnel_id(),
        type=type_, local_host=local_host, local_port=local_port,
        subdomain=subdomain, remote_port=remote_port, mode=mode,
    )


async def start_client(server: ServerHarness, tmp_path, specs, *,
                       secret: str | None = None, retry_interval: float = 1.0,
                       state_name: str | None = None, grace_time: float = 5.0,
                       client_id: str | None = None, tls: bool = False,
                       ca_cert: str | None = None):
    """Start the real client engine against the harnessed server."""
    log = logging.getLogger(f"lp-test-client-{uuid.uuid4().hex[:6]}")
    log.addHandler(logging.NullHandler())
    log.propagate = False
    recent = deque(maxlen=200)
    client = my_proxy.TunnelClient(
        specs=list(specs), server_host="127.0.0.1", server_port=server.control_port,
        secret=secret or server.secret, grace_time=grace_time,
        state_file=Path(tmp_path) / (state_name or f"client-{uuid.uuid4().hex[:6]}.json"),
        log=log, recent_logs=recent, retry_interval=retry_interval,
        client_id=client_id, tls=tls, ca_cert=ca_cert,
    )
    task = asyncio.create_task(client.run())
    return client, task


async def wait_tunnel_active(client, tunnel_id: str, timeout: float = 8.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        rt = client.tunnels.get(tunnel_id)
        if rt is not None and rt.status == "active":
            return rt
        await asyncio.sleep(0.02)
    rt = client.tunnels.get(tunnel_id)
    raise AssertionError(
        f"tunnel {tunnel_id[:8]} never became active "
        f"(status={getattr(rt, 'status', None)}, error={getattr(rt, 'error', None)})"
    )


async def wait_until(predicate, timeout: float = 8.0, interval: float = 0.02, msg: str = "condition"):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    raise AssertionError(f"timed out waiting for {msg}")


async def stop_client(client, task):
    # Bound both legs: request_shutdown can block on a stalled control writer,
    # and a cancelled run task may take a moment to unwind.
    with contextlib.suppress(BaseException):
        await asyncio.wait_for(client.request_shutdown(), timeout=2.0)
    if not task.done():
        task.cancel()
    with contextlib.suppress(BaseException):
        await asyncio.wait_for(task, timeout=5.0)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def parse_http(data: bytes):
    if not data:
        return 0, {}, b""
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return status, headers, body


async def send_request(port: int, host: str, path: str = "/", method: str = "GET",
                       body: bytes = b"", extra_headers: bytes = b""):
    """Open a public HTTP request and return the live (reader, writer)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n".encode("latin-1")
    if extra_headers:
        head += extra_headers
    if body:
        head += f"Content-Length: {len(body)}\r\n".encode("latin-1")
    head += b"Connection: close\r\n\r\n"
    writer.write(head + body)
    await writer.drain()
    return reader, writer


async def read_response(reader, timeout: float = 8.0):
    data = await asyncio.wait_for(reader.read(-1), timeout=timeout)
    return parse_http(data)


async def http_roundtrip(port: int, host: str, path: str = "/", method: str = "GET",
                         body: bytes = b"", timeout: float = 8.0):
    reader, writer = await send_request(port, host, path, method, body)
    try:
        return await read_response(reader, timeout=timeout)
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


# ---------------------------------------------------------------------------
# backends (local services the client forwards to)
# ---------------------------------------------------------------------------

class HttpBackend:
    """Records every request it receives and answers 200 with a marker body."""

    def __init__(self, marker: str = "BACKEND", status: int = 200):
        self.marker = marker
        self.status = status
        self.requests = []
        self.server = None
        self.port = 0
        self._tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _accept(self, reader, writer):
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=8)
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
            return
        try:
            method, path = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)[:2]
        except Exception:
            method, path = "?", "?"
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                with contextlib.suppress(ValueError):
                    clen = int(line.split(b":", 1)[1])
        body = b""
        if clen:
            with contextlib.suppress(Exception):
                body = await asyncio.wait_for(reader.readexactly(clen), timeout=8)
        self.requests.append((method, path, body))
        payload = f"{self.marker}:{method}:{path}:".encode() + body
        writer.write(
            f"HTTP/1.1 {self.status} OK\r\nContent-Type: text/plain\r\n".encode()
            + f"Content-Length: {len(payload)}\r\n".encode()
            + b"Connection: close\r\n\r\n" + payload
        )
        with contextlib.suppress(Exception):
            await writer.drain()
        with contextlib.suppress(Exception):
            writer.close()

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()
        await _cancel_tasks(self._tasks)


class TcpEchoBackend:
    """Echoes every byte back to the sender until EOF."""

    def __init__(self):
        self.server = None
        self.port = 0
        self.received = bytearray()
        self._tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _accept(self, reader, writer):
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader, writer):
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                self.received += chunk
                writer.write(chunk)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()
        await _cancel_tasks(self._tasks)


class EofReplyBackend:
    """Reads until the peer half-closes, then writes a fixed reply.

    Only works if the client honours a *directional* half-close (STREAM_EOF):
    with an abortive close the reply has nowhere to go.
    """

    def __init__(self, reply: bytes = b"REPLY-AFTER-EOF"):
        self.reply = reply
        self.server = None
        self.port = 0
        self.received = bytearray()
        self.saw_eof = asyncio.Event()
        self._tasks = set()

    async def start(self):
        self.server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _accept(self, reader, writer):
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader, writer):
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                self.received += chunk
            self.saw_eof.set()
            writer.write(self.reply)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()
        await _cancel_tasks(self._tasks)


class UdpEchoBackend(asyncio.DatagramProtocol):
    """Echoes every datagram, optionally prefixed."""

    def __init__(self, prefix: bytes = b"ECHO:"):
        self.prefix = prefix
        self.transport = None
        self.received = []
        self.port = 0
        self.last_peer = None

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=("127.0.0.1", 0)
        )
        self.transport = transport
        self.port = transport.get_extra_info("sockname")[1]
        return self

    def datagram_received(self, data, addr):
        self.received.append(bytes(data))
        self.last_peer = addr
        self.transport.sendto(self.prefix + data, addr)

    def send_raw(self, data: bytes, addr=None):
        """Push an exact datagram (including an empty one) back to a peer."""
        target = addr or self.last_peer
        if target is not None and self.transport is not None:
            self.transport.sendto(data, target)

    def error_received(self, exc):
        pass

    async def stop(self):
        if self.transport is not None:
            self.transport.close()


# ---------------------------------------------------------------------------
# raw control-channel helpers (handshake / protocol / grace tests)
# ---------------------------------------------------------------------------

async def raw_connect(server: ServerHarness, *, ssl_ctx=None, server_hostname=None):
    return await asyncio.open_connection(
        "127.0.0.1", server.control_port, ssl=ssl_ctx, server_hostname=server_hostname
    )


def hello_payload(secret: str, client_id_bytes: bytes = protocol.NULL_CLIENT_ID,
                  ts: int | None = None, nonce: bytes | None = None) -> bytes:
    ts = int(time.time()) if ts is None else ts
    nonce = nonce if nonce is not None else os.urandom(16)
    mac = hmac.new(secret.encode(), client_id_bytes + struct.pack("!Q", ts) + nonce,
                   hashlib.sha256).digest()
    return struct.pack("!16sQ16s32s", client_id_bytes, ts, nonce, mac)


async def raw_hello(reader, writer, payload: bytes):
    writer.write(protocol.encode_frame(protocol.FrameType.HELLO, 0, payload))
    await writer.drain()
    return await asyncio.wait_for(protocol.read_frame(reader), timeout=5)


async def read_frame_timeout(reader, timeout: float = 5.0):
    return await asyncio.wait_for(protocol.read_frame(reader), timeout=timeout)


async def raw_session(server, *, client_id: bytes | None = None):
    """Authenticate a raw control session. Returns (reader, writer, client_id_hex)."""
    reader, writer = await raw_connect(server)
    frame = await raw_hello(reader, writer,
                            hello_payload(server.secret, client_id or protocol.NULL_CLIENT_ID))
    assert frame.type == protocol.FrameType.HELLO_OK, frame
    info = json.loads(frame.payload.decode())
    return reader, writer, info["client_id"]


async def raw_open(reader, writer, *, ttype: str = "http", subdomain=None, remote_port=None,
                   mode: str = protocol.TUNNEL_MODE_HANDOFF, instance_id=None,
                   tunnel_id=None, capabilities=None):
    """Send a TUNNEL_OPEN_REQUEST and read its TUNNEL_OPEN_RESPONSE."""
    req = {"tunnel_id": tunnel_id or protocol.new_tunnel_id(), "type": ttype, "mode": mode}
    if instance_id is not None:
        req["instance_id"] = instance_id
    if subdomain is not None:
        req["subdomain"] = subdomain
    if remote_port is not None:
        req["remote_port"] = remote_port
    if capabilities is not None:
        req["capabilities"] = capabilities
    writer.write(protocol.encode_frame(
        protocol.FrameType.TUNNEL_OPEN_REQUEST, 0, json.dumps(req).encode()))
    await writer.drain()
    frame = await read_frame_timeout(reader)
    return req["tunnel_id"], json.loads(frame.payload.decode())


async def raw_close(writer, tunnel_id: str):
    writer.write(protocol.encode_frame(
        protocol.FrameType.TUNNEL_CLOSE, 0, json.dumps({"tunnel_id": tunnel_id}).encode()))
    await writer.drain()


def new_client_id_bytes() -> bytes:
    return uuid.uuid4().bytes


async def drop(writer):
    """Abruptly drop a raw connection (simulates an unexpected disconnect)."""
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()
