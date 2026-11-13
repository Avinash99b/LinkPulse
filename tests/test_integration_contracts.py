"""Integration contracts added by the final integration pass.

Unlike the worker-owned regression modules, these tests close cross-component
gaps that only appear when the server, client, protocol copy and deployment
surfaces are checked together:

  * the client's embedded protocol functions/constants are AST-identical to
    the canonical ``tunnel-proxy/protocol.py`` (no drift on either copy);
  * the server's fragmentation-tolerant outbound queue coalesces many small
    frames and still enforces its byte bound;
  * a public peer that half-closes its write side (a legitimate HTTP caller
    FIN) is not mistaken for a vanished caller while its request is parked;
  * a name registered to a session that is already being torn down parks the
    request instead of racing cleanup with an immediate 502;
  * the standalone loopback dashboard bounds concurrent handlers and shuts
    them down without waiting on a slow client;
  * the real TLS server context reloads a rotated certificate for both the
    public and control listeners;
  * a local backend connect that is still in progress cannot be installed
    after the stream/pending entry was closed.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import sys
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402
import protocol  # noqa: E402
import proxy_server as ps  # noqa: E402
import dashboard  # noqa: E402
import my_proxy  # noqa: E402


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(tmp_path / "logs"))
    for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER", "MY_PROXY_TLS",
                 "MY_PROXY_CA_CERT", "MY_PROXY_RETRY_INTERVAL"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# canonical protocol vs. the client's embedded copy
# ---------------------------------------------------------------------------

CANONICAL = H.SERVER_DIR / "protocol.py"
EMBEDDED = H.CLIENT_DIR / "my_proxy.py"

_SHARED_TYPES = ("Frame", "FrameType", "ProtocolError")
_SHARED_FUNCTIONS = (
    "encode_frame",
    "read_frame_header",
    "read_frame",
    "build_hello_payload",
    "new_tunnel_id",
)
_SHARED_CONSTANTS = (
    "PROTO_MAGIC",
    "PROTO_VERSION",
    "_HEADER_FMT",
    "HEADER_LEN",
    "MAX_FRAME_PAYLOAD",
    "MAX_ALLOWED_LENGTH",
    "CONTROL_STREAM_ID",
    "INITIAL_WINDOW",
    "MAX_WINDOW_CREDIT",
    "MAX_CONTROL_PAYLOAD",
    "UDP_MAX_DATAGRAM",
    "STREAM_CAPABILITY",
    "SERVER_CAPABILITIES",
    "TUNNEL_MODE_HANDOFF",
    "TUNNEL_MODE_LEASE",
    "TUNNEL_MODES",
    "_HELLO_FMT",
    "HELLO_PAYLOAD_LEN",
    "NULL_CLIENT_ID",
    "HELLO_TIMESTAMP_SKEW_SECONDS",
    "_FIXED_FRAME_SIZES",
    "_MAX_FRAME_PAYLOADS",
    "_CONTROL_PAYLOAD_TYPES",
)


def _strip_docstrings(tree: ast.Module) -> ast.Module:
    """Drop docstrings before comparing semantics, not comments."""
    class _Strip(ast.NodeTransformer):
        def _strip(self, node):
            self.generic_visit(node)
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                node.body = body[1:] or [ast.Pass()]
            return node

        def visit_FunctionDef(self, node):
            return self._strip(node)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            return self._strip(node)

    return _Strip().visit(tree)


def _definitions(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def _assignments(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            found[node.targets[0].id] = node
    return found


def _normalized(node: ast.AST) -> str:
    return ast.dump(_strip_docstrings(ast.Module(body=[node], type_ignores=[])))


def test_embedded_protocol_copy_is_ast_identical_to_canonical():
    canonical_defs = _definitions(CANONICAL)
    embedded_defs = _definitions(EMBEDDED)
    for name in _SHARED_TYPES + _SHARED_FUNCTIONS:
        assert name in canonical_defs, f"{name} missing from canonical protocol.py"
        assert name in embedded_defs, f"{name} missing from the client's protocol copy"
        assert _normalized(canonical_defs[name]) == _normalized(embedded_defs[name]), (
            f"protocol drift: {name} differs between tunnel-proxy/protocol.py and "
            f"the embedded client copy")

    canonical_consts = _assignments(CANONICAL)
    embedded_consts = _assignments(EMBEDDED)
    for name in _SHARED_CONSTANTS:
        assert name in canonical_consts, f"{name} missing from canonical protocol.py"
        assert name in embedded_consts, f"{name} missing from the client's protocol copy"
        assert (ast.dump(canonical_consts[name]) == ast.dump(embedded_consts[name])), (
            f"protocol constant drift: {name} differs between the canonical module "
            f"and the embedded client copy")


# ---------------------------------------------------------------------------
# fragmentation-tolerant outbound queue
# ---------------------------------------------------------------------------

def test_outbound_buffer_coalesces_many_small_frames_within_byte_bound():
    async def _run():
        queue = ps.OutboundBuffer()
        chunk = b"x" * 1024
        count = 300  # 300 KiB, below the 256 KiB + 64 KiB byte ceiling
        for _ in range(count):
            assert queue.put(chunk) is True
        assert queue.queued_bytes == count * len(chunk)
        # Coalescing must keep item count proportional to bytes/64 KiB, not to
        # the number of small frames (300 frames must not become 300 items).
        assert len(queue._chunks) <= 8, len(queue._chunks)

        total = 0
        while queue.queued_bytes:
            item = await queue.get()
            assert item is not ps._EOF_SENTINEL
            assert len(item) <= protocol.MAX_FRAME_PAYLOAD
            total += len(item)
        assert total == count * len(chunk)

        # The documented byte bound is still enforced exactly.
        full = ps.OutboundBuffer()
        assert full.put(b"y" * (protocol.INITIAL_WINDOW + protocol.MAX_FRAME_PAYLOAD))
        assert full.put(b"z") is False

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# reconnect waiting must preserve a legitimate public half-close
# ---------------------------------------------------------------------------

async def _serve_next_http_stream(reader, writer, body: bytes, *,
                                  half_close: bool = False) -> None:
    while True:
        frame = await H.read_frame_timeout(reader, 5.0)
        if frame.type == protocol.FrameType.STREAM_OPEN:
            sid = frame.stream_id
            break
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n" + body)
    writer.write(protocol.encode_frame(protocol.FrameType.STREAM_DATA, sid, response))
    await writer.drain()
    end_type = (protocol.FrameType.STREAM_EOF if half_close
                else protocol.FrameType.STREAM_CLOSE)
    writer.write(protocol.encode_frame(end_type, sid))
    await writer.drain()


def test_public_fin_is_not_treated_as_a_vanished_caller(iso_env):
    """An HTTP client may shutdown(SHUT_WR) while waiting for the response.

    ``_caller_gone`` is deliberately best-effort and must ignore that FIN; only
    a locally closing transport or a reader error may cancel the wait.
    """
    async def _run():
        server = await H.start_server(
            iso_env, extra_config={"http_reconnect_grace_seconds": 3})
        try:
            cid = H.new_client_id_bytes()
            first = await H.raw_session(server, client_id=cid)
            tid, resp = await H.raw_open(*first[:2], subdomain="fin",
                                         instance_id="i1")
            assert resp["status"] == "ok", resp
            await H.drop(first[1])
            await H.wait_until(lambda: "fin" not in server.ctx.by_subdomain,
                               timeout=3.0, msg="fin released")

            reader, writer = await H.send_request(
                server.http_port, f"fin.{server.wildcard}", "/half-close")
            writer.write_eof()  # legitimate public writer half-close
            pending = asyncio.create_task(reader.read(-1))
            await asyncio.sleep(0.3)
            assert not pending.done(), (
                "a public write-half-close cancelled the reconnect wait")

            second = await H.raw_session(server, client_id=cid)
            await H.raw_open(*second[:2], subdomain="fin", instance_id="i1",
                             tunnel_id=tid,
                             capabilities=[protocol.STREAM_CAPABILITY])
            await _serve_next_http_stream(second[0], second[1], b"FIN-OK",
                                          half_close=True)
            data = await asyncio.wait_for(pending, timeout=5.0)
            status, _headers, body = H.parse_http(data)
            assert status == 200 and body == b"FIN-OK"

            with contextlib.suppress(Exception):
                writer.close()
            await H.drop(second[1])
        finally:
            await server.stop()

    asyncio.run(_run())


def test_dead_owner_entry_parks_instead_of_racing_cleanup_with_502(iso_env):
    """A request that lands after ``session.alive=False`` but before the
    reconnect hint is published must wait, not fail with an immediate 502."""
    async def _run():
        server = await H.start_server(
            iso_env, extra_config={"http_reconnect_grace_seconds": 3})
        try:
            cid = H.new_client_id_bytes()
            first = await H.raw_session(server, client_id=cid)
            tid, resp = await H.raw_open(*first[:2], subdomain="racing",
                                         instance_id="i1")
            assert resp["status"] == "ok", resp
            owner, _ = server.ctx.by_subdomain["racing"]
            owner.alive = False  # cleanup has started but has not run yet

            reader, writer = await H.send_request(
                server.http_port, f"racing.{server.wildcard}", "/")
            pending = asyncio.create_task(reader.read(-1))
            await asyncio.sleep(0.3)
            assert not pending.done(), (
                "request hit the dead-session cleanup window and was rejected "
                "instead of being parked")

            second = await H.raw_session(server, client_id=cid)
            await H.raw_open(*second[:2], subdomain="racing", instance_id="i1",
                             tunnel_id=tid)
            await _serve_next_http_stream(second[0], second[1], b"RACE-OK")
            data = await asyncio.wait_for(pending, timeout=5.0)
            status, _headers, body = H.parse_http(data)
            assert status == 200 and body == b"RACE-OK"

            with contextlib.suppress(Exception):
                writer.close()
            await H.drop(first[1])
            await H.drop(second[1])
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# standalone dashboard connection bound / bounded shutdown
# ---------------------------------------------------------------------------

class _DashboardCtx:
    def __init__(self, port: int):
        self.config = {
            "dashboard": {"host": "127.0.0.1", "port": port},
            "dashboard_password": "a-long-dashboard-password",
            "jwt_secret": "a-high-entropy-jwt-secret-0123456789abcdef",
            "wildcard_domain": "example.test",
            "http_only": True,
        }
        self.clients = {}
        self.start_time = 0.0
        self.recent_logs = []


def test_standalone_dashboard_bounds_connections_and_shutdown(iso_env, monkeypatch):
    monkeypatch.setattr(dashboard, "_MAX_CONCURRENT_CONNS", 1)

    async def _run():
        port = H.free_port()
        ctx = _DashboardCtx(port)
        task = asyncio.create_task(dashboard.serve_dashboard(ctx))
        try:
            deadline = asyncio.get_running_loop().time() + 3.0
            while True:
                try:
                    first_reader, first_writer = await asyncio.open_connection(
                        "127.0.0.1", port)
                    break
                except OSError:
                    if asyncio.get_running_loop().time() >= deadline:
                        raise AssertionError("dashboard never started listening")
                    await asyncio.sleep(0.02)

            # Hold one handler with an unterminated request head.
            first_writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Partial: ")
            await first_writer.drain()

            second_reader, second_writer = await asyncio.open_connection(
                "127.0.0.1", port)
            data = await asyncio.wait_for(second_reader.read(-1), timeout=3.0)
            status, _headers, _body = H.parse_http(data)
            assert status == 503, (
                f"over-cap dashboard connection was not rejected: {data[:120]!r}")
            second_writer.close()

            # Cancelling the listener must cancel/close the still-held handler
            # instead of waiting for its per-read timeouts.
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=3.0)
            first_writer.close()
            with contextlib.suppress(Exception):
                await first_writer.wait_closed()
        finally:
            if not task.done():
                task.cancel()
                with contextlib.suppress(BaseException):
                    await task

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# real SSLContext certificate reload (public + control)
# ---------------------------------------------------------------------------

def _make_cert(tmp_path: Path, serial: int, stem: str):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not available")
    cert = tmp_path / f"{stem}-cert.pem"
    key = tmp_path / f"{stem}-key.pem"
    # Config file instead of -addext for portability (LibreSSL on macOS).
    config = tmp_path / f"{stem}-openssl.cnf"
    config.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = localhost\n"
        "[v3]\n"
        "subjectAltName = DNS:localhost,IP:127.0.0.1\n"
    )
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-set_serial", str(serial), "-config", str(config)],
        check=True, capture_output=True, timeout=60,
    )
    return cert, key


def _reload_config(kind: str, cert: Path, key: Path) -> dict:
    cfg = json.loads(json.dumps(ps.DEFAULT_CONFIG))
    cfg["shared_secret"] = "a-strong-shared-secret"
    cfg["wildcard_domain"] = "example.test"
    cfg["http_only"] = False
    cfg["tls"]["cert_path"] = str(cert)
    cfg["tls"]["key_path"] = str(key)
    if kind == "control":
        cfg["control"]["tls"] = True
        cfg["control"]["cert_path"] = str(cert)
        cfg["control"]["key_path"] = str(key)
    return cfg


@pytest.mark.parametrize("kind", ["public", "control"])
def test_certificate_reload_updates_the_live_ssl_context(iso_env, kind):
    async def _run():
        cert1, key1 = _make_cert(iso_env, 1001, f"{kind}-one")
        cert2, key2 = _make_cert(iso_env, 2002, f"{kind}-two")
        cfg = _reload_config(kind, cert1, key1)
        if kind == "control":
            ssl_ctx = ps._load_control_ssl_context(cfg)
            cert_path, key_path = str(cert1), str(key1)
        else:
            ssl_ctx = ps._load_ssl_context(cfg)
            cert_path = key_path = None
        assert ssl_ctx is not None

        server = await asyncio.start_server(
            lambda r, w: None, "127.0.0.1", 0, ssl=ssl_ctx)
        port = server.sockets[0].getsockname()[1]
        reload_task = asyncio.create_task(
            ps.cert_reload_loop(SimpleNamespace(config=cfg), ssl_ctx,
                                cert_path, key_path, interval=0.05))
        try:
            # The initial context serves certificate #1.
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=ssl.create_default_context(cafile=str(cert1)),
                server_hostname="localhost")
            first_serial = writer.get_extra_info("ssl_object").getpeercert()["serialNumber"]
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            assert first_serial == "1001" or int(first_serial, 16) == 1001

            # Rotate the files atomically; the same SSLContext must serve #2.
            os.replace(cert2, cert1)
            os.replace(key2, key1)

            last_error = None
            deadline = asyncio.get_running_loop().time() + 5.0
            while asyncio.get_running_loop().time() < deadline:
                try:
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", port,
                        ssl=ssl.create_default_context(cafile=str(cert1)),
                        server_hostname="localhost")
                except (ssl.SSLError, OSError) as e:
                    last_error = e
                    await asyncio.sleep(0.05)
                    continue
                serial = writer.get_extra_info("ssl_object").getpeercert()["serialNumber"]
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                assert int(serial, 16) == 2002, (
                    f"live SSLContext still serves serial {serial}, not the rotated one")
                return
            raise AssertionError(
                f"SSLContext did not reload the rotated certificate; last error {last_error!r}")
        finally:
            reload_task.cancel()
            with contextlib.suppress(BaseException):
                await reload_task
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# in-progress local backend connect cannot be installed after close
# ---------------------------------------------------------------------------

class _LocalWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _client(tmp_path):
    log = logging.getLogger("integration-client")
    log.addHandler(logging.NullHandler())
    log.propagate = False
    return my_proxy.TunnelClient(
        specs=[], server_host="127.0.0.1", server_port=1, secret="s",
        grace_time=1.0, state_file=tmp_path / "client-state.json",
        log=log, recent_logs=deque(maxlen=20),
    )


class _ErrorFrameCapacityServer:
    """Sends the *ERROR* frame the real server uses for capacity exhaustion."""

    def __init__(self):
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        try:
            await asyncio.wait_for(protocol.read_frame(reader), timeout=5)
            body = json.dumps({
                "error": "server at capacity",
                "reason": "capacity",
                "retryable": True,
            }).encode()
            writer.write(protocol.encode_frame(protocol.FrameType.ERROR, 0, body))
            await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()


def test_error_frame_capacity_is_retried_not_treated_as_bad_token(iso_env):
    """The real server rejects an over-capacity HELLO with an ERROR frame (not
    HELLO_FAIL); the client must treat that as retryable, never as a bad token."""
    async def _run():
        server = _ErrorFrameCapacityServer()
        await server.start()
        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = str(iso_env / "config")
        env["LINKPULSE_STATE_DIR"] = str(iso_env / "state")
        env["LINKPULSE_LOGS_DIR"] = str(iso_env / "logs")
        for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER"):
            env.pop(name, None)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(H.CLIENT_DIR / "my_proxy.py"),
            "http", "1", "--server", f"127.0.0.1:{server.port}",
            "--token", "test-secret", "--no-dashboard",
            "--state-file", str(iso_env / "client-state.json"),
            "--retry-interval", "1", "--grace-time", "1",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        try:
            await asyncio.sleep(2.5)
            alive = proc.returncode is None
            if alive:
                proc.terminate()
            out, _ = await proc.communicate()
            text = out.decode(errors="replace")
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await server.stop()
        assert alive, (
            "client exited after an ERROR-frame capacity rejection instead of "
            f"retrying; output: {text[-600:]}")
        assert "check --token" not in text, text[-600:]

    asyncio.run(_run())


def test_blocked_backend_connect_cannot_install_after_stream_close(iso_env, monkeypatch):
    async def _run():
        client = _client(iso_env)
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked_open(*_args, **_kwargs):
            entered.set()
            await release.wait()
            return None, _LocalWriter()

        monkeypatch.setattr(my_proxy.asyncio, "open_connection", blocked_open)
        spec = H.make_spec("tcp", 1)
        client.tunnels = {spec.tunnel_id: my_proxy.TunnelRuntime(spec=spec)}
        meta = json.dumps({"tunnel_id": spec.tunnel_id, "proto": "tcp"}).encode()

        # (a) A server close arrives while the local connect is genuinely
        # blocked: cancellation must win and no stream may be installed.
        sid = 21
        client._handle_stream_open(
            protocol.Frame(protocol.PROTO_VERSION, protocol.FrameType.STREAM_OPEN,
                           sid, meta))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        client._route_stream_close(
            protocol.Frame(protocol.PROTO_VERSION, protocol.FrameType.STREAM_CLOSE,
                           sid, b""))
        release.set()
        await H.wait_until(
            lambda: sid not in client.streams and sid not in client.pending_streams,
            timeout=1.0, msg="cancelled in-progress stream removed")
        assert sid not in client.streams

        # (b) Even if a close marks the pending entry without cancelling the
        # connect task, the post-await identity guard must discard the result.
        entered.clear()
        release.clear()
        sid2 = 22
        client._handle_stream_open(
            protocol.Frame(protocol.PROTO_VERSION, protocol.FrameType.STREAM_OPEN,
                           sid2, meta))
        await asyncio.wait_for(entered.wait(), timeout=1.0)
        client.pending_streams[sid2].closed = True
        release.set()
        await H.wait_until(
            lambda: sid2 not in client.streams and sid2 not in client.pending_streams,
            timeout=1.0, msg="late in-progress stream discarded")
        assert sid2 not in client.streams

    asyncio.run(_run())