"""Data-plane regression tests for LinkPulse.

These drive the *real* proxy server and the *real* client engine in-process on
ephemeral loopback ports.  Tests named ``test_contract_*`` encode the frozen
behaviour agreed for this iteration; a failure there is an oracle signal, never
a reason to weaken the assertion.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402
import protocol  # noqa: E402


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("MY_PROXY_TOKEN", raising=False)
    monkeypatch.delenv("MY_PROXY_SERVER", raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# HTTP data plane
# ---------------------------------------------------------------------------

def test_http_named_tunnel_round_trip(iso_env):
    async def _run():
        backend = await H.HttpBackend().start()
        server = await H.start_server(iso_env)
        spec = H.make_spec("http", backend.port, subdomain="app")
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            status, _headers, body = await H.http_roundtrip(
                server.http_port, f"app.{server.wildcard}", "/hello")
            assert status == 200, body
            assert body == b"BACKEND:GET:/hello:"
            assert len(backend.requests) == 1
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_http_auto_assigned_subdomain_round_trip(iso_env):
    async def _run():
        backend = await H.HttpBackend().start()
        server = await H.start_server(iso_env)
        spec = H.make_spec("http", backend.port)  # no subdomain -> server picks
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            rt = await H.wait_tunnel_active(client, spec.tunnel_id)
            assert rt.public_url and rt.public_url.startswith("http://")
            subdomain = rt.public_url[len("http://"):].split(".")[0]
            status, _headers, body = await H.http_roundtrip(
                server.http_port, f"{subdomain}.{server.wildcard}", "/x")
            assert status == 200 and body.startswith(b"BACKEND:GET:/x:")
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_http_unknown_host_is_immediate_404(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            t0 = time.monotonic()
            status, _headers, _body = await H.http_roundtrip(
                server.http_port, f"ghost.{server.wildcard}", "/")
            elapsed = time.monotonic() - t0
            assert status == 404
            assert elapsed < 1.0, f"unknown host took {elapsed:.2f}s"
        finally:
            await server.stop()

    asyncio.run(_run())


def test_http_root_health_endpoint(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            status, _headers, body = await H.http_roundtrip(
                server.http_port, "127.0.0.1", "/health")
            assert status == 200 and body == b"healthy\n"
        finally:
            await server.stop()

    asyncio.run(_run())


def test_contract_oversized_http_headers_return_431(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.http_port)
            huge = b"X-Pad: " + b"a" * 60000 + b"\r\n"
            writer.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" + huge + b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=5.0)
            status, _headers, _body = H.parse_http(data)
            assert status == 431, f"expected 431 for oversized headers, got {status}"
        finally:
            if writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# TCP data plane
# ---------------------------------------------------------------------------

async def _tcp_roundtrip(tcp_port: int, payload: bytes, timeout: float = 20.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
    got = bytearray()
    deadline = time.monotonic() + timeout

    async def _drain():
        while len(got) < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(65536), timeout=remaining)
            if not chunk:
                break
            got.extend(chunk)

    reader_task = asyncio.create_task(_drain())
    try:
        writer.write(payload)
        await writer.drain()
        await asyncio.wait_for(reader_task, timeout=timeout)
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
    return bytes(got)


def test_tcp_large_echo_over_flow_window(iso_env):
    async def _run():
        backend = await H.TcpEchoBackend().start()
        port = H.free_port()
        server = await H.start_server(iso_env, tcp_range=(port, port))
        spec = H.make_spec("tcp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            payload = os.urandom(600 * 1024)  # 600 KiB > one 256 KiB window
            echoed = await _tcp_roundtrip(port, payload)
            assert len(echoed) == len(payload)
            assert echoed == payload
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_tcp_600kib_echo_data_phase_within_3s(iso_env):
    """The 600 KiB transfer itself must complete well under 3 s.

    Measures only the data phase (write -> full echo) and keeps setup/cleanup
    outside the budget; teardown is bounded and records (rather than raises)
    cleanup errors so it can never mask the timing result.
    """
    async def _run():
        backend = server = client = task = None
        cleanup_errors = []
        try:
            backend = await H.TcpEchoBackend().start()
            port = H.free_port()
            server = await H.start_server(iso_env, tcp_range=(port, port))
            spec = H.make_spec("tcp", backend.port, remote_port=port)
            client, task = await H.start_client(server, iso_env, [spec])
            await H.wait_tunnel_active(client, spec.tunnel_id)

            payload = os.urandom(600 * 1024)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            got = bytearray()

            async def _drain():
                while len(got) < len(payload):
                    chunk = await reader.read(65536)
                    if not chunk:
                        break
                    got.extend(chunk)

            reader_task = asyncio.create_task(_drain())
            started = time.monotonic()
            writer.write(payload)
            await writer.drain()
            await asyncio.wait_for(reader_task, timeout=3.0)
            elapsed = time.monotonic() - started

            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

            assert bytes(got) == payload
            assert elapsed < 3.0, (
                f"600 KiB echo data phase took {elapsed:.2f}s (> 3s budget)")
        finally:
            if client is not None and task is not None:
                try:
                    await asyncio.wait_for(H.stop_client(client, task), timeout=6.0)
                except BaseException as e:
                    cleanup_errors.append(("client", repr(e)))
            if backend is not None:
                try:
                    await asyncio.wait_for(backend.stop(), timeout=3.0)
                except BaseException as e:
                    cleanup_errors.append(("backend", repr(e)))
            if server is not None:
                try:
                    await asyncio.wait_for(server.stop(), timeout=6.0)
                except BaseException as e:
                    cleanup_errors.append(("server", repr(e)))
            if cleanup_errors:
                sys.stderr.write(f"[tcp-probe cleanup] {cleanup_errors}\n")

    asyncio.run(_run())


def test_stalled_stream_does_not_block_unrelated_stream(iso_env):
    """One public peer that never reads must not freeze the whole client."""
    class StreamingBackend:
        def __init__(self):
            self.server = None
            self.port = 0

        async def start(self):
            self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            return self

        async def _handle(self, reader, writer):
            try:
                await reader.read(65536)
                writer.write(b"X" * (2 * 1024 * 1024))
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

    async def _run():
        stalled_backend = await StreamingBackend().start()
        echo_backend = await H.TcpEchoBackend().start()
        p_stall, p_echo = H.free_port(), H.free_port()
        server = await H.start_server(
            iso_env, tcp_range=(min(p_stall, p_echo), max(p_stall, p_echo)))
        spec_stall = H.make_spec("tcp", stalled_backend.port, remote_port=p_stall)
        spec_echo = H.make_spec("tcp", echo_backend.port, remote_port=p_echo)
        client, task = await H.start_client(server, iso_env, [spec_stall, spec_echo])
        try:
            await H.wait_tunnel_active(client, spec_stall.tunnel_id)
            await H.wait_tunnel_active(client, spec_echo.tunnel_id)

            # Peer A: request, then deliberately never read the reply.
            a_reader, a_writer = await asyncio.open_connection("127.0.0.1", p_stall)
            a_writer.write(b"go")
            await a_writer.drain()

            # Peer B must still get a prompt echo.
            echoed = await _tcp_roundtrip(p_echo, b"ping-pong", timeout=4.0)
            assert echoed == b"ping-pong", f"unrelated stream was blocked (got {echoed!r})"
            with contextlib.suppress(Exception):
                a_writer.close()
        finally:
            await H.stop_client(client, task)
            await stalled_backend.stop()
            await echo_backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_contract_tcp_half_close_preserves_reply(iso_env):
    """A write-half-close must be delivered as STREAM_EOF, not an abort, so the
    backend can still reply on the read half."""
    async def _run():
        backend = await H.EofReplyBackend().start()
        port = H.free_port()
        server = await H.start_server(iso_env, tcp_range=(port, port))
        spec = H.make_spec("tcp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"PING")
            await writer.drain()
            writer.write_eof()
            data = await asyncio.wait_for(reader.read(-1), timeout=6.0)
            assert data == b"REPLY-AFTER-EOF", f"half-close lost the reply (got {data!r})"
            with contextlib.suppress(Exception):
                writer.close()
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_contract_hello_ok_advertises_stream_eof_capability(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            reader, writer = await H.raw_connect(server)
            frame = await H.raw_hello(reader, writer, H.hello_payload(server.secret))
            assert frame.type == protocol.FrameType.HELLO_OK
            info = json.loads(frame.payload.decode())
            caps = info.get("capabilities")
            assert isinstance(caps, (list, tuple)), info
            assert protocol.STREAM_CAPABILITY in caps, info
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_protocol_stream_eof_frame_type_exists():
    assert int(protocol.FrameType.STREAM_EOF) == 0x0F
    assert int(protocol.FrameType.STREAM_CLOSE) == 0x0B  # legacy abort kept distinct
    assert int(protocol.FrameType.UDP_DATAGRAM) == 0x0E


# ---------------------------------------------------------------------------
# UDP data plane
# ---------------------------------------------------------------------------

async def _udp_echo(tunnel_port: int, datagram: bytes, *, timeout: float = 5.0,
                    source_port: int = 0):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(("127.0.0.1", source_port))
    try:
        await loop.sock_sendto(sock, datagram, ("127.0.0.1", tunnel_port))
        data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 70000), timeout=timeout)
        return data, addr
    finally:
        sock.close()


def test_udp_basic_echo_round_trip(iso_env):
    async def _run():
        backend = await H.UdpEchoBackend().start()
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        spec = H.make_spec("udp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            data, _addr = await _udp_echo(port, b"hello-udp")
            assert data == b"ECHO:hello-udp"
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_udp_max_size_datagram_round_trip(iso_env):
    async def _run():
        # No prefix: the reply must stay <= 65507 bytes to be a legal datagram.
        backend = await H.UdpEchoBackend(prefix=b"").start()
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        spec = H.make_spec("udp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            payload = os.urandom(65507)
            data, _addr = await _udp_echo(port, payload, timeout=8.0)
            assert data == payload
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_udp_empty_datagram_round_trip(iso_env):
    async def _run():
        # Non-empty reply (so the public probe can observe it) while the
        # *request* datagram is genuinely zero-length.
        backend = await H.UdpEchoBackend(prefix=b"OK:").start()
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        spec = H.make_spec("udp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            data, _addr = await _udp_echo(port, b"", timeout=3.0)
            assert backend.received == [b""], (
                "client did not forward the empty datagram to the local backend")
            assert data == b"OK:", f"empty datagram not forwarded (got {data!r})"
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_udp_not_limited_by_tcp_credit_window(iso_env):
    """Cumulative UDP traffic past 256 KiB must keep flowing without the
    per-stream TCP credit window."""
    async def _run():
        backend = await H.UdpEchoBackend().start()
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        spec = H.make_spec("udp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.bind(("127.0.0.1", 0))
            try:
                total = 0
                target = 300 * 1024
                deadline = time.monotonic() + 10.0
                while total < target and time.monotonic() < deadline:
                    payload = os.urandom(4096)
                    await loop.sock_sendto(sock, payload, ("127.0.0.1", port))
                    try:
                        data, _ = await asyncio.wait_for(
                            loop.sock_recvfrom(sock, 70000), timeout=1.0)
                    except asyncio.TimeoutError:
                        break
                    if data != b"ECHO:" + payload:
                        break
                    total += len(payload)
                assert total >= target, (
                    f"UDP stalled after {total} bytes (window-limited); expected >= {target}")
            finally:
                sock.close()
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_udp_distinct_peers_get_distinct_streams(iso_env):
    async def _run():
        backend = await H.UdpEchoBackend().start()
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        spec = H.make_spec("udp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            d1, _ = await _udp_echo(port, b"peer-one")
            d2, _ = await _udp_echo(port, b"peer-two")
            assert d1 == b"ECHO:peer-one" and d2 == b"ECHO:peer-two"
            await H.wait_until(lambda: len(client.streams) >= 2, timeout=3.0,
                               msg="two UDP peer streams")
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# persistence / bookkeeping
# ---------------------------------------------------------------------------

def test_storage_bookkeeping_tracks_tunnel_lifecycle(iso_env):
    async def _run():
        backend = await H.HttpBackend().start()
        server = await H.start_server(iso_env)
        spec = H.make_spec("http", backend.port, subdomain="tracked")
        client, task = await H.start_client(server, iso_env, [spec])
        db = Path(server.ctx.config["storage"]["db_path"])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)

            def _rows():
                con = sqlite3.connect(str(db))
                try:
                    return con.execute("SELECT tunnel_id, subdomain FROM tunnels").fetchall()
                finally:
                    con.close()

            await H.wait_until(
                lambda: any(r[0] == spec.tunnel_id for r in _rows()),
                msg="tunnel row persisted")
            assert (spec.tunnel_id, "tracked") in _rows()

            await H.stop_client(client, task)
            task = None
            await H.wait_until(
                lambda: all(r[0] != spec.tunnel_id for r in _rows()),
                msg="tunnel row removed on close")
        finally:
            if task is not None:
                await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_contract_duplicate_tunnel_id_is_rejected(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            reader, writer, _cid = await H.raw_session(server)
            tid = protocol.new_tunnel_id()
            _t1, first = await H.raw_open(reader, writer, subdomain="dup-one", tunnel_id=tid)
            _t2, second = await H.raw_open(reader, writer, subdomain="dup-two", tunnel_id=tid)
            assert first["status"] == "ok", first
            assert second["status"] == "error", (
                "a second tunnel with the same tunnel_id must be rejected; "
                f"got {second}")
            assert server.ctx.by_subdomain.get("dup-one") is not None
            assert server.ctx.by_subdomain.get("dup-two") is None
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_contract_tcp_stream_teardown_leaves_no_stream_state(iso_env):
    async def _run():
        backend = await H.TcpEchoBackend().start()
        port = H.free_port()
        server = await H.start_server(iso_env, tcp_range=(port, port))
        spec = H.make_spec("tcp", backend.port, remote_port=port)
        client, task = await H.start_client(server, iso_env, [spec])
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await H.wait_until(lambda: len(client.streams) >= 1, timeout=3.0,
                               msg="stream established")
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await H.wait_until(lambda: len(client.streams) == 0, timeout=4.0,
                               msg="stream teardown")
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())
