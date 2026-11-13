"""Server edge-case regression tests (second pass).

Targets gaps found in whole-file review that the first pass did not cover:
  * UDP idle reaping must use one clock (maintenance passes monotonic while
    ``last_activity`` is wall-clock);
  * a queued response must be flushed before a stream is closed when both
    directions hit EOF while the public writer is blocked;
  * a pump blocked on zero send credit must stop as soon as the stream is
    aborted, not only when the whole client is cleaned up;
  * many small legitimate STREAM_DATA frames must not trip the fixed 8-slot
    per-stream queue;
  * a legacy UDP STREAM_CLOSE must free the peer mapping and client endpoint;
  * a UDP bind failure must not report "ok" or leave a registry entry;
  * the pending-HTTP cap must count accepted sockets before headers parse;
  * unknown hosts stay 404 even with the wait queue at capacity;
  * shutdown must not close storage under live handler tasks.

These use the real server code with minimal event-driven fakes (no sleeps used
as ordering guarantees).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402
import protocol  # noqa: E402
import proxy_server as ps  # noqa: E402


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("MY_PROXY_TOKEN", raising=False)
    monkeypatch.delenv("MY_PROXY_SERVER", raising=False)
    return tmp_path


class SinkWriter:
    """Minimal control-connection writer (records bytes, never blocks)."""

    def __init__(self):
        self.buffer = bytearray()
        self.closed = False

    def write(self, data):
        self.buffer += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    async def wait_closed(self):
        pass

    def get_extra_info(self, name, default=None):
        return ("127.0.0.1", 12345)


class BlockingPublicWriter:
    """Public socket writer whose drain blocks until an event is released."""

    def __init__(self):
        self.allow = asyncio.Event()
        self.drain_entered = asyncio.Event()
        self.pending = bytearray()
        self.delivered = bytearray()
        self.closed = False
        self.closed_with: bytes | None = None
        self.eof_after: bytes | None = None

    def write(self, data):
        self.pending += bytes(data)

    async def drain(self):
        self.drain_entered.set()
        await self.allow.wait()
        self.delivered += self.pending
        self.pending.clear()

    def close(self):
        self.closed = True
        self.closed_with = bytes(self.delivered)

    def is_closing(self):
        return self.closed

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof_after = bytes(self.delivered)

    def get_extra_info(self, name, default=None):
        return ("127.0.0.1", 12345)


class NeverReader:
    async def read(self, n):
        await asyncio.Event().wait()


def _ctx(tmp_path):
    cfg = json.loads(json.dumps(ps.DEFAULT_CONFIG))
    cfg["storage"]["db_path"] = str(tmp_path / "edge.db")
    cfg["http_only"] = True
    return ps.ServerContext(cfg)


def _session(client_id="a" * 32):
    return ps.ClientSession(client_id, None, SinkWriter())


# ---------------------------------------------------------------------------
# UDP idle expiry must be clock-consistent
# ---------------------------------------------------------------------------

class FakeTime:
    def __init__(self, wall: float, mono: float):
        self.wall = wall
        self.mono = mono

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, delta: float):
        self.wall += delta
        self.mono += delta


def test_udp_idle_reap_is_clock_consistent(tmp_path, monkeypatch):
    """Production uses ``time.monotonic()`` for maintenance but stores
    ``last_activity`` from ``time.time()``, so idle peers are never reaped.
    Drive the real datagram handler under a controlled clock (wall epoch far
    from monotonic, as in production) and require reaping after the idle
    timeout."""
    fake = FakeTime(wall=1_700_000_000.0, mono=1_000.0)
    monkeypatch.setattr(ps, "time", fake)

    async def _run():
        ctx = _ctx(tmp_path)
        try:
            session = _session()
            tunnel = ps.TunnelInfo(tunnel_id="t" * 16, type="udp",
                                   remote_port=23456, udp_streams={})
            session.tunnels[tunnel.tunnel_id] = tunnel
            ctx.clients[session.client_id] = {session}
            peer = ("198.51.100.7", 5555)
            await ps.handle_udp_public_datagram(session, tunnel, b"x", peer, ctx)
            assert len(session.streams) == 1

            fake.advance(ctx.limits["udp_idle_timeout"] + 1)
            await ps._reap_idle_udp(ctx, fake.monotonic())
            assert session.streams == {}, (
                "idle UDP peer was not reaped: last_activity and the reap clock "
                "disagree (wall-clock vs monotonic)")
            assert tunnel.udp_streams == {}
        finally:
            ctx.storage.close()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# queued response must flush before close on EOF
# ---------------------------------------------------------------------------

def test_queued_response_flushes_before_close_on_both_eof():
    async def _run():
        session = _session()
        session.supports_stream_eof = True
        session.stream_write_timeout = 30.0
        tunnel = ps.TunnelInfo(tunnel_id="t" * 16, type="tcp")
        pub_reader = asyncio.StreamReader()
        writer = BlockingPublicWriter()
        await ps.open_new_stream(session, tunnel, pub_reader, writer,
                                 b"", "tcp", ("127.0.0.1", 1), SimpleNamespace())
        stream = next(iter(session.streams.values()))
        sid = stream.stream_id

        # Enqueue a response, then *wait* until the writer is genuinely blocked
        # inside drain() before delivering either EOF.
        await ps.handle_stream_data(
            session,
            protocol.Frame(protocol.PROTO_VERSION, protocol.FrameType.STREAM_DATA,
                           sid, b"RESPONSE-BODY"),
            SimpleNamespace())
        await asyncio.wait_for(writer.drain_entered.wait(), timeout=1.0)

        await ps.handle_stream_eof_from_client(
            session,
            protocol.Frame(protocol.PROTO_VERSION, protocol.FrameType.STREAM_EOF,
                           sid, b""),
            SimpleNamespace())
        pub_reader.feed_eof()    # pump drains the public side -> server_eof
        await H.wait_until(
            lambda: stream.server_eof and stream.client_eof,
            timeout=1.0, msg="both EOF directions processed")

        # The writer is still blocked with a queued response: teardown must not
        # close/abort it yet.
        assert not stream.closed, (
            "stream was finalized while a queued response was still blocked in drain()")

        writer.allow.set()       # release the blocked public drain
        await H.wait_until(
            lambda: b"RESPONSE-BODY" in (writer.eof_after or b"")
            or b"RESPONSE-BODY" in (writer.closed_with or b""),
            timeout=2.0, msg="queued response flushed")
        for t in (stream.writer_task, stream.pump_task):
            if t is not None and not t.done():
                t.cancel()
        await asyncio.gather(
            *[t for t in (stream.writer_task, stream.pump_task) if t is not None],
            return_exceptions=True)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# zero-credit pump stops promptly on stream abort
# ---------------------------------------------------------------------------

def test_zero_credit_pump_stops_on_stream_abort():
    async def _run():
        session = _session()
        session.stream_write_timeout = 30.0
        tunnel = ps.TunnelInfo(tunnel_id="t" * 16, type="tcp")
        pub_reader = asyncio.StreamReader()
        writer = BlockingPublicWriter()
        await ps.open_new_stream(session, tunnel, pub_reader, writer,
                                 b"", "tcp", ("127.0.0.1", 1), SimpleNamespace())
        stream = next(iter(session.streams.values()))
        pump = stream.pump_task
        assert pump is not None

        # Drive the pump into a zero-credit wait, then abort the stream.
        stream.send_window.consume(stream.send_window.available)
        pub_reader.feed_data(b"x" * 16)
        for _ in range(20):
            await asyncio.sleep(0)
            if not stream.send_window.available:
                break
        await ps.abort_stream(session, stream)

        try:
            await asyncio.wait_for(asyncio.shield(pump), timeout=1.0)
        except asyncio.CancelledError:
            pass  # abort cancelled the blocked pump -> exactly the fix required
        except asyncio.TimeoutError:
            raise AssertionError(
                "pump blocked on zero credit did not stop when the stream was aborted")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# many small legitimate STREAM_DATA frames
# ---------------------------------------------------------------------------

def test_small_stream_frames_do_not_trip_eight_slot_queue():
    async def _run():
        session = _session()
        tunnel = ps.TunnelInfo(tunnel_id="t" * 16, type="tcp")
        pub_reader = asyncio.StreamReader()
        writer = BlockingPublicWriter()
        await ps.open_new_stream(session, tunnel, pub_reader, writer,
                                 b"", "tcp", ("127.0.0.1", 1), SimpleNamespace())
        stream = next(iter(session.streams.values()))
        sid = stream.stream_id

        frames = 12
        chunk = b"z" * 1024
        for _ in range(frames):
            await ps.handle_stream_data(
                session,
                protocol.Frame(protocol.PROTO_VERSION,
                               protocol.FrameType.STREAM_DATA, sid, chunk),
                SimpleNamespace())

        assert not stream.closed, (
            f"{frames} x 1KiB frames are far below the 256KiB window but "
            "tripped a fixed frame-count limit")
        writer.allow.set()
        await H.wait_until(
            lambda: len(writer.pending) + len(writer.delivered) >= frames * len(chunk),
            timeout=3.0, msg="all small frames delivered")
        for t in (stream.writer_task, stream.pump_task):
            if t is not None and not t.done():
                t.cancel()
        await asyncio.gather(
            *[t for t in (stream.writer_task, stream.pump_task) if t is not None],
            return_exceptions=True)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# legacy UDP STREAM_CLOSE frees the peer mapping and stream
# ---------------------------------------------------------------------------

def test_legacy_udp_stream_close_frees_peer_and_stream(iso_env):
    async def _run():
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            reader, writer, _cid = await H.raw_session(server)
            tid, resp = await H.raw_open(reader, writer, ttype="udp", remote_port=port)
            assert resp["status"] == "ok", resp
            # A legacy peer does NOT advertise stream_eof (raw_open default).
            await asyncio.get_running_loop().sock_sendto(
                sock, b"hello", ("127.0.0.1", port))

            sid = None
            for _ in range(4):
                frame = await H.read_frame_timeout(reader, 2.0)
                if frame.type == protocol.FrameType.STREAM_OPEN:
                    sid = frame.stream_id
                    break
            assert sid is not None, "no STREAM_OPEN for the UDP peer"

            writer.write(protocol.encode_frame(frame_type=protocol.FrameType.STREAM_CLOSE,
                                               stream_id=sid))
            await writer.drain()

            session, tunnel_id = server.ctx.by_udp_port[port]
            tunnel = session.tunnels[tunnel_id]
            await H.wait_until(lambda: sid not in session.streams, timeout=1.0,
                               msg="legacy UDP STREAM_CLOSE removed the stream")
            assert tunnel.udp_streams == {}, "legacy UDP close leaked the peer mapping"
            writer.close()
        finally:
            sock.close()
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# zero-length datagram direction probes (server vs client)
# ---------------------------------------------------------------------------

def test_server_forwards_zero_length_datagram_to_client(iso_env):
    """Isolate the server: an empty public datagram must reach the tunnel as a
    zero-length UDP_DATAGRAM frame (no real client involved)."""
    async def _run():
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        try:
            reader, writer, _cid = await H.raw_session(server)
            _tid, resp = await H.raw_open(reader, writer, ttype="udp", remote_port=port)
            assert resp["status"] == "ok", resp
            await asyncio.get_running_loop().sock_sendto(
                sock, b"", ("127.0.0.1", port))

            saw_empty = False
            for _ in range(4):
                frame = await H.read_frame_timeout(reader, 2.0)
                if (frame.type == protocol.FrameType.UDP_DATAGRAM
                        and frame.payload == b""):
                    saw_empty = True
                    break
            assert saw_empty, "server did not forward the zero-length datagram"
            writer.close()
        finally:
            sock.close()
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# established UDP stream refuses TCP STREAM_DATA; server credit is capped
# ---------------------------------------------------------------------------

def test_established_udp_stream_refuses_tcp_stream_data(iso_env):
    async def _run():
        port = H.free_port(socket.SOCK_DGRAM)
        server = await H.start_server(iso_env, udp_range=(port, port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        loop = asyncio.get_running_loop()
        try:
            reader, writer, _cid = await H.raw_session(server)
            _tid, resp = await H.raw_open(reader, writer, ttype="udp", remote_port=port)
            assert resp["status"] == "ok", resp
            await loop.sock_sendto(sock, b"first", ("127.0.0.1", port))
            sid = None
            for _ in range(4):
                frame = await H.read_frame_timeout(reader, 2.0)
                if frame.type == protocol.FrameType.STREAM_OPEN:
                    sid = frame.stream_id
                    break
            assert sid is not None

            # A TCP STREAM_DATA frame on a UDP stream must be refused, not
            # interpreted as data.
            writer.write(protocol.encode_frame(
                protocol.FrameType.STREAM_DATA, sid, b"not-a-datagram"))
            await writer.drain()

            await loop.sock_sendto(sock, b"second", ("127.0.0.1", port))
            found = False
            for _ in range(5):
                frame = await H.read_frame_timeout(reader, 2.0)
                if (frame.type == protocol.FrameType.UDP_DATAGRAM
                        and frame.payload == b"second"):
                    found = True
                    break
            assert found, "UDP stream was corrupted by a stray TCP frame"
            writer.close()
        finally:
            sock.close()
            await server.stop()

    asyncio.run(_run())


def test_server_flow_window_replenish_is_capped():
    window = ps.FlowWindow(initial=0)
    for _ in range(ps.MAX_WINDOW_CREDIT + 5000):
        window.replenish(1)
    assert window.available <= ps.MAX_WINDOW_CREDIT


# ---------------------------------------------------------------------------
# UDP bind failure must not register the tunnel
# ---------------------------------------------------------------------------

def test_udp_bind_failure_does_not_report_ok_or_leak_registry(iso_env):
    port = H.free_port(socket.SOCK_DGRAM)

    async def _run():
        server = await H.start_server(iso_env, extra_config={
            "udp": {"port_range": [port, port], "bind_host": "203.0.113.1"},
        })
        try:
            reader, writer, _cid = await H.raw_session(server)
            _tid, resp = await H.raw_open(reader, writer, ttype="udp", remote_port=port)
            await asyncio.sleep(0.2)   # let the spawned bind attempt run
            assert resp["status"] == "error", (
                f"UDP bind to an unassignable address must fail, got {resp}")
            assert port not in server.ctx.by_udp_port, (
                "a failed UDP bind left a registry entry behind")
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# pending-HTTP cap must cover unparsed headers
# ---------------------------------------------------------------------------

def test_pending_http_cap_includes_unparsed_headers(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config={
            "limits": {"max_pending_http_connections": 1},
        })
        conns = []
        try:
            for _ in range(2):
                r, w = await asyncio.open_connection("127.0.0.1", server.http_port)
                # Partial head: never terminated, so the handler is still parsing.
                w.write(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Partial: ")
                await w.drain()
                conns.append((r, w))

            async def _probe(reader):
                try:
                    return await asyncio.wait_for(reader.read(256), timeout=1.5)
                except asyncio.TimeoutError:
                    return None

            results = await asyncio.gather(_probe(conns[0][0]), _probe(conns[1][0]))
            # Either an immediate close (b"") or an explicit 503 is a valid
            # bounded rejection; only "still open" (None) is a failure.
            rejected = [r for r in results if r is not None]
            assert rejected, (
                "the pending-HTTP cap ignored connections whose headers are not "
                "yet parsed; both sockets stayed open")
            assert any(r == b"" or b"503" in r for r in rejected), rejected
        finally:
            for _r, w in conns:
                with contextlib.suppress(Exception):
                    w.close()
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# unknown host stays 404 even when the wait queue is at capacity
# ---------------------------------------------------------------------------

def test_unknown_name_is_404_even_when_wait_queue_full(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config={
            "http_reconnect_grace_seconds": 8,
            "http_reconnect_max_waiters": 1,
        })
        try:
            # Saturate the *reconnect-wait* quota (not the global accepted-socket
            # admission cap, which must keep protecting against DoS).
            server.ctx.reconnect_waiters_total = 1
            assert server.ctx.pending_http == 0
            status, _h, _b = await H.http_roundtrip(
                server.http_port, f"never-seen.{server.wildcard}", "/", timeout=3.0)
            assert status == 404, (
                f"unknown hosts must stay an immediate 404, got {status}")
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# shutdown must not close storage under live handlers
# ---------------------------------------------------------------------------

def test_shutdown_completes_cleanly_with_a_live_control_connection(iso_env):
    control = H.free_port()
    http = H.free_port()
    https = H.free_port()
    dashboard = H.free_port()
    env = os.environ.copy()
    env.update({
        "SHARED_SECRET": "a-strong-shared-secret",
        "WILDCARD_DOMAIN": "tunnel.example.test",
        "DASHBOARD_PASSWORD": "a-long-dashboard-password",
        "JWT_SECRET": "a-high-entropy-jwt-secret-0123456789abcdef",
        "HTTP_ONLY": "true",
        "CONTROL_PORT": str(control),
        "HTTP_PORT": str(http),
        "HTTPS_PORT": str(https),
        "DASHBOARD_PORT": str(dashboard),
        "DB_PATH": str(iso_env / "shutdown.db"),
        "LOG_FILE": str(iso_env / "shutdown.log"),
        "LOG_LEVEL": "INFO",
    })
    proc = subprocess.Popen(
        [sys.executable, "proxy_server.py"],
        cwd=str(H.SERVER_DIR), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", control), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("server did not start listening")

        # Leave an accepted handler mid-frame (partial header).
        partial = socket.create_connection(("127.0.0.1", control), timeout=1)
        partial.sendall(b"TN\x01")
        time.sleep(0.05)

        proc.send_signal(signal.SIGTERM)
        try:
            out, _ = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            raise AssertionError(
                "server did not complete shutdown within 20s with an accepted "
                f"handler still open; output: {out[-1500:]}")
    finally:
        with contextlib.suppress(Exception):
            partial.close()
        if proc.poll() is None:
            proc.kill()
            out, _ = proc.communicate()

    assert proc.returncode == 0, out[-1000:]
    assert "Shutdown complete" in out
    lowered = out.lower()
    assert "closed database" not in lowered and "cannot operate on a closed database" not in lowered