"""Client edge-case regression tests (third pass).

Independent oracles for the remaining client gaps found in whole-file review.
No source is monkeypatched to change behaviour; where a test needs to simulate
an unreadable platform value it substitutes the *helper* (a test double), and
otherwise it drives real code paths with event-controlled minimal fakes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import stat
import struct
import subprocess
import sys
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402
import protocol  # noqa: E402
import my_proxy  # noqa: E402


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    state_dir = tmp_path / "state"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(state_dir))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(tmp_path / "logs"))
    for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER", "MY_PROXY_TLS",
                 "MY_PROXY_CA_CERT", "MY_PROXY_RETRY_INTERVAL"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def make_client(tmp, specs, *, secret="s", state_file=None, logger=None):
    return my_proxy.TunnelClient(
        specs=list(specs), server_host="127.0.0.1", server_port=1,
        secret=secret, grace_time=1.0,
        state_file=state_file or (tmp / "state.json"),
        log=logger or logging.getLogger("client-edge"),
        recent_logs=deque(maxlen=200),
    )


def _frame(ftype, stream_id, payload=b""):
    return protocol.Frame(protocol.PROTO_VERSION, ftype, stream_id, payload)


class BlockingLocalWriter:
    """Local backend writer whose drain blocks until released (event-driven)."""

    def __init__(self):
        self.allow = asyncio.Event()
        self.drain_entered = asyncio.Event()
        self.pending = bytearray()
        self.delivered = bytearray()
        self.closed = False

    def write(self, data):
        self.pending += bytes(data)

    async def drain(self):
        self.drain_entered.set()
        await self.allow.wait()
        self.delivered += self.pending
        self.pending.clear()

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    async def wait_closed(self):
        pass

    def can_write_eof(self):
        return True

    def write_eof(self):
        pass


# ---------------------------------------------------------------------------
# (a) a stream closed while its backend is still connecting must not install
# ---------------------------------------------------------------------------

def test_pending_stream_close_prevents_late_install(iso_env):
    async def _run():
        backend = await H.TcpEchoBackend().start()
        spec = H.make_spec("tcp", backend.port)
        client = make_client(iso_env, [spec])
        sid = 7
        meta = json.dumps({"tunnel_id": spec.tunnel_id, "proto": "tcp"}).encode()
        client._handle_stream_open(_frame(protocol.FrameType.STREAM_OPEN, sid, meta))
        # The server aborts the stream before our local connect finishes.
        client._route_stream_close(_frame(protocol.FrameType.STREAM_CLOSE, sid))
        await asyncio.sleep(0.2)
        try:
            assert sid not in client.streams, (
                "a stream closed during backend connect was installed late")
            assert sid not in client.pending_streams
        finally:
            await backend.stop()

    asyncio.run(_run())


def test_tunnel_handoff_during_pending_connect_prevents_late_install(iso_env):
    async def _run():
        backend = await H.TcpEchoBackend().start()
        spec = H.make_spec("tcp", backend.port)
        client = make_client(iso_env, [spec])
        sid = 9
        meta = json.dumps({"tunnel_id": spec.tunnel_id, "proto": "tcp"}).encode()
        client._handle_stream_open(_frame(protocol.FrameType.STREAM_OPEN, sid, meta))
        notice = json.dumps({"tunnel_id": spec.tunnel_id, "reason": "handoff",
                             "message": "handed off"}).encode()
        await client._handle_tunnel_close_from_server(
            _frame(protocol.FrameType.TUNNEL_CLOSE, 0, notice))
        await asyncio.sleep(0.2)
        try:
            assert sid not in client.streams, (
                "a stream installed after its tunnel had been handed off")
        finally:
            await backend.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (b) both EOF with a blocked local writer must flush queued data first
# ---------------------------------------------------------------------------

def test_both_eof_flush_queued_data_before_teardown(iso_env):
    async def _run():
        client = make_client(iso_env, [])
        lw = BlockingLocalWriter()
        stream = my_proxy.ClientStream(stream_id=1, tunnel_id="t",
                                       local_reader=None, local_writer=lw)
        stream.generation = client._generation
        client.streams[1] = stream
        stream.write_task = client._track_task(client._stream_write_loop(stream))

        client._route_stream_data(_frame(protocol.FrameType.STREAM_DATA, 1, b"DATA"))
        # Wait until the writer is genuinely blocked in drain() before EOF.
        await asyncio.wait_for(lw.drain_entered.wait(), timeout=1.0)

        client._route_stream_eof(_frame(protocol.FrameType.STREAM_EOF, 1))
        stream.local_eof = True         # local backend also reached EOF
        client._maybe_finish_stream(stream)
        assert not stream.closed, (
            "stream torn down while queued data was still blocked in the local writer")

        lw.allow.set()                  # release the blocked drain
        await H.wait_until(lambda: b"DATA" in lw.delivered, timeout=2.0,
                           msg="queued local data flushed")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (c) flow-control / framing caps
# ---------------------------------------------------------------------------

def test_client_flow_window_replenish_is_capped():
    cap = getattr(my_proxy, "MAX_WINDOW_CREDIT", 2 * my_proxy.INITIAL_WINDOW)
    window = my_proxy.FlowWindow(initial=0)
    for _ in range(cap + 5000):
        window.replenish(1)
    assert window.available <= cap, (
        f"repeated +1 credits inflated the window to {window.available} (> {cap})")


def test_empty_tcp_frame_is_not_buffered(iso_env):
    async def _run():
        client = make_client(iso_env, [])
        stream = my_proxy.ClientStream(stream_id=1, tunnel_id="t",
                                       local_reader=None, local_writer=None)
        client.streams[1] = stream
        for _ in range(200):
            client._route_stream_data(_frame(protocol.FrameType.STREAM_DATA, 1, b""))
        assert stream.recv_queue.qsize() == 0, (
            "empty TCP frames are being queued without bound")

    asyncio.run(_run())


def test_pending_udp_empty_frames_are_count_capped(iso_env):
    async def _run():
        spec = H.make_spec("udp", 5353)
        client = make_client(iso_env, [spec])
        sid = 11
        meta = json.dumps({"tunnel_id": spec.tunnel_id, "proto": "udp"}).encode()
        client._handle_stream_open(_frame(protocol.FrameType.STREAM_OPEN, sid, meta))
        for _ in range(2000):
            client._route_udp_datagram(
                _frame(protocol.FrameType.UDP_DATAGRAM, sid, b""))
        # The implementation may keep a pre-connect buffer (pending) or drop
        # unknown datagrams, but it must never accumulate unbounded entries.
        pending = client.pending_streams.get(sid)
        buffered = len(pending.buffered) if pending is not None else 0
        stream = client.streams.get(sid)
        if stream is not None:
            buffered += stream.udp_queue.qsize()
        assert buffered <= 512, (
            f"empty UDP frames accumulated {buffered} entries without bound")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (d) process verification fail-closed + stop-failure state retention
# ---------------------------------------------------------------------------

def test_expected_boot_id_unreadable_fails_closed(monkeypatch):
    monkeypatch.setattr(my_proxy, "_read_boot_id", lambda: None)
    state = {"start_time": my_proxy._proc_start_time(os.getpid()),
             "boot_id": "some-recorded-boot-id"}
    assert my_proxy._verify_client_process(os.getpid(), state) is False, (
        "a recorded boot id that cannot be re-read must fail closed")


def test_stop_failure_keeps_state_file(iso_env, monkeypatch, capsys):
    state_dir = iso_env / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    cid = "deadbeefdeadbeefdeadbeefdeadbeef"
    sf = state_dir / f"{cid}.json"
    sf.write_text(json.dumps({"client_id": cid, "pid": 4242,
                              "start_time": 1, "mode": "http", "target": "1"}))
    monkeypatch.setattr(my_proxy, "_verify_client_process", lambda pid, data: True)
    monkeypatch.setattr(my_proxy, "_terminate_pid", lambda pid, force=False: False)
    monkeypatch.setattr(my_proxy, "_is_pid_alive", lambda pid, *a, **k: True)
    my_proxy._cli_clients_delete(cid)
    capsys.readouterr()
    assert sf.exists(), (
        "deletion removed the state file even though the process could not be stopped")


# ---------------------------------------------------------------------------
# (e) private-write helpers must not clobber a user-provided directory
# ---------------------------------------------------------------------------

def test_atomic_write_does_not_chmod_an_existing_directory(iso_env):
    custom = iso_env / "custom-dir"
    custom.mkdir()
    os.chmod(custom, 0o775)
    my_proxy._atomic_write_json(custom / "data.json", {"a": 1})
    assert stat.S_IMODE(custom.stat().st_mode) == 0o775, (
        "an existing user-provided directory was chmod'd to 0700")
    assert stat.S_IMODE((custom / "data.json").stat().st_mode) == 0o600


def test_load_client_id_recovers_from_corrupt_state(iso_env):
    sf = iso_env / "corrupt.json"
    sf.write_text("[1, 2, 3]")
    client = make_client(iso_env, [], state_file=sf)
    assert client.client_id is None, "a JSON array state file crashed the client"

    sf.write_text('{"client_id": "not-hex"}')
    client2 = make_client(iso_env, [], state_file=sf)
    assert client2.client_id is None, "an invalid client id crashed the client"


# ---------------------------------------------------------------------------
# (f) managed ids are listed; shared machine file is not a per-process record
# ---------------------------------------------------------------------------

def test_clients_list_includes_managed_ids(iso_env, capsys):
    c1 = make_client(iso_env, [])
    c2 = make_client(iso_env, [])
    my_proxy._cli_clients_list()
    out = capsys.readouterr().out
    assert c1.managed_id in out, "clients list did not show the first managed id"
    assert c2.managed_id in out, "clients list did not show the second managed id"


# ---------------------------------------------------------------------------
# (g) malformed HELLO_OK must not kill the process
# ---------------------------------------------------------------------------

class HelloOkServer:
    def __init__(self, payload: dict):
        self.payload = payload
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readexactly(protocol.HEADER_LEN), timeout=5)
            _m, _v, _t, _s, length = struct.unpack("!2sBBII", header)
            if length:
                await reader.readexactly(length)
            body = json.dumps(self.payload).encode()
            writer.write(protocol.encode_frame(protocol.FrameType.HELLO_OK, 0, body))
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


@pytest.mark.parametrize("payload", [
    {"client_id": "not-hex", "heartbeat_interval": 1},
    {"client_id": "a" * 32, "capabilities": [["unhashable"]], "heartbeat_interval": 1},
])
def test_malformed_hello_ok_does_not_kill_the_client(iso_env, payload):
    async def _run():
        server = HelloOkServer(payload)
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
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
        )
        try:
            await asyncio.sleep(2.0)
            alive = proc.returncode is None
            if alive:
                proc.terminate()
            out, _ = await proc.communicate()
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await server.stop()
        assert alive, (
            "client exited on malformed HELLO_OK (should reconnect); "
            f"output: {out.decode(errors='replace')[-500:]}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (h) input validation
# ---------------------------------------------------------------------------

def test_parse_host_port_rejects_trailing_garbage_after_bracket():
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._parse_host_port("[::1]garbage")


def test_validate_port_rejects_bool_and_fractional():
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._validate_port(True)
    with pytest.raises(my_proxy.ConfigError):
        my_proxy._validate_port(1.5)


def _resolve(cfg, monkeypatch, tmp):
    parser = my_proxy._build_arg_parser()
    args = parser.parse_args(["http", "1", "--no-dashboard"])
    monkeypatch.setattr(my_proxy, "DEFAULT_TOKEN_FILE", tmp / "none.json")
    monkeypatch.setenv("MY_PROXY_TOKEN", "a-token")
    return my_proxy._resolve_runtime_config(args, cfg)


def test_config_tls_string_false_is_rejected(iso_env, monkeypatch):
    with pytest.raises(my_proxy.ConfigError):
        _resolve({"tls": "false"}, monkeypatch, iso_env)


def test_token_non_string_is_rejected(iso_env, monkeypatch):
    with pytest.raises(my_proxy.ConfigError):
        _resolve({"token": 12345}, monkeypatch, iso_env)


# ---------------------------------------------------------------------------
# (i) generation guard + bounded shutdown
# ---------------------------------------------------------------------------

def test_stale_generation_send_is_refused(iso_env):
    async def _run():
        client = make_client(iso_env, [])

        class W:
            def __init__(self):
                self.data = bytearray()

            def write(self, data):
                self.data += bytes(data)

            async def drain(self):
                pass

            def is_closing(self):
                return False

        client.writer = W()
        client._generation = 2
        sent = await client._send_checked(protocol.FrameType.STREAM_DATA, 1, b"x", gen=1)
        assert sent is False
        assert bytes(client.writer.data) == b""

    asyncio.run(_run())


def test_request_shutdown_is_bounded_with_blocked_writer(iso_env):
    async def _run():
        spec = H.make_spec("tcp", 1)
        client = make_client(iso_env, [spec])

        class Blocking:
            def __init__(self):
                self.event = asyncio.Event()
                self.closed = False

            def write(self, data):
                pass

            async def drain(self):
                await self.event.wait()

            def is_closing(self):
                return self.closed

            def close(self):
                self.closed = True

        client.writer = Blocking()
        try:
            await asyncio.wait_for(client.request_shutdown(), timeout=1.0)
        except asyncio.TimeoutError:
            raise AssertionError(
                "request_shutdown hung on a blocked control writer")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (k) token redaction reaches the terminal/log, not only the ring
# ---------------------------------------------------------------------------

def test_log_redacts_token_in_terminal_output(iso_env):
    secret = "super-secret-token"
    client = make_client(iso_env, [], secret=secret)
    seen = []
    handler = logging.Handler()
    handler.emit = lambda record: seen.append(record.getMessage())
    client.log.addHandler(handler)
    client.log.setLevel(logging.DEBUG)
    try:
        client._log(logging.ERROR, "authentication failed for %s", client.secret)
    finally:
        client.log.removeHandler(handler)
    assert seen and all(secret not in msg for msg in seen), (
        f"token leaked into terminal/log output: {seen}")


# ---------------------------------------------------------------------------
# (l) client dashboard oversized request line + HEAD length
# ---------------------------------------------------------------------------

def test_client_dashboard_oversized_line_and_head(iso_env):
    async def _run():
        client = make_client(iso_env, [])
        server = await asyncio.start_server(
            lambda r, w: my_proxy._handle_dashboard_conn(r, w, client),
            "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=3.0)
            status, headers, body = H.parse_http(data)
            assert status == 431, f"expected 431, got {status}"
            assert body, "the 431 response must not be empty"
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=3.0)
            get_status, get_headers, get_body = H.parse_http(data)
            assert get_status == 200 and get_body
            writer.close()

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=3.0)
            status, headers, body = H.parse_http(data)
            assert status == 200
            # HEAD carries no body but must advertise the same representation
            # length a GET would return.
            assert body == b""
            assert headers.get("content-length") == str(len(get_body)), (
                f"HEAD Content-Length {headers.get('content-length')} does not match "
                f"the GET body length {len(get_body)}")
            writer.close()
        finally:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    asyncio.run(_run())