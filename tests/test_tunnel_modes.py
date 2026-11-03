"""Tests for tunnel ownership modes (handoff vs. lease) and for the client's
never-give-up reconnect behaviour.

The mode tests drive the real server-side tunnel registry
(proxy_server.handle_tunnel_open) with in-memory sessions, so they cover the
claim/lease/eviction rules without opening public listeners.
"""

import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = ROOT / "tunnel-proxy"
CLIENT_DIR = ROOT / "my_proxy_client"
CLIENT_SCRIPT = CLIENT_DIR / "my_proxy.py"
sys.path.insert(0, str(SERVER_DIR))

import protocol  # noqa: E402
import proxy_server as ps  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeWriter:
    """Minimal stand-in for asyncio.StreamWriter (we only need bytes + close)."""

    def __init__(self):
        self.buffer = bytearray()
        self.closed = False
        self.closed_event = asyncio.Event()

    def write(self, data):
        if self.closed:
            raise ConnectionError("writer closed")
        self.buffer += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True
        self.closed_event.set()

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name, default=None):
        return ("127.0.0.1", 5555)


def make_context(tmp_path, tcp_range=None):
    cfg = json.loads(json.dumps(ps.DEFAULT_CONFIG))
    cfg["storage"]["db_path"] = str(tmp_path / "test.db")
    cfg["http_only"] = True
    cfg["tcp"]["port_range"] = tcp_range or [24000, 24050]
    cfg["udp"]["port_range"] = [24000, 24050]
    return ps.ServerContext(cfg)


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_session(ctx, client_id="a" * 32):
    return ps.ClientSession(client_id, None, FakeWriter())


def take_frames(writer):
    data = bytes(writer.buffer)
    writer.buffer.clear()
    frames, off = [], 0
    while off + protocol.HEADER_LEN <= len(data):
        magic, ver, ftype, sid, length = struct.unpack("!2sBBII",
                                                       data[off:off + protocol.HEADER_LEN])
        assert magic == protocol.PROTO_MAGIC
        payload = data[off + protocol.HEADER_LEN:off + protocol.HEADER_LEN + length]
        frames.append((ftype, sid, payload))
        off += protocol.HEADER_LEN + length
    return frames


async def open_tunnel(session, ctx, *, ttype="http", subdomain=None, remote_port=None,
                      mode=protocol.TUNNEL_MODE_HANDOFF, instance_id=None, tunnel_id=None):
    tunnel_id = tunnel_id or protocol.new_tunnel_id()
    req = {"tunnel_id": tunnel_id, "type": ttype, "mode": mode}
    if instance_id is not None:
        req["instance_id"] = instance_id
    if subdomain is not None:
        req["subdomain"] = subdomain
    if remote_port is not None:
        req["remote_port"] = remote_port
    frame = protocol.Frame(protocol.PROTO_VERSION,
                           protocol.FrameType.TUNNEL_OPEN_REQUEST, 0,
                           json.dumps(req).encode())
    await ps.handle_tunnel_open(session, frame, ctx)
    responses = [json.loads(p.decode()) for t, _, p in take_frames(session.writer)
                 if t == protocol.FrameType.TUNNEL_OPEN_RESPONSE]
    assert responses, "server sent no TUNNEL_OPEN_RESPONSE"
    return tunnel_id, responses[-1]


def revocation_notices(session):
    """TUNNEL_CLOSE frames the server pushed to this session."""
    return [json.loads(p.decode()) for t, _, p in take_frames(session.writer)
            if t == protocol.FrameType.TUNNEL_CLOSE]


# ---------------------------------------------------------------------------
# handoff mode (default)
# ---------------------------------------------------------------------------

def test_handoff_gives_name_to_newcomer(tmp_path):
    async def _run():
        ctx = make_context(tmp_path)
        old = make_session(ctx, "a" * 32)
        new = make_session(ctx, "b" * 32)

        old_tid, resp = await open_tunnel(old, ctx, subdomain="demo", instance_id="i-old")
        assert resp["status"] == "ok"
        assert resp["mode"] == "handoff"

        new_tid, resp = await open_tunnel(new, ctx, subdomain="demo", instance_id="i-new")
        assert resp["status"] == "ok"
        assert resp["public_url"] == "http://demo." + ctx.config["wildcard_domain"]

        # The old owner is told, and its tunnel is gone.
        notes = revocation_notices(old)
        assert len(notes) == 1
        assert notes[0]["tunnel_id"] == old_tid
        assert notes[0]["reason"] == "handoff"
        assert "handed off" in notes[0]["message"].lower()
        assert old_tid not in old.tunnels

        # Routing now belongs to the newcomer.
        owner, tid = ctx.by_subdomain["demo"]
        assert owner is new and tid == new_tid

        ctx.storage.close()

    asyncio.run(_run())


def test_handoff_works_for_tcp_ports(tmp_path):
    async def _run():
        port = free_tcp_port()
        ctx = make_context(tmp_path, tcp_range=[port, port])
        old = make_session(ctx, "a" * 32)
        new = make_session(ctx, "b" * 32)

        _, resp = await open_tunnel(old, ctx, ttype="tcp", remote_port=port,
                                    instance_id="i-old")
        assert resp["status"] == "ok", resp

        _, resp = await open_tunnel(new, ctx, ttype="tcp", remote_port=port,
                                    instance_id="i-new")
        assert resp["status"] == "ok", resp
        owner, _ = ctx.by_port[port]
        assert owner is new
        assert len(revocation_notices(old)) == 1

        for session in (old, new):
            for tunnel_id in list(session.tunnels):
                await ps.close_tunnel(session, tunnel_id, ctx)
        ctx.storage.close()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# lease mode
# ---------------------------------------------------------------------------

def test_lease_blocks_other_client(tmp_path):
    async def _run():
        ctx = make_context(tmp_path)
        holder = make_session(ctx, "a" * 32)
        other = make_session(ctx, "b" * 32)

        holder_tid, resp = await open_tunnel(holder, ctx, subdomain="mine",
                                             mode=protocol.TUNNEL_MODE_LEASE,
                                             instance_id="i-holder")
        assert resp["status"] == "ok"
        assert resp["mode"] == "lease"

        rejected_tid, resp = await open_tunnel(other, ctx, subdomain="mine",
                                               instance_id="i-other")
        assert resp["status"] == "error"
        assert resp["reason"] == "leased"
        assert "leased" in resp["error"]
        assert rejected_tid not in other.tunnels

        # Nothing was revoked: the lease holder keeps the name.
        assert revocation_notices(holder) == []
        owner, tid = ctx.by_subdomain["mine"]
        assert owner is holder and tid == holder_tid

        ctx.storage.close()

    asyncio.run(_run())


def test_leasing_a_name_that_is_in_use_is_refused(tmp_path):
    async def _run():
        ctx = make_context(tmp_path)
        first = make_session(ctx, "a" * 32)
        second = make_session(ctx, "b" * 32)

        _, resp = await open_tunnel(first, ctx, subdomain="busy", instance_id="i-1")
        assert resp["status"] == "ok"

        _, resp = await open_tunnel(second, ctx, subdomain="busy",
                                    mode=protocol.TUNNEL_MODE_LEASE,
                                    instance_id="i-2")
        assert resp["status"] == "error"
        assert resp["reason"] == "in_use"

        # Still owned by the first client.
        assert ctx.by_subdomain["busy"][0] is first
        assert revocation_notices(first) == []

        ctx.storage.close()

    asyncio.run(_run())


def test_same_client_process_reclaims_its_own_lease(tmp_path):
    """A reconnect (same client_id *and* instance) must get its lease back
    even if the server has not noticed the old TCP connection dying."""
    async def _run():
        ctx = make_context(tmp_path)
        cid = "c" * 32
        old_session = make_session(ctx, cid)
        new_session = make_session(ctx, cid)

        tunnel_id, resp = await open_tunnel(old_session, ctx, subdomain="stable",
                                            mode=protocol.TUNNEL_MODE_LEASE,
                                            instance_id="instance-1",
                                            tunnel_id="t" * 32)
        assert resp["status"] == "ok"

        _, resp = await open_tunnel(new_session, ctx, subdomain="stable",
                                    mode=protocol.TUNNEL_MODE_LEASE,
                                    instance_id="instance-1",
                                    tunnel_id="t" * 32)
        assert resp["status"] == "ok", resp
        assert tunnel_id not in old_session.tunnels
        assert ctx.by_subdomain["stable"][0] is new_session

        ctx.storage.close()

    asyncio.run(_run())


def test_second_process_of_same_client_is_a_competitor(tmp_path):
    """Two client processes on one machine share the persisted client_id.
    Their instance ids differ, so they must not be mistaken for a reconnect."""
    async def _run():
        ctx = make_context(tmp_path)
        cid = "d" * 32
        first = make_session(ctx, cid)
        second = make_session(ctx, cid)

        await open_tunnel(first, ctx, subdomain="leased", mode=protocol.TUNNEL_MODE_LEASE,
                          instance_id="instance-1")
        _, resp = await open_tunnel(second, ctx, subdomain="leased",
                                    mode=protocol.TUNNEL_MODE_LEASE,
                                    instance_id="instance-2")
        assert resp["status"] == "error"
        assert resp["reason"] == "leased"
        assert ctx.by_subdomain["leased"][0] is first

        # In handoff mode the same pair behaves like any other takeover.
        await open_tunnel(first, ctx, subdomain="shared", instance_id="instance-1")
        _, resp = await open_tunnel(second, ctx, subdomain="shared",
                                    instance_id="instance-2")
        assert resp["status"] == "ok"
        assert ctx.by_subdomain["shared"][0] is second

        ctx.storage.close()

    asyncio.run(_run())


def test_invalid_mode_is_rejected(tmp_path):
    async def _run():
        ctx = make_context(tmp_path)
        session = make_session(ctx)
        _, resp = await open_tunnel(session, ctx, subdomain="x", mode="exclusive")
        assert resp["status"] == "error"
        assert "mode must be" in resp["error"]
        ctx.storage.close()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# client: never gives up reconnecting
# ---------------------------------------------------------------------------

def test_client_keeps_retrying_past_grace_period(tmp_path):
    """With no server listening the client must stay alive well past
    --grace-time and keep retrying instead of exiting."""
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(tmp_path)
    env.pop("MY_PROXY_TOKEN", None)
    env.pop("MY_PROXY_SERVER", None)

    proc = subprocess.Popen(
        [sys.executable, str(CLIENT_SCRIPT), "http", "1", "-u", "never",
         "--server", "127.0.0.1:1", "--token", "test-secret",
         "--no-dashboard", "--grace-time", "1", "--retry-interval", "1",
         "--state-file", str(tmp_path / "state.json")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    try:
        time.sleep(4.5)   # several retries, far beyond the 1s grace period
        assert proc.poll() is None, "client exited instead of retrying forever"
    finally:
        proc.terminate()
        try:
            out = proc.communicate(timeout=10)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0]

    assert "retrying" in out.lower()
    assert "giving up" not in out.lower()


# ---------------------------------------------------------------------------
# client: handoff revokes the tunnel and terminates the client cleanly
# ---------------------------------------------------------------------------

class HandoffMockServer:
    """Minimal server: accept HELLO, grant every tunnel, then revoke it with
    reason="handoff" -- exactly what the real server does to the losing client."""

    def __init__(self, secret="test-secret"):
        self.secret = secret
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            _, _, ftype, _, length = struct.unpack("!2sBBII", await reader.readexactly(12))
            await reader.readexactly(length)
            assert ftype == protocol.FrameType.HELLO

            ok = json.dumps({"client_id": "1" * 32, "heartbeat_interval": 60}).encode()
            writer.write(protocol.encode_frame(protocol.FrameType.HELLO_OK, 0, ok))
            await writer.drain()

            while True:
                _, _, ftype, _, length = struct.unpack("!2sBBII", await reader.readexactly(12))
                payload = await reader.readexactly(length) if length else b""
                if ftype == protocol.FrameType.TUNNEL_OPEN_REQUEST:
                    req = json.loads(payload.decode())
                    resp = json.dumps({"tunnel_id": req["tunnel_id"], "status": "ok",
                                       "type": "http",
                                       "public_url": f"http://{req.get('subdomain')}.test.local",
                                       "mode": req.get("mode", "handoff")}).encode()
                    writer.write(protocol.encode_frame(
                        protocol.FrameType.TUNNEL_OPEN_RESPONSE, 0, resp))
                    await writer.drain()
                    # The real server hands the name to a newer client: revoke.
                    notice = json.dumps({
                        "tunnel_id": req["tunnel_id"],
                        "reason": "handoff",
                        "message": "Tunnel 'demo' was handed off to a new client",
                    }).encode()
                    writer.write(protocol.encode_frame(
                        protocol.FrameType.TUNNEL_CLOSE, 0, notice))
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


def test_client_terminates_with_message_on_handoff(tmp_path):
    async def _run():
        server = HandoffMockServer()
        await server.start()
        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = str(tmp_path)
        env.pop("MY_PROXY_TOKEN", None)
        env.pop("MY_PROXY_SERVER", None)

        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(CLIENT_SCRIPT), "http", "1", "-u", "demo",
            "--server", f"127.0.0.1:{server.port}", "--token", "test-secret",
            "--no-dashboard", "--state-file", str(tmp_path / "state.json"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await server.stop()

        text = out.decode()
        assert proc.returncode == 0, f"client exited with {proc.returncode}: {text}"
        assert "handed off to a new client" in text
        assert "No tunnels left to serve" in text

    asyncio.run(_run())
