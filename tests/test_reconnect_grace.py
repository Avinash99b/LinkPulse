"""HTTP reconnect-grace regression tests.

When an HTTP tunnel's client drops *unexpectedly*, a request for that name is
held briefly (``HTTP_RECONNECT_GRACE_SECONDS``) instead of failing with a
transient 404, then served by whoever owns the name again.  Unknown names are
still an immediate 404; an expired wait or a full queue is 503 + Retry-After.

Most tests drive the real server over raw control connections (a tiny
hand-written client), so they are independent of the client engine.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
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


GRACE = {"http_reconnect_grace_seconds": 8}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

async def _open_collect(reader, writer, **kw):
    """Send TUNNEL_OPEN_REQUEST; return (response_dict, extra_frames_seen)."""
    req = {"tunnel_id": kw.pop("tunnel_id", None) or protocol.new_tunnel_id(),
           "type": kw.pop("ttype", "http"),
           "mode": kw.pop("mode", protocol.TUNNEL_MODE_HANDOFF)}
    subdomain = kw.pop("subdomain", None)
    instance_id = kw.pop("instance_id", None)
    if subdomain is not None:
        req["subdomain"] = subdomain
    if instance_id is not None:
        req["instance_id"] = instance_id
    writer.write(protocol.encode_frame(
        protocol.FrameType.TUNNEL_OPEN_REQUEST, 0, json.dumps(req).encode()))
    await writer.drain()
    extras = []
    while True:
        frame = await H.read_frame_timeout(reader, 5.0)
        if frame.type == protocol.FrameType.TUNNEL_OPEN_RESPONSE:
            return json.loads(frame.payload.decode()), extras
        extras.append(frame)


async def _drop_unexpected(session, server, subdomain):
    """Drop a raw session and wait until the server has freed the name + set a hint."""
    reader, writer, cid = session
    await H.drop(writer)
    await H.wait_until(
        lambda: subdomain not in server.ctx.by_subdomain, timeout=3.0,
        msg=f"{subdomain} released")
    return cid


async def _expect_pending(reader, wait=0.5):
    try:
        data = await asyncio.wait_for(reader.read(-1), timeout=wait)
    except asyncio.TimeoutError:
        return
    raise AssertionError(f"request was not held; server responded {data[:200]!r}")


async def _expect_status(reader, expected, timeout=6.0):
    data = await asyncio.wait_for(reader.read(-1), timeout=timeout)
    status, headers, _body = H.parse_http(data)
    assert status == expected, f"expected {expected}, got {status} ({data[:200]!r})"
    return headers


async def _serve_one_http_request(reader, writer, body: bytes = b"OK",
                                  extras=()):
    """Act as the recovering owner: answer the parked request on `extras`/next frame."""
    frames = list(extras)
    while True:
        if frames:
            frame = frames.pop(0)
        else:
            frame = await H.read_frame_timeout(reader, 5.0)
        if frame.type == protocol.FrameType.STREAM_OPEN:
            sid = frame.stream_id
            break
    # Drain request data until we see the end of the buffered request bytes.
    # (The server forwards the head immediately; a POST body may follow.)
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n" + body)
    writer.write(protocol.encode_frame(protocol.FrameType.STREAM_DATA, sid, resp))
    await writer.drain()
    writer.write(protocol.encode_frame(protocol.FrameType.STREAM_CLOSE, sid))
    await writer.drain()
    return sid


# ---------------------------------------------------------------------------
# negative / boundary behaviour
# ---------------------------------------------------------------------------

def test_unknown_name_is_immediate_404(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config=GRACE)
        try:
            t0 = time.monotonic()
            status, _h, _b = await H.http_roundtrip(
                server.http_port, f"nope.{server.wildcard}", "/")
            assert status == 404
            assert time.monotonic() - t0 < 1.0
        finally:
            await server.stop()

    asyncio.run(_run())


def test_grace_zero_disables_waiting(iso_env):
    async def _run():
        server = await H.start_server(
            iso_env, extra_config={"http_reconnect_grace_seconds": 0})
        try:
            session = await H.raw_session(server)
            await H.raw_open(*session[:2], subdomain="zero")
            await _drop_unexpected(session, server, "zero")
            assert "zero" not in server.ctx.reconnect_hints
            t0 = time.monotonic()
            status, _h, _b = await H.http_roundtrip(
                server.http_port, f"zero.{server.wildcard}", "/")
            assert status == 404
            assert time.monotonic() - t0 < 1.0
        finally:
            await server.stop()

    asyncio.run(_run())


def test_explicit_close_records_no_reconnect_hint(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config=GRACE)
        try:
            reader, writer, _cid = await H.raw_session(server)
            tid, resp = await H.raw_open(reader, writer, subdomain="closed")
            assert resp["status"] == "ok"
            await H.raw_close(writer, tid)
            await H.wait_until(lambda: "closed" not in server.ctx.by_subdomain,
                               timeout=3.0, msg="explicit close applied")
            assert "closed" not in server.ctx.reconnect_hints, (
                "an explicit close must not create a reconnect hint")
            await H.drop(writer)
            status, _h, _b = await H.http_roundtrip(
                server.http_port, f"closed.{server.wildcard}", "/")
            assert status == 404
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# the core: hold, then serve from the recovering owner
# ---------------------------------------------------------------------------

def test_disconnect_holds_request_then_routes_to_new_owner(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config=GRACE)
        try:
            cid = H.new_client_id_bytes()
            a = await H.raw_session(server, client_id=cid)
            tid, resp = await H.raw_open(*a[:2], subdomain="recover", instance_id="i1")
            assert resp["status"] == "ok", resp
            await _drop_unexpected(a, server, "recover")
            assert "recover" in server.ctx.reconnect_hints

            # A public request arrives in the disconnect window: it must park.
            r_reader, r_writer = await H.send_request(
                server.http_port, f"recover.{server.wildcard}", "/held")
            await _expect_pending(r_reader, wait=0.6)
            assert server.ctx.reconnect_waiters_total == 1

            # The same client process reconnects and re-registers the name.
            b = await H.raw_session(server, client_id=cid)
            resp2, extras = await _open_collect(
                b[0], b[1], subdomain="recover", instance_id="i1", tunnel_id=tid)
            assert resp2["status"] == "ok", resp2

            # The parked request must be forwarded to the new owner exactly once.
            await _serve_one_http_request(b[0], b[1], b"BACKEND-RESPONSE", extras=extras)
            status, _h, body = await H.read_response(r_reader, timeout=5.0)
            assert status == 200, body
            assert body == b"BACKEND-RESPONSE"
            assert server.ctx.reconnect_waiters_total == 0

            with contextlib.suppress(Exception):
                r_writer.close()
            await H.drop(b[1])
        finally:
            await server.stop()

    asyncio.run(_run())


def test_post_body_is_forwarded_once_no_replay(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config=GRACE)
        try:
            cid = H.new_client_id_bytes()
            a = await H.raw_session(server, client_id=cid)
            await H.raw_open(*a[:2], subdomain="poster", instance_id="i1")
            await _drop_unexpected(a, server, "poster")

            r_reader, r_writer = await H.send_request(
                server.http_port, f"poster.{server.wildcard}", "/submit",
                method="POST", body=b"UNIQUE-BODY-1234")
            await _expect_pending(r_reader, wait=0.5)

            b = await H.raw_session(server, client_id=cid)
            _resp, extras = await _open_collect(b[0], b[1], subdomain="poster",
                                                instance_id="i1")
            # Collect every STREAM_DATA the server forwards for this stream.
            sid_holder = {}
            collected = bytearray()
            for fr in extras:
                if fr.type == protocol.FrameType.STREAM_OPEN:
                    sid_holder["sid"] = fr.stream_id
                elif fr.type == protocol.FrameType.STREAM_DATA:
                    collected += fr.payload
            sid = sid_holder.get("sid")
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and b"UNIQUE-BODY-1234" not in collected:
                try:
                    fr = await H.read_frame_timeout(b[0], timeout=1.0)
                except asyncio.TimeoutError:
                    break
                if fr.type == protocol.FrameType.STREAM_OPEN:
                    sid = fr.stream_id
                elif fr.type == protocol.FrameType.STREAM_DATA:
                    collected += fr.payload
            assert collected.count(b"UNIQUE-BODY-1234") == 1, (
                f"POST body must be forwarded exactly once, saw {collected.count(b'UNIQUE-BODY-1234')}")
            # Answer so the public request completes.
            if sid is not None:
                resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                b[1].write(protocol.encode_frame(protocol.FrameType.STREAM_DATA, sid, resp))
                await b[1].drain()
                b[1].write(protocol.encode_frame(protocol.FrameType.STREAM_CLOSE, sid))
                await b[1].drain()
            status, _h, _body = await H.read_response(r_reader, timeout=5.0)
            assert status == 200
            with contextlib.suppress(Exception):
                r_writer.close()
            await H.drop(b[1])
        finally:
            await server.stop()

    asyncio.run(_run())


def test_handoff_during_wait_is_allowed(iso_env):
    """A different client legitimately claiming the name while a request waits
    must serve that waiter -- the wait is a hint, not a lease."""
    async def _run():
        server = await H.start_server(iso_env, extra_config=GRACE)
        try:
            a = await H.raw_session(server, client_id=H.new_client_id_bytes())
            await H.raw_open(*a[:2], subdomain="shared", instance_id="iA")
            await _drop_unexpected(a, server, "shared")

            r_reader, r_writer = await H.send_request(
                server.http_port, f"shared.{server.wildcard}", "/")
            await _expect_pending(r_reader, wait=0.5)

            # A competitor (new client id) claims the name in handoff mode.
            b = await H.raw_session(server, client_id=H.new_client_id_bytes())
            resp, extras = await _open_collect(b[0], b[1], subdomain="shared")
            assert resp["status"] == "ok", resp
            await _serve_one_http_request(b[0], b[1], b"NEW-OWNER", extras=extras)
            status, _h, body = await H.read_response(r_reader, timeout=5.0)
            assert status == 200 and body == b"NEW-OWNER"

            with contextlib.suppress(Exception):
                r_writer.close()
            await H.drop(b[1])
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# expiry + queue bounds
# ---------------------------------------------------------------------------

def test_expired_wait_returns_503_with_retry_after(iso_env):
    async def _run():
        server = await H.start_server(
            iso_env, extra_config={"http_reconnect_grace_seconds": 1})
        try:
            a = await H.raw_session(server)
            await H.raw_open(*a[:2], subdomain="gone", instance_id="i1")
            await _drop_unexpected(a, server, "gone")

            r_reader, r_writer = await H.send_request(
                server.http_port, f"gone.{server.wildcard}", "/")
            headers = await _expect_status(r_reader, 503, timeout=4.0)
            assert headers.get("retry-after") == "2", headers
            with contextlib.suppress(Exception):
                r_writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_per_name_waiter_cap_returns_503(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config={
            "http_reconnect_grace_seconds": 2,
            "http_reconnect_max_waiters_per_name": 1,
            "http_reconnect_max_waiters": 128,
        })
        try:
            a = await H.raw_session(server)
            await H.raw_open(*a[:2], subdomain="capname", instance_id="i1")
            await _drop_unexpected(a, server, "capname")

            r1_reader, r1_writer = await H.send_request(
                server.http_port, f"capname.{server.wildcard}", "/1")
            await _expect_pending(r1_reader, wait=0.4)
            assert server.ctx.reconnect_waiters_total == 1

            # Second waiter over the per-name cap -> immediate 503.
            t0 = time.monotonic()
            status, headers, _b = await H.http_roundtrip(
                server.http_port, f"capname.{server.wildcard}", "/2", timeout=3.0)
            assert status == 503
            assert headers.get("retry-after") == "2"
            assert time.monotonic() - t0 < 1.0

            with contextlib.suppress(Exception):
                r1_writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_total_waiter_cap_returns_503(iso_env):
    async def _run():
        server = await H.start_server(iso_env, extra_config={
            "http_reconnect_grace_seconds": 2,
            "http_reconnect_max_waiters_per_name": 16,
            "http_reconnect_max_waiters": 1,
        })
        try:
            a = await H.raw_session(server)
            await H.raw_open(*a[:2], subdomain="tot1", instance_id="i1")
            await _drop_unexpected(a, server, "tot1")
            b = await H.raw_session(server)
            await H.raw_open(*b[:2], subdomain="tot2", instance_id="i2")
            await _drop_unexpected(b, server, "tot2")

            r1_reader, r1_writer = await H.send_request(
                server.http_port, f"tot1.{server.wildcard}", "/")
            await _expect_pending(r1_reader, wait=0.4)
            status, headers, _b = await H.http_roundtrip(
                server.http_port, f"tot2.{server.wildcard}", "/", timeout=3.0)
            assert status == 503 and headers.get("retry-after") == "2"
            with contextlib.suppress(Exception):
                r1_writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_waiter_counters_released_after_timeout(iso_env):
    async def _run():
        server = await H.start_server(
            iso_env, extra_config={"http_reconnect_grace_seconds": 1})
        try:
            a = await H.raw_session(server)
            await H.raw_open(*a[:2], subdomain="rel", instance_id="i1")
            await _drop_unexpected(a, server, "rel")

            r_reader, r_writer = await H.send_request(
                server.http_port, f"rel.{server.wildcard}", "/")
            await _expect_pending(r_reader, wait=0.3)
            assert server.ctx.reconnect_waiters_total == 1
            await _expect_status(r_reader, 503, timeout=4.0)
            await H.wait_until(
                lambda: server.ctx.reconnect_waiters_total == 0
                and "rel" not in server.ctx.reconnect_waiters_by_name,
                timeout=2.0, msg="waiter counters released")
            with contextlib.suppress(Exception):
                r_writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# full integration through the real client (real backend response)
# ---------------------------------------------------------------------------

def test_named_disconnect_waits_and_serves_real_backend_response(iso_env):
    async def _run():
        backend = await H.HttpBackend(marker="REAL").start()
        server = await H.start_server(iso_env, extra_config=GRACE)
        spec = H.make_spec("http", backend.port, subdomain="waited")
        client, task = await H.start_client(server, iso_env, [spec], retry_interval=1.0)
        try:
            await H.wait_tunnel_active(client, spec.tunnel_id)

            # Drop the control connection as if the network blipped.
            client.writer.close()
            await H.wait_until(lambda: "waited" not in server.ctx.by_subdomain,
                               timeout=3.0, msg="client disconnect processed")

            r_reader, r_writer = await H.send_request(
                server.http_port, f"waited.{server.wildcard}", "/after")
            await _expect_pending(r_reader, wait=0.5)
            status, _h, body = await H.read_response(r_reader, timeout=8.0)
            assert status == 200, body
            assert body == b"REAL:GET:/after:"
            assert any(r[1] == "/after" for r in backend.requests)
            with contextlib.suppress(Exception):
                r_writer.close()
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())


def test_auto_assigned_name_is_stable_across_reconnect(iso_env):
    async def _run():
        backend = await H.HttpBackend().start()
        server = await H.start_server(iso_env, extra_config=GRACE)
        spec = H.make_spec("http", backend.port)
        client, task = await H.start_client(server, iso_env, [spec], retry_interval=1.0)
        try:
            rt = await H.wait_tunnel_active(client, spec.tunnel_id)
            first_url = rt.public_url
            assert first_url

            client.writer.close()
            await H.wait_until(lambda: client.status == "reconnecting"
                               or client.reconnect_count > 0, timeout=3.0,
                               msg="client began reconnecting")
            await H.wait_until(lambda: client.tunnels[spec.tunnel_id].status == "active",
                               timeout=6.0, msg="client re-registered")
            assert client.tunnels[spec.tunnel_id].public_url == first_url, (
                "auto-assigned public URL changed across a reconnect")
        finally:
            await H.stop_client(client, task)
            await backend.stop()
            await server.stop()

    asyncio.run(_run())
