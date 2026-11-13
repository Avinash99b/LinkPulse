#!/usr/bin/env python3
"""
reference_client.py -- Minimal, self-contained reference client.

This is an *illustrative* worked example of the wire protocol defined in
``protocol.py`` (the canonical source). It is NOT the production client: the
supported client is ``my_proxy_client/my_proxy.py`` (packaged as ``linkpulse``),
which additionally handles reconnects, process management, the local dashboard
and hardening. Use this file only to understand or port the protocol.

What it does: one control connection, HELLO auth, opens one HTTP and/or one TCP
tunnel, and forwards multiplexed STREAM_* traffic to/from a real local TCP
service (e.g. one listening on 127.0.0.1:3000). It implements the pieces that a
correct minimal peer must not omit:

  * buffers STREAM_DATA that arrives before the local backend is connected,
  * replenishes receive-side flow-control credit (STREAM_WINDOW_UPDATE) only
    after data has been written locally, so the server is not stalled,
  * honours stream_eof half-close when the server advertises it, and falls back
    to a full STREAM_CLOSE otherwise,
  * can encrypt the control channel with verified TLS (``--tls``/``--ca-cert``).

Usage:
    python3 reference_client.py --server proxy.example.com:9000 \\
        --secret <shared_secret> --local-http 127.0.0.1:3000 --subdomain myapp

    # encrypted control channel (certificate verification is mandatory):
    python3 reference_client.py --server proxy.example.com:9000 --tls \\
        --ca-cert /path/to/ca.pem --secret <shared_secret> --local-http 127.0.0.1:3000

Persists its client_id in .client_id.json next to this script so that restarts
reconnect as the same client (and can request the same subdomain/port again).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import ssl
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from protocol import (  # noqa: E402
    CONTROL_STREAM_ID, FrameType, INITIAL_WINDOW, MAX_FRAME_PAYLOAD,
    NULL_CLIENT_ID, build_hello_payload, encode_frame, read_frame, new_tunnel_id,
)

STATE_FILE = os.path.join(os.path.dirname(__file__), ".client_id.json")
WINDOW_UPDATE_THRESHOLD = INITIAL_WINDOW // 2
BUFFER_LIMIT = INITIAL_WINDOW + MAX_FRAME_PAYLOAD
QUEUE_EOF = object()


def load_client_id() -> bytes:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            hexid = json.load(f)["client_id"]
        return bytes.fromhex(hexid)
    return NULL_CLIENT_ID


def save_client_id(client_id_hex: str):
    path = STATE_FILE
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_id": client_id_hex}, f)
    os.replace(tmp, path)


class Stream:
    """One multiplexed stream's state on the client side."""

    def __init__(self, stream_id, tunnel_id):
        self.stream_id = stream_id
        self.tunnel_id = tunnel_id
        self.local_reader = None
        self.local_writer = None
        self.pending = bytearray()
        self.pending_eof = False
        self.send_window = INITIAL_WINDOW      # credit we may still send
        self.send_event = asyncio.Event()
        self.send_event.set()
        self.unacked_recv = 0
        self.recv_eof = False
        self.local_eof = False
        self.closed = False
        self.write_task = None
        self.pump_task = None


class TunnelClient:
    def __init__(self, host, port, secret, local_targets, tls=False, ca_cert=None):
        self.host, self.port, self.secret = host, port, secret
        self.local_targets = local_targets  # {tunnel_id: (local_host, local_port)}
        self.tls = tls
        self.ca_cert = ca_cert
        self.reader = None
        self.writer = None
        self.write_lock = asyncio.Lock()
        self.streams = {}
        self.server_supports_eof = False
        # One id per process: lets the server tell a reconnect (same client_id
        # AND same instance_id) from a second competing process on this host.
        self.instance_id = secrets.token_hex(8)

    async def connect(self):
        kwargs = {}
        if self.tls:
            # Verification and hostname checking are mandatory; there is no
            # insecure switch. A custom CA bundle may be supplied instead of
            # relying on the system trust store.
            ctx = ssl.create_default_context(cafile=self.ca_cert or None)
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            kwargs["ssl"] = ctx
            kwargs["server_hostname"] = self.host
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, **kwargs)
        client_id_bytes = load_client_id()
        hello = build_hello_payload(self.secret, client_id_bytes)
        await self._send(FrameType.HELLO, CONTROL_STREAM_ID, hello)
        frame = await read_frame(self.reader)
        if frame.type == FrameType.HELLO_FAIL:
            raise RuntimeError(f"auth failed: {frame.payload}")
        info = json.loads(frame.payload.decode())
        save_client_id(info["client_id"])
        caps = info.get("capabilities") or []
        self.server_supports_eof = "stream_eof" in caps
        print(f"[client] connected, client_id={info['client_id']} "
              f"(tls={bool(self.tls)}, stream_eof={self.server_supports_eof})")

    async def _send(self, ftype, stream_id, payload=b""):
        async with self.write_lock:
            self.writer.write(encode_frame(ftype, stream_id, payload))
            await self.writer.drain()

    async def open_tunnels(self, http_subdomain, tcp_remote_port, mode="handoff"):
        common = {"mode": mode, "instance_id": self.instance_id,
                  "capabilities": ["stream_eof"]}
        if "http" in self.local_targets:
            tid = new_tunnel_id()
            self.local_targets[tid] = self.local_targets.pop("http")
            await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(
                {"tunnel_id": tid, "type": "http", "subdomain": http_subdomain, **common}).encode())
        if "tcp" in self.local_targets:
            tid = new_tunnel_id()
            self.local_targets[tid] = self.local_targets.pop("tcp")
            await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(
                {"tunnel_id": tid, "type": "tcp", "remote_port": tcp_remote_port, **common}).encode())

    async def run(self):
        while True:
            frame = await read_frame(self.reader)
            if frame.type == FrameType.PING:
                await self._send(FrameType.PONG, CONTROL_STREAM_ID)
            elif frame.type == FrameType.TUNNEL_OPEN_RESPONSE:
                print("[client] tunnel:", frame.payload.decode())
            elif frame.type == FrameType.TUNNEL_CLOSE:
                # Server-initiated revocation: handoff, reclaim, shutdown.
                print("[client] tunnel closed by server:", frame.payload.decode())
            elif frame.type == FrameType.STREAM_OPEN:
                self._on_stream_open(frame)
            elif frame.type == FrameType.STREAM_DATA:
                self._on_stream_data(frame)
            elif frame.type == FrameType.STREAM_EOF:
                self._on_stream_eof(frame)
            elif frame.type == FrameType.STREAM_CLOSE:
                self._teardown(frame.stream_id, notify=False)
            elif frame.type == FrameType.STREAM_WINDOW_UPDATE:
                self._on_window_update(frame)

    def _on_window_update(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None or len(frame.payload) != 4:
            return
        inc = int.from_bytes(frame.payload, "big")
        if not (0 < inc <= INITIAL_WINDOW):
            return
        stream.send_window += inc
        stream.send_event.set()

    def _on_stream_open(self, frame):
        try:
            meta = json.loads(frame.payload.decode())
            tunnel_id = meta["tunnel_id"]
        except (ValueError, KeyError, UnicodeDecodeError):
            return
        stream = Stream(frame.stream_id, tunnel_id)
        self.streams[frame.stream_id] = stream
        asyncio.create_task(self._connect_local(stream))

    async def _connect_local(self, stream: Stream):
        target = self.local_targets.get(stream.tunnel_id)
        if target is None:
            self._teardown(stream.stream_id, notify=True)
            return
        try:
            reader, writer = await asyncio.open_connection(*target)
        except OSError as e:
            print(f"[client] could not reach local backend {target}: {e}")
            self._teardown(stream.stream_id, notify=True)
            return
        if stream.closed:
            writer.close()
            return
        stream.local_reader, stream.local_writer = reader, writer
        # Drain anything that arrived before the backend was ready.
        pending, stream.pending = bytes(stream.pending), bytearray()
        for chunk in _chunks(pending, MAX_FRAME_PAYLOAD):
            if not await self._write_local(stream, chunk):
                return
            await self._credit(stream, len(chunk))
        if stream.pending_eof:
            stream.pending_eof = False
            await self._finish_recv(stream)
        stream.pump_task = asyncio.create_task(self._pump_local_to_server(stream))
        self._maybe_finish(stream)

    def _on_stream_data(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            return
        if stream.local_writer is None:
            if len(stream.pending) + len(frame.payload) > BUFFER_LIMIT:
                print("[client] pre-connect buffer overflow; aborting stream")
                self._teardown(frame.stream_id, notify=True)
                return
            stream.pending.extend(frame.payload)
            return
        asyncio.create_task(self._write_local_then_credit(stream, frame.payload))

    def _on_stream_eof(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            return
        if stream.local_writer is None:
            stream.pending_eof = True
            return
        asyncio.create_task(self._finish_recv(stream))

    async def _write_local_then_credit(self, stream: Stream, payload: bytes):
        if await self._write_local(stream, payload):
            await self._credit(stream, len(payload))

    async def _write_local(self, stream: Stream, payload: bytes) -> bool:
        writer = stream.local_writer
        if stream.closed or writer is None:
            return False
        try:
            writer.write(payload)
            await writer.drain()
        except (ConnectionError, OSError):
            self._teardown(stream.stream_id, notify=True)
            return False
        return True

    async def _credit(self, stream: Stream, n: int):
        """Receive-side flow control: only after the bytes are written locally."""
        if n <= 0 or stream.closed:
            return
        stream.unacked_recv += n
        if stream.unacked_recv >= WINDOW_UPDATE_THRESHOLD:
            increment = min(stream.unacked_recv, INITIAL_WINDOW)
            stream.unacked_recv -= increment
            await self._send(FrameType.STREAM_WINDOW_UPDATE, stream.stream_id,
                             increment.to_bytes(4, "big"))

    async def _finish_recv(self, stream: Stream):
        stream.recv_eof = True
        writer = stream.local_writer
        if writer is not None:
            try:
                writer.write_eof()
                await writer.drain()
            except (ConnectionError, OSError, RuntimeError):
                pass
        self._maybe_finish(stream)

    async def _pump_local_to_server(self, stream: Stream):
        try:
            while not stream.closed:
                await stream.send_event.wait()
                if stream.closed:
                    return
                while stream.send_window <= 0 and not stream.closed:
                    stream.send_event.clear()
                    await stream.send_event.wait()
                if stream.closed:
                    return
                chunk = await stream.local_reader.read(MAX_FRAME_PAYLOAD)
                if not chunk:
                    await self._half_close(stream)
                    return
                view = memoryview(chunk)
                while len(view):
                    allowed = max(1, min(len(view), stream.send_window))
                    piece = bytes(view[:allowed])
                    await self._send(FrameType.STREAM_DATA, stream.stream_id, piece)
                    stream.send_window -= len(piece)
                    view = view[len(piece):]
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            self._teardown(stream.stream_id, notify=True)
        finally:
            self._maybe_finish(stream)

    async def _half_close(self, stream: Stream):
        stream.local_eof = True
        if self.server_supports_eof:
            await self._send(FrameType.STREAM_EOF, stream.stream_id)
            self._maybe_finish(stream)
        else:
            await self._send(FrameType.STREAM_CLOSE, stream.stream_id)
            self._teardown(stream.stream_id, notify=False)

    def _maybe_finish(self, stream: Stream):
        if stream.recv_eof and stream.local_eof:
            self._teardown(stream.stream_id, notify=False)

    def _teardown(self, stream_id: int, *, notify: bool):
        stream = self.streams.pop(stream_id, None)
        if stream is None:
            return
        stream.closed = True
        stream.send_event.set()
        current = asyncio.current_task()
        for task in (stream.write_task, stream.pump_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        if stream.local_writer is not None:
            try:
                stream.local_writer.close()
            except Exception:
                pass
        if notify and self.writer is not None:
            asyncio.create_task(self._send(FrameType.STREAM_CLOSE, stream_id))


def _chunks(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i:i + size]


async def main():
    ap = argparse.ArgumentParser(description="Minimal reference client (illustrative).")
    ap.add_argument("--server", required=True, help="host:port of the proxy's control channel")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--local-http", help="host:port of local HTTP service to expose, e.g. 127.0.0.1:3000")
    ap.add_argument("--subdomain", help="requested subdomain for the HTTP tunnel")
    ap.add_argument("--local-tcp", help="host:port of local TCP service to expose")
    ap.add_argument("--remote-port", type=int, help="preferred public TCP port")
    ap.add_argument("--tls", action="store_true",
                    help="encrypt the control channel (certificate verification is mandatory)")
    ap.add_argument("--ca-cert", help="PEM bundle to verify the server certificate against")
    ap.add_argument("--mode", choices=("handoff", "lease"), default="handoff",
                    help="ownership mode for the requested names: handoff (default, newest "
                         "client wins) or lease (reserve the name; refuse instead of taking over)")
    args = ap.parse_args()

    host, port = args.server.split(":")
    targets = {}
    if args.local_http:
        lh, lp = args.local_http.split(":")
        targets["http"] = (lh, int(lp))
    if args.local_tcp:
        lh, lp = args.local_tcp.split(":")
        targets["tcp"] = (lh, int(lp))

    print("[client] NOTE: illustrative reference only; the supported client is "
          "my_proxy_client/my_proxy.py")
    client = TunnelClient(host, int(port), args.secret, targets,
                          tls=args.tls or bool(args.ca_cert), ca_cert=args.ca_cert)
    await client.connect()
    await client.open_tunnels(args.subdomain, args.remote_port, args.mode)
    await client.run()


if __name__ == "__main__":
    asyncio.run(main())
