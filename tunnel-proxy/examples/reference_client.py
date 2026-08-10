#!/usr/bin/env python3
"""
reference_client.py -- Minimal reference client for proxy_server.py.

This is NOT the deliverable (the task scope is the server), but is
included because the protocol was designed to be implemented by a client,
and a worked example makes the spec unambiguous. It's intentionally
simple: one control connection, HELLO auth, opens one HTTP tunnel and/or
one TCP tunnel, and forwards multiplexed STREAM_* traffic to/from a real
local TCP service (e.g. something listening on 127.0.0.1:3000).

Usage:
    python3 reference_client.py --server proxy.example.com:9000 \\
        --secret <shared_secret> --local-http 127.0.0.1:3000 --subdomain myapp

Persists its client_id in .client_id.json next to this script so that
restarts reconnect as the same client (and can request the same
subdomain/port again).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from protocol import (  # noqa: E402
    CONTROL_STREAM_ID, FrameType, MAX_FRAME_PAYLOAD, NULL_CLIENT_ID,
    build_hello_payload, encode_frame, read_frame, new_tunnel_id,
)

STATE_FILE = os.path.join(os.path.dirname(__file__), ".client_id.json")


def load_client_id() -> bytes:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            hexid = json.load(f)["client_id"]
        return bytes.fromhex(hexid)
    return NULL_CLIENT_ID


def save_client_id(client_id_hex: str):
    with open(STATE_FILE, "w") as f:
        json.dump({"client_id": client_id_hex}, f)


class TunnelClient:
    def __init__(self, host, port, secret, local_targets):
        self.host, self.port, self.secret = host, port, secret
        self.local_targets = local_targets  # {tunnel_id: (local_host, local_port)}
        self.reader = None
        self.writer = None
        self.write_lock = asyncio.Lock()
        self.local_writers = {}  # stream_id -> asyncio.StreamWriter (to local backend)
        self.send_windows = {}   # stream_id -> available credit toward the server

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        client_id_bytes = load_client_id()
        hello = build_hello_payload(self.secret, client_id_bytes)
        await self._send(FrameType.HELLO, CONTROL_STREAM_ID, hello)
        frame = await read_frame(self.reader)
        if frame.type == FrameType.HELLO_FAIL:
            raise RuntimeError(f"auth failed: {frame.payload}")
        info = json.loads(frame.payload.decode())
        save_client_id(info["client_id"])
        print(f"[client] connected, client_id={info['client_id']}")

    async def _send(self, ftype, stream_id, payload=b""):
        async with self.write_lock:
            self.writer.write(encode_frame(ftype, stream_id, payload))
            await self.writer.drain()

    async def open_tunnels(self, http_subdomain, tcp_remote_port):
        if "http" in self.local_targets:
            tid = new_tunnel_id()
            self.local_targets[tid] = self.local_targets.pop("http")
            await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(
                {"tunnel_id": tid, "type": "http", "subdomain": http_subdomain}).encode())
        if "tcp" in self.local_targets:
            tid = new_tunnel_id()
            self.local_targets[tid] = self.local_targets.pop("tcp")
            await self._send(FrameType.TUNNEL_OPEN_REQUEST, CONTROL_STREAM_ID, json.dumps(
                {"tunnel_id": tid, "type": "tcp", "remote_port": tcp_remote_port}).encode())

    async def run(self):
        while True:
            frame = await read_frame(self.reader)
            if frame.type == FrameType.PING:
                await self._send(FrameType.PONG, CONTROL_STREAM_ID)
            elif frame.type == FrameType.TUNNEL_OPEN_RESPONSE:
                print("[client] tunnel:", frame.payload.decode())
            elif frame.type == FrameType.STREAM_OPEN:
                asyncio.create_task(self._handle_stream_open(frame))
            elif frame.type == FrameType.STREAM_DATA:
                await self._handle_stream_data(frame)
            elif frame.type == FrameType.STREAM_CLOSE:
                w = self.local_writers.pop(frame.stream_id, None)
                if w:
                    w.close()
            elif frame.type == FrameType.STREAM_WINDOW_UPDATE:
                inc = int.from_bytes(frame.payload, "big")
                self.send_windows[frame.stream_id] = self.send_windows.get(frame.stream_id, 0) + inc

    async def _handle_stream_open(self, frame):
        meta = json.loads(frame.payload.decode())
        tunnel_id = meta["tunnel_id"]
        local_host, local_port = self.local_targets.get(tunnel_id, (None, None))
        if local_host is None:
            return
        try:
            local_reader, local_writer = await asyncio.open_connection(local_host, local_port)
        except OSError as e:
            print(f"[client] could not reach local backend {local_host}:{local_port}: {e}")
            await self._send(FrameType.STREAM_CLOSE, frame.stream_id)
            return
        self.local_writers[frame.stream_id] = local_writer
        self.send_windows[frame.stream_id] = 256 * 1024  # matches server's INITIAL_WINDOW
        # Pump local backend -> multiplexed connection.
        asyncio.create_task(self._pump_local_to_server(frame.stream_id, local_reader))

    async def _pump_local_to_server(self, stream_id, local_reader):
        try:
            while True:
                chunk = await local_reader.read(MAX_FRAME_PAYLOAD)
                if not chunk:
                    break
                while self.send_windows.get(stream_id, 0) <= 0:
                    await asyncio.sleep(0.01)  # simple poll; a real client would use an Event
                await self._send(FrameType.STREAM_DATA, stream_id, chunk)
                self.send_windows[stream_id] -= len(chunk)
        except (ConnectionError, OSError):
            pass
        finally:
            await self._send(FrameType.STREAM_CLOSE, stream_id)
            self.local_writers.pop(stream_id, None)

    async def _handle_stream_data(self, frame):
        w = self.local_writers.get(frame.stream_id)
        if w is None:
            return
        try:
            w.write(frame.payload)
            await w.drain()
        except (ConnectionError, OSError):
            self.local_writers.pop(frame.stream_id, None)
            await self._send(FrameType.STREAM_CLOSE, frame.stream_id)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="host:port of the proxy's control channel")
    ap.add_argument("--secret", required=True)
    ap.add_argument("--local-http", help="host:port of local HTTP service to expose, e.g. 127.0.0.1:3000")
    ap.add_argument("--subdomain", help="requested subdomain for the HTTP tunnel")
    ap.add_argument("--local-tcp", help="host:port of local TCP service to expose")
    ap.add_argument("--remote-port", type=int, help="preferred public TCP port")
    args = ap.parse_args()

    host, port = args.server.split(":")
    targets = {}
    if args.local_http:
        lh, lp = args.local_http.split(":")
        targets["http"] = (lh, int(lp))
    if args.local_tcp:
        lh, lp = args.local_tcp.split(":")
        targets["tcp"] = (lh, int(lp))

    client = TunnelClient(host, int(port), args.secret, targets)
    await client.connect()
    await client.open_tunnels(args.subdomain, args.remote_port)
    await client.run()


if __name__ == "__main__":
    asyncio.run(main())
