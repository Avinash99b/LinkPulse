#!/usr/bin/env python3
"""
reference_client.py -- Minimal reference client for proxy_server.py.

This is NOT the deliverable (the task scope is the server), but a worked
example makes the WebSocket message protocol unambiguous. It is
intentionally simple: one WebSocket control connection, HELLO auth, then
it opens one HTTP tunnel and/or any number of TCP tunnels and forwards the
multiplexed stream traffic to/from local TCP services (e.g. a web app on
127.0.0.1:3000, an SSH server, ...).

Unlike the old binary protocol, ALL client <-> server traffic now rides on
a single WebSocket (full-duplex):
  * text messages   = JSON control (hello, tunnel lifecycle, window updates)
  * binary messages = stream data ([stream_id u32be][payload])

Usage:
    python3 reference_client.py --server ws://proxy.example.com/ws \
        --secret <shared_secret> --local-http 127.0.0.1:3000 --subdomain myapp
    python3 reference_client.py --server ws://proxy.example.com/ws \
        --secret <secret> --local-tcp 127.0.0.1:22 --local-tcp 127.0.0.1:3306

`--local-tcp` may be repeated to expose several local ports at once.

Persists its client_id in .client_id.json next to this script so restarts
reconnect as the same client.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from protocol import (  # noqa: E402
    INITIAL_WINDOW, MAX_FRAME_PAYLOAD, NULL_CLIENT_ID,
    WINDOW_UPDATE_THRESHOLD,
    build_hello_payload, encode_stream_data, new_tunnel_id,
)
from ws import open_websocket  # noqa: E402

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


def parse_server(spec: str):
    """Accept either ws://host:port/path or host:port (defaults to /ws)."""
    if "://" not in spec:
        spec = "ws://" + spec
    url = urlparse(spec)
    scheme = url.scheme.lower()
    if scheme not in ("ws", "wss"):
        raise SystemExit("--server must be ws:// or wss:// (got %r)" % url.scheme)
    host = url.hostname or "localhost"
    port = url.port or (443 if scheme == "wss" else 80)
    path = url.path or "/ws"
    if not path.endswith("/ws"):
        path = path.rstrip("/") + "/ws"
    return host, port, path, (scheme == "wss")


class TunnelClient:
    def __init__(self, host, port, path, use_tls, secret, local_targets):
        self.host, self.port, self.path = host, port, path
        self.use_tls = use_tls
        self.secret = secret
        self.local_targets = local_targets  # {tunnel_id: (local_host, local_port)}
        self.ws = None
        self.local_writers = {}   # stream_id -> asyncio.StreamWriter (to local backend)
        self.send_windows = {}    # stream_id -> credit available toward the server
        self.pending_tunnels = {}  # tunnel_id -> human label for responses
        self._unacked = {}  # stream_id -> received-(not-yet-credited) bytes
        self.run = True

    async def connect(self):
        tls = None
        if self.use_tls:
            import ssl
            tls = ssl.create_default_context()
        self.ws = await open_websocket(self.host, self.port, path=self.path, tls=tls)
        client_id_bytes = load_client_id()
        hello = build_hello_payload(self.secret, client_id_bytes)
        await self.ws.send_text(json.dumps({"type": "hello", "sign": hello.hex()}))
        while True:
            kind, payload = await self.ws.recv()
            if kind == "text":
                msg = json.loads(payload)
                break
            if kind in ("close", "error"):
                raise RuntimeError("connection closed during auth: %r" % (payload,))
        if msg.get("type") == "hello_fail":
            raise RuntimeError("auth failed: %s" % msg.get("message"))
        if msg.get("type") != "hello_ok":
            raise RuntimeError("unexpected auth reply: %r" % payload)
        save_client_id(msg["client_id"])
        print("[client] connected as client_id=%s" % msg["client_id"])

    async def open_tunnels(self, http_subdomain, remote_port_pref):
        if "http" in self.local_targets:
            tid = new_tunnel_id()
            self.pending_tunnels[tid] = "http tunnel"
            self.local_targets[tid] = self.local_targets.pop("http")
            await self.ws.send_text(json.dumps({
                "type": "open_tunnel", "tunnel_id": tid, "kind": "http",
                "subdomain": http_subdomain,
            }))
        tcp_entries = self.local_targets.pop("tcp", [])
        for (local_host, local_port) in tcp_entries:
            tid = new_tunnel_id()
            self.pending_tunnels[tid] = "tcp tunnel (port %s)" % local_port
            self.local_targets[tid] = (local_host, int(local_port))
            req = {"type": "open_tunnel", "tunnel_id": tid, "kind": "tcp"}
            if remote_port_pref:
                req["remote_port"] = remote_port_pref
                remote_port_pref = None  # only the first tunnel may prefer a port
            await self.ws.send_text(json.dumps(req))

    async def run(self):
        while self.run:
            kind, payload = await self.ws.recv()
            if kind == "binary":
                await self._handle_stream_data(payload)
            elif kind == "text":
                await self._handle_text(payload)
            elif kind == "close":
                print("[client] connection closed (code=%s)" % payload)
                break
            elif kind == "error":
                print("[client] connection error: %s" % payload)
                break

    async def _handle_text(self, payload):
        try:
            msg = json.loads(payload)
        except (ValueError, TypeError):
            return
        mtype = msg.get("type")
        if mtype == "open_tunnel_response":
            label = self.pending_tunnels.pop(msg.get("tunnel_id", ""), "tunnel")
            if msg.get("status") == "ok":
                extra = msg.get("public_url") or "port %s" % msg.get("remote_port")
                print("[client] %s open OK: %s" % (label, extra))
            else:
                print("[client] %s failed: %s" % (label, msg.get("error")))
        elif mtype == "stream_open":
            await self._handle_stream_open(msg)
        elif mtype == "close_stream":
            w = self.local_writers.pop(msg.get("stream_id"), None)
            if w:
                try:
                    w.close()
                except Exception:
                    pass
        elif mtype == "window_update":
            sid = msg.get("stream_id")
            self.send_windows[sid] = self.send_windows.get(sid, 0) + int(msg.get("increment", 0))

    async def _handle_stream_open(self, msg):
        tunnel_id = msg.get("tunnel_id")
        stream_id = msg.get("stream_id")
        target = self.local_targets.get(tunnel_id)
        if target is None:
            return
        local_host, local_port = target
        try:
            local_reader, local_writer = await asyncio.open_connection(local_host, local_port)
        except OSError as e:
            print("[client] could not reach local backend %s:%s: %s" %
                  (local_host, local_port, e))
            await self.ws.send_text(json.dumps(
                {"type": "close_stream", "stream_id": stream_id}))
            return
        self.local_writers[stream_id] = local_writer
        self.send_windows[stream_id] = INITIAL_WINDOW  # matches server's initial window
        asyncio.ensure_future(self._pump_local_to_server(stream_id, local_reader))

    async def _pump_local_to_server(self, stream_id, local_reader):
        try:
            while True:
                chunk = await local_reader.read(MAX_FRAME_PAYLOAD)
                if not chunk:
                    break
                # Simple credit wait (a production client would use an Event).
                while self.send_windows.get(stream_id, 0) <= 0:
                    await asyncio.sleep(0.005)
                await self.ws.send_binary(encode_stream_data(stream_id, chunk))
                self.send_windows[stream_id] -= len(chunk)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                await self.ws.send_text(json.dumps(
                    {"type": "close_stream", "stream_id": stream_id}))
            except Exception:
                pass
            self.local_writers.pop(stream_id, None)

    async def _handle_stream_data(self, payload):
        if len(payload) < 4:
            return
        stream_id = int.from_bytes(payload[:4], "big")
        data = payload[4:]
        w = self.local_writers.get(stream_id)
        if w is None:
            return
        try:
            w.write(data)
            await w.drain()
        except (ConnectionError, OSError):
            self.local_writers.pop(stream_id, None)
            try:
                await self.ws.send_text(json.dumps(
                    {"type": "close_stream", "stream_id": stream_id}))
            except Exception:
                pass
            return
        # Flow control credit back to the server.
        self._unacked[stream_id] = self._unacked.get(stream_id, 0) + len(data)
        if self._unacked[stream_id] >= WINDOW_UPDATE_THRESHOLD:
            inc = self._unacked[stream_id]
            self._unacked[stream_id] = 0
            try:
                await self.ws.send_text(json.dumps(
                    {"type": "window_update", "stream_id": stream_id, "increment": inc}))
            except Exception:
                pass

    async def shutdown(self):
        for w in list(self.local_writers.values()):
            try:
                w.close()
            except Exception:
                pass
        self.local_writers.clear()
        if self.ws is not None:
            try:
                await self.ws.close()
            except Exception:
                pass


async def main():
    ap = argparse.ArgumentParser(
        description="Reference WebSocket tunnel client. "
                    "Exposes local services via the tunnel proxy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--server", required=True,
                    help="ws://host:port/ws (or host:port) of the proxy")
    ap.add_argument("--secret", required=True, help="shared secret")
    ap.add_argument("--local-http", help="host:port of a local HTTP service to expose")
    ap.add_argument("--subdomain", help="requested subdomain for the HTTP tunnel")
    ap.add_argument("--local-tcp", action="append", metavar="HOST:PORT", default=[],
                    help="host:port of a local TCP service to expose (repeatable)")
    ap.add_argument("--remote-port", type=int,
                    help="preferred public TCP port for the first TCP tunnel")
    args = ap.parse_args()

    host, port, path, use_tls = parse_server(args.server)
    targets = {}
    if args.local_http:
        lh, lp = args.local_http.split(":")
        targets["http"] = (lh, int(lp))
    if args.local_tcp:
        targets["tcp"] = []
        for entry in args.local_tcp:
            lh, lp = entry.split(":")
            targets["tcp"].append((lh, int(lp)))

    client = TunnelClient(host, port, path, use_tls, args.secret, targets)
    try:
        await client.connect()
        await client.open_tunnels(args.subdomain, args.remote_port)
        await client.run()
    finally:
        await client.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass