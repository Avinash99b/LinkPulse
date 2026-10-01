"""End-to-end integration tests for LinkPulse detached client and process management."""

import asyncio
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

CLIENT_DIR = Path(__file__).resolve().parent.parent / "my_proxy_client"
CLIENT_SCRIPT = CLIENT_DIR / "my_proxy.py"
sys.path.insert(0, str(CLIENT_DIR))

import my_proxy


class MockTunnelServer:
    """Mock server implementing the wire protocol for end-to-end testing."""

    def __init__(self, host="127.0.0.1", port=0, secret="test-secret"):
        self.host = host
        self.port = port
        self.secret = secret
        self.server = None
        self.opened_tunnels = []
        self.closed_tunnels = []
        self._stop_event = asyncio.Event()

    async def start(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            # Read HELLO frame
            header = await reader.readexactly(12)
            magic, ver, ftype, sid, length = struct.unpack("!2sBBII", header)
            payload = await reader.readexactly(length)
            client_id_bytes = payload[:16]
            cid_hex = client_id_bytes.hex()
            if cid_hex == "0" * 32:
                cid_hex = "0123456789abcdef0123456789abcdef"

            # Send HELLO_OK
            ok_body = json.dumps({"client_id": cid_hex, "heartbeat_interval": 30}).encode()
            ok_header = struct.pack("!2sBBII", b"TN", 1, 0x02, 0, len(ok_body))
            writer.write(ok_header + ok_body)
            await writer.drain()

            while not self._stop_event.is_set():
                header = await reader.readexactly(12)
                magic, ver, ftype, sid, length = struct.unpack("!2sBBII", header)
                payload = await reader.readexactly(length) if length > 0 else b""

                if ftype == 0x06:  # TUNNEL_OPEN_REQUEST
                    req = json.loads(payload.decode())
                    tid = req["tunnel_id"]
                    self.opened_tunnels.append(req)
                    resp = {
                        "tunnel_id": tid,
                        "status": "ok",
                        "public_url": f"https://{req.get('subdomain', 'auto')}.test.local",
                        "remote_port": req.get("remote_port", 20022),
                    }
                    resp_body = json.dumps(resp).encode()
                    resp_hdr = struct.pack("!2sBBII", b"TN", 1, 0x07, 0, len(resp_body))
                    writer.write(resp_hdr + resp_body)
                    await writer.drain()

                elif ftype == 0x08:  # TUNNEL_CLOSE
                    req = json.loads(payload.decode())
                    self.closed_tunnels.append(req)

                elif ftype == 0x04:  # PING
                    pong_hdr = struct.pack("!2sBBII", b"TN", 1, 0x05, 0, 0)
                    writer.write(pong_hdr)
                    await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def stop(self):
        self._stop_event.set()
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def run_cli(*args, env=None):
    cmd = [sys.executable, str(CLIENT_SCRIPT)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def test_detached_mode_end_to_end(tmp_path):
    """Test launching a detached client, checking info/list, and deleting it."""
    async def _run():
        state_dir = tmp_path / "clients"
        logs_dir = tmp_path / "logs"
        config_dir = tmp_path / "config"
        state_dir.mkdir()
        logs_dir.mkdir()
        config_dir.mkdir()

        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = str(tmp_path)
        env["LINKPULSE_STATE_DIR"] = str(state_dir)
        env["LINKPULSE_LOGS_DIR"] = str(logs_dir)

        server = MockTunnelServer()
        await server.start()

        child_pid = None
        client_id = None
        try:
            res = run_cli(
                "http", "8080",
                "--detach",
                "--server", f"127.0.0.1:{server.port}",
                "--token", "test-secret",
                "--no-dashboard",
                env=env,
            )
            assert res.returncode == 0
            assert "LinkPulse client started in background" in res.stdout

            for _ in range(30):
                files = list(state_dir.glob("*.json"))
                if files:
                    data = json.loads(files[0].read_text())
                    if data.get("pid") and data["pid"] > 0:
                        child_pid = data["pid"]
                        client_id = data["client_id"]
                        if data.get("status") in ("running", "connected"):
                            break
                await asyncio.sleep(0.1)

            assert child_pid is not None
            assert my_proxy._is_pid_alive(child_pid)

            list_res = run_cli("clients", "list", env=env)
            assert list_res.returncode == 0
            assert client_id in list_res.stdout
            assert str(child_pid) in list_res.stdout

            info_res = run_cli("clients", "info", client_id, env=env)
            assert info_res.returncode == 0
            assert f"Client ID:       {client_id}" in info_res.stdout
            assert f"PID:             {child_pid}" in info_res.stdout
            assert "Local target:    8080" in info_res.stdout

            del_res = run_cli("clients", "delete", client_id, env=env)
            assert del_res.returncode == 0
            assert f"Client {client_id} stopped and removed." in del_res.stdout

            await asyncio.sleep(0.2)
            assert not my_proxy._is_pid_alive(child_pid)
            assert not (state_dir / f"{client_id}.json").exists()

            empty_list = run_cli("clients", "list", env=env)
            assert "No LinkPulse clients found." in empty_list.stdout

        finally:
            await server.stop()
            if child_pid and my_proxy._is_pid_alive(child_pid):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except OSError:
                    pass

    asyncio.run(_run())



def test_multiple_simultaneous_detached_clients(tmp_path):
    """Test running multiple detached clients simultaneously and managing them."""
    async def _run():
        state_dir = tmp_path / "clients"
        logs_dir = tmp_path / "logs"
        config_dir = tmp_path / "config"
        state_dir.mkdir()
        logs_dir.mkdir()
        config_dir.mkdir()

        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = str(tmp_path)
        env["LINKPULSE_STATE_DIR"] = str(state_dir)
        env["LINKPULSE_LOGS_DIR"] = str(logs_dir)

        server = MockTunnelServer()
        await server.start()

        pids = []
        cids = []

        try:
            # Launch client 1 (HTTP 3000)
            res1 = run_cli("http", "3000", "-d", "--server", f"127.0.0.1:{server.port}", "--token", "test-secret", "--no-dashboard", env=env)
            assert res1.returncode == 0

            # Launch client 2 (TCP 22)
            res2 = run_cli("tcp", "22", "-d", "--server", f"127.0.0.1:{server.port}", "--token", "test-secret", "--no-dashboard", env=env)
            assert res2.returncode == 0

            # Wait for both state files to populate
            for _ in range(30):
                files = list(state_dir.glob("*.json"))
                if len(files) == 2:
                    all_have_pid = True
                    for f in files:
                        try:
                            d = json.loads(f.read_text())
                            if not d.get("pid"):
                                all_have_pid = False
                        except Exception:
                            all_have_pid = False
                    if all_have_pid:
                        break
                await asyncio.sleep(0.1)

            files = list(state_dir.glob("*.json"))
            assert len(files) == 2

            for f in files:
                d = json.loads(f.read_text())
                cids.append(d["client_id"])
                pids.append(d["pid"])

            # Check list shows both
            list_res = run_cli("clients", "list", env=env)
            assert cids[0] in list_res.stdout
            assert cids[1] in list_res.stdout

            # Delete first client
            del1 = run_cli("clients", "delete", cids[0], env=env)
            assert del1.returncode == 0
            assert not (state_dir / f"{cids[0]}.json").exists()

            # Second client should still be listed
            list_res2 = run_cli("clients", "list", env=env)
            assert cids[0] not in list_res2.stdout
            assert cids[1] in list_res2.stdout

            # Delete second client
            del2 = run_cli("clients", "delete", cids[1], env=env)
            assert del2.returncode == 0
            assert not (state_dir / f"{cids[1]}.json").exists()

        finally:
            await server.stop()
            for p in pids:
                if my_proxy._is_pid_alive(p):
                    try:
                        os.kill(p, signal.SIGKILL)
                    except OSError:
                        pass

    asyncio.run(_run())

