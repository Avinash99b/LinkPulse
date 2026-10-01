"""Unit and integration tests for LinkPulse client process management and CLI."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

CLIENT_DIR = Path(__file__).resolve().parent.parent / "my_proxy_client"
sys.path.insert(0, str(CLIENT_DIR))

import my_proxy


@pytest.fixture
def temp_env(monkeypatch, tmp_path):
    """Fixture providing isolated state, logs, and config directories."""
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "clients"
    logs_dir = tmp_path / "logs"

    config_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(state_dir))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(logs_dir))

    return {
        "root": tmp_path,
        "config_dir": config_dir,
        "state_dir": state_dir,
        "logs_dir": logs_dir,
    }


class TestCLIArgumentParsing:
    """Tests for CLI options and subcommands."""

    def test_detach_flag_on_http(self):
        parser = my_proxy._build_arg_parser()
        args = parser.parse_args(["http", "8080", "--detach"])
        assert args.command == "http"
        assert args.target == "8080"
        assert args.detach is True

        args_short = parser.parse_args(["http", "8080", "-d"])
        assert args_short.detach is True

    def test_detach_flag_on_tcp(self):
        parser = my_proxy._build_arg_parser()
        args = parser.parse_args(["tcp", "22", "-d", "--remote-port", "20022"])
        assert args.command == "tcp"
        assert args.target == "22"
        assert args.remote_port == 20022
        assert args.detach is True

    def test_detach_flag_on_start(self):
        parser = my_proxy._build_arg_parser()
        args = parser.parse_args(["start", "tunnels.json", "-d"])
        assert args.command == "start"
        assert args.config == "tunnels.json"
        assert args.detach is True

    def test_clients_subcommands(self):
        parser = my_proxy._build_arg_parser()

        # clients list / ls
        a1 = parser.parse_args(["clients", "list"])
        assert a1.command == "clients"
        assert a1.clients_command == "list"

        a2 = parser.parse_args(["client", "ls"])
        assert a2.command == "client"
        assert a2.clients_command == "ls"

        # clients info / show / status
        a3 = parser.parse_args(["clients", "info", "abc12345"])
        assert a3.command == "clients"
        assert a3.clients_command == "info"
        assert a3.client_id == "abc12345"

        a4 = parser.parse_args(["client", "show", "abc12345"])
        assert a4.command == "client"
        assert a4.clients_command == "show"
        assert a4.client_id == "abc12345"

        # clients delete / stop / rm / kill
        a5 = parser.parse_args(["clients", "delete", "abc12345"])
        assert a5.command == "clients"
        assert a5.clients_command == "delete"
        assert a5.client_id == "abc12345"

        a6 = parser.parse_args(["client", "stop", "abc12345"])
        assert a6.command == "client"
        assert a6.clients_command == "stop"
        assert a6.client_id == "abc12345"

    def test_foreground_defaults_unchanged(self):
        parser = my_proxy._build_arg_parser()
        args = parser.parse_args(["http", "8080"])
        assert args.detach is False
        assert args.grace_time == 10.0
        assert args.no_dashboard is False


class TestProcessVerificationAndSafety:
    """Tests ensuring process verification and PID safety."""

    def test_is_pid_alive(self):
        assert my_proxy._is_pid_alive(os.getpid()) is True
        assert my_proxy._is_pid_alive(0) is False
        assert my_proxy._is_pid_alive(-1) is False
        assert my_proxy._is_pid_alive(9999999) is False

    def test_is_pid_alive_start_time_guard(self):
        start = my_proxy._proc_start_time(os.getpid())
        if start is not None:
            assert my_proxy._is_pid_alive(os.getpid(), start) is True
            assert my_proxy._is_pid_alive(os.getpid(), start + 1) is False

    def test_verify_client_process_with_recorded_start_time(self):
        state = {
            "client_id": "test_cid",
            "mode": "http",
            "start_time": my_proxy._proc_start_time(os.getpid()),
        }
        assert my_proxy._verify_client_process(os.getpid(), state) is True

    def test_verify_client_process_rejects_reused_pid(self):
        state = {"client_id": "test_cid", "mode": "http", "start_time": 1}
        assert my_proxy._verify_client_process(os.getpid(), state) is False

    def test_verify_client_process_dead_pid(self):
        state = {"client_id": "test_cid", "mode": "http"}
        assert my_proxy._verify_client_process(9999999, state) is False

class TestStateManagementHelpers:
    """Tests for finding, reading, and formatting client state."""

    def test_format_uptime(self):
        assert my_proxy._format_uptime(None) == "-"
        assert my_proxy._format_uptime(-5) == "-"
        assert my_proxy._format_uptime(30) == "30s"
        assert my_proxy._format_uptime(90) == "1m 30s"
        assert my_proxy._format_uptime(3665) == "1h 1m"
        assert my_proxy._format_uptime(90000) == "1d 1h"

    def test_find_client_state_file_exact(self, temp_env):
        state_dir = temp_env["state_dir"]
        sf = state_dir / "abc123456789.json"
        sf.write_text(json.dumps({"client_id": "abc123456789"}))

        found, err = my_proxy._find_client_state_file("abc123456789")
        assert err is None
        assert found == sf

    def test_find_client_state_file_prefix(self, temp_env):
        state_dir = temp_env["state_dir"]
        sf = state_dir / "abc123456789.json"
        sf.write_text(json.dumps({"client_id": "abc123456789"}))

        found, err = my_proxy._find_client_state_file("abc123")
        assert err is None
        assert found == sf

    def test_find_client_state_file_ambiguous_prefix(self, temp_env):
        state_dir = temp_env["state_dir"]
        (state_dir / "abc111.json").write_text(json.dumps({"client_id": "abc111"}))
        (state_dir / "abc222.json").write_text(json.dumps({"client_id": "abc222"}))

        found, err = my_proxy._find_client_state_file("abc")
        assert found is None
        assert "Ambiguous" in err

    def test_find_client_state_file_not_found(self, temp_env):
        found, err = my_proxy._find_client_state_file("nonexistent")
        assert found is None
        assert "not found" in err

    def test_read_client_state_corrupt(self, temp_env):
        state_dir = temp_env["state_dir"]
        sf = state_dir / "bad.json"
        sf.write_text("invalid json content {{{")

        data = my_proxy._read_client_state(sf)
        assert data["status"] == "corrupt"
        assert data["client_id"] == "bad"


class TestClientsCLICommands:
    """Tests for clients list, info, and delete CLI operations."""

    def test_cli_clients_list_empty(self, temp_env, capsys):
        my_proxy._cli_clients_list()
        captured = capsys.readouterr()
        assert "No LinkPulse clients found." in captured.out

    def test_cli_clients_list_with_clients(self, temp_env, capsys):
        state_dir = temp_env["state_dir"]
        cid1 = "1111222233334444"
        cid2 = "5555666677778888"

        (state_dir / f"{cid1}.json").write_text(json.dumps({
            "client_id": cid1,
            "pid": os.getpid(),  # Alive
            "start_time": my_proxy._proc_start_time(os.getpid()),
            "mode": "http",
            "target": "localhost:8080",
            "server": "127.0.0.1:9000",
            "status": "connected",
            "started_at": time.time(),
        }))

        (state_dir / f"{cid2}.json").write_text(json.dumps({
            "client_id": cid2,
            "pid": 9999998,  # Dead
            "mode": "tcp",
            "target": "localhost:22",
            "server": "127.0.0.1:9000",
            "status": "running",
            "started_at": time.time(),
        }))

        my_proxy._cli_clients_list()
        captured = capsys.readouterr()
        assert "CLIENT ID" in captured.out
        assert cid1 in captured.out
        assert cid2 in captured.out
        assert "running" in captured.out or "connected" in captured.out
        assert "stopped" in captured.out

    def test_cli_clients_info_success(self, temp_env, capsys):
        state_dir = temp_env["state_dir"]
        cid = "aabbccddeeff1122"
        sf = state_dir / f"{cid}.json"
        sf.write_text(json.dumps({
            "client_id": cid,
            "pid": os.getpid(),
            "start_time": my_proxy._proc_start_time(os.getpid()),
            "mode": "http",
            "target": "localhost:8080",
            "server": "proxy.example.com:9000",
            "dashboard": None,
            "started_at": time.time() - 100,
            "started_at_iso": "2026-10-01T14:20:31Z",
            "public_urls": ["https://myapp.forwarding.example.com"],
            "status": "connected",
        }))

        my_proxy._cli_clients_info("aabbcc")
        captured = capsys.readouterr()
        assert f"Client ID:       {cid}" in captured.out
        assert "Mode:            http" in captured.out
        assert "Local target:    localhost:8080" in captured.out
        assert "Public endpoint: https://myapp.forwarding.example.com" in captured.out
        assert "Server:          proxy.example.com:9000" in captured.out

    def test_cli_clients_info_not_found(self, temp_env, capsys):
        with pytest.raises(SystemExit) as exc:
            my_proxy._cli_clients_info("unknown_id")
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Error: Client 'unknown_id' not found." in captured.err

    def test_cli_clients_delete_already_stopped(self, temp_env, capsys):
        state_dir = temp_env["state_dir"]
        cid = "deadclient123456"
        sf = state_dir / f"{cid}.json"
        sf.write_text(json.dumps({
            "client_id": cid,
            "pid": 9999997,  # Dead
            "mode": "http",
            "target": "8080",
        }))

        my_proxy._cli_clients_delete(cid)
        captured = capsys.readouterr()
        assert f"Client {cid} (stopped) removed." in captured.out
        assert not sf.exists()

    def test_cli_clients_delete_running_process(self, temp_env, capsys):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            state_dir = temp_env["state_dir"]
            cid = "liveclient123456"
            sf = state_dir / f"{cid}.json"
            sf.write_text(json.dumps({
                "client_id": cid,
                "pid": proc.pid,
                "start_time": my_proxy._proc_start_time(proc.pid),
                "mode": "tcp",
                "target": "22",
                "status": "running",
            }))

            my_proxy._cli_clients_delete(cid)
            captured = capsys.readouterr()
            assert f"Stopping client {cid} (PID {proc.pid})..." in captured.out
            assert f"Client {cid} stopped and removed." in captured.out
            assert not sf.exists()
            assert not my_proxy._is_pid_alive(proc.pid)
        finally:
            if my_proxy._is_pid_alive(proc.pid):
                proc.kill()

    def test_cli_clients_delete_rejected_for_reused_pid(self, temp_env, capsys):
        """A PID reused by an unrelated process must never be signaled."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            state_dir = temp_env["state_dir"]
            cid = "reusedpid123456"
            sf = state_dir / f"{cid}.json"
            sf.write_text(json.dumps({
                "client_id": cid,
                "pid": proc.pid,
                "start_time": 1,  # does not match proc's real start time
                "mode": "http",
                "target": "8080",
            }))

            my_proxy._cli_clients_delete(cid)
            captured = capsys.readouterr()
            assert f"Client {cid} (stopped) removed." in captured.out
            assert not sf.exists()
            # unrelated process must still be alive
            assert my_proxy._is_pid_alive(proc.pid)
        finally:
            if my_proxy._is_pid_alive(proc.pid):
                proc.kill()


class TestClientsClearCommand:
    """Tests for the clients clear subcommand."""

    def test_clear_empty(self, temp_env, capsys):
        my_proxy._cli_clients_clear(force=False)
        captured = capsys.readouterr()
        assert "No LinkPulse clients found." in captured.out

    def test_clear_removes_only_idle_clients(self, temp_env, capsys):
        state_dir = temp_env["state_dir"]
        idle_cid = "idle111122223333"
        alive_cid = "alive44445555666"

        (state_dir / f"{idle_cid}.json").write_text(json.dumps({
            "client_id": idle_cid,
            "pid": 9999990,  # dead
            "mode": "http",
            "target": "8080",
            "status": "stopped",
        }))
        (state_dir / f"{alive_cid}.json").write_text(json.dumps({
            "client_id": alive_cid,
            "pid": os.getpid(),
            "start_time": my_proxy._proc_start_time(os.getpid()),
            "mode": "tcp",
            "target": "22",
            "status": "connected",
        }))

        my_proxy._cli_clients_clear(force=False)
        captured = capsys.readouterr()

        # idle client removed
        assert not (state_dir / f"{idle_cid}.json").exists()
        assert idle_cid in captured.out
        # alive client skipped
        assert (state_dir / f"{alive_cid}.json").exists()
        assert "Skipped" in captured.out
        assert alive_cid in captured.out
        assert "1 client(s) removed" in captured.out
        assert "1 connected client(s) skipped" in captured.out

    def test_clear_force_removes_all(self, temp_env, capsys):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            state_dir = temp_env["state_dir"]
            idle_cid = "idleforce1234567"
            live_cid = "liveforce7654321"

            (state_dir / f"{idle_cid}.json").write_text(json.dumps({
                "client_id": idle_cid,
                "pid": 9999991,
                "mode": "http",
                "target": "3000",
                "status": "stopped",
            }))
            (state_dir / f"{live_cid}.json").write_text(json.dumps({
                "client_id": live_cid,
                "pid": proc.pid,
                "start_time": my_proxy._proc_start_time(proc.pid),
                "mode": "tcp",
                "target": "22",
                "status": "connected",
            }))

            my_proxy._cli_clients_clear(force=True)
            captured = capsys.readouterr()

            assert not (state_dir / f"{idle_cid}.json").exists()
            assert not (state_dir / f"{live_cid}.json").exists()
            assert "2 client(s) removed" in captured.out
            assert "skipped" not in captured.out.lower()
            assert not my_proxy._is_pid_alive(proc.pid)
        finally:
            if my_proxy._is_pid_alive(proc.pid):
                proc.kill()

    def test_clear_cli_parse(self):
        parser = my_proxy._build_arg_parser()
        args = parser.parse_args(["clients", "clear"])
        assert args.command == "clients"
        assert args.clients_command == "clear"
        assert args.force is False

        args_f = parser.parse_args(["clients", "clear", "-f"])
        assert args_f.force is True

        args_prune = parser.parse_args(["client", "prune", "--force"])
        assert args_prune.command == "client"
        assert args_prune.clients_command == "prune"
        assert args_prune.force is True


class TestDetachedModeLifecycle:
    """Integration tests for detached mode process spawning and survival."""

    def test_spawn_detached_creates_process_and_state(self, temp_env):
        state_dir = temp_env["state_dir"]
        logs_dir = temp_env["logs_dir"]

        parser = my_proxy._build_arg_parser()
        args = parser.parse_args([
            "http", "8080",
            "-d",
            "--server", "127.0.0.1:9000",
            "--token", "secret",
            "--no-dashboard",
        ])

        with pytest.raises(SystemExit) as exc:
            my_proxy._spawn_detached(args, mode="http", target_str="8080")
        assert exc.value.code == 0

        # Verify state file was created
        state_files = list(state_dir.glob("*.json"))
        assert len(state_files) == 1
        sf = state_files[0]
        data = json.loads(sf.read_text())

        assert data["mode"] == "http"
        assert data["target"] == "8080"
        assert data["server"] == "127.0.0.1:9000"
        assert data["pid"] > 0
        child_pid = data["pid"]

        # Verify log file was created
        log_file = Path(data["log_file"])
        assert log_file.exists()

        # Clean up the spawned process
        if my_proxy._is_pid_alive(child_pid):
            try:
                os.kill(child_pid, signal.SIGTERM)
            except OSError:
                pass

