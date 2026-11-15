"""Deployment / container-lifecycle regression tests.

Two layers:
  * fast structural checks that the shipped shell scripts are syntactically
    valid and keep their safety properties (privilege drop, narrow mounts);
  * a *lifecycle* test that drives the real ``startup.sh`` against a mock
    ``docker`` executable, proving an unhealthy deploy rolls back to the exact
    previous container (rename-back), not merely to an image.

No real Docker daemon is touched.
"""

from __future__ import annotations

import json
import copy
import http.server
import importlib.util
import os
import shutil
import socketserver
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402

SERVER_DIR = H.SERVER_DIR
STARTUP = SERVER_DIR / "startup.sh"
ENTRYPOINT = SERVER_DIR / "entrypoint.sh"
DOCKERFILE = SERVER_DIR / "Dockerfile"


# ---------------------------------------------------------------------------
# shell syntax / structural safety
# ---------------------------------------------------------------------------

def test_startup_script_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(STARTUP)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_startup_help_describes_image_only_update():
    result = subprocess.run(["bash", str(STARTUP), "--help"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--action update" in result.stdout
    assert "--no-rebuild" in result.stdout


def test_entrypoint_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(ENTRYPOINT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_entrypoint_drops_privileges_to_unprivileged_user():
    text = ENTRYPOINT.read_text()
    assert "setpriv" in text, "entrypoint must drop privileges with setpriv"
    assert "exec setpriv" in text, "the server must be exec'd as the unprivileged user"
    # It must not exec the server directly as root.
    assert not any(
        line.strip().startswith("exec ") and "proxy_server.py" in line and "setpriv" not in line
        for line in text.splitlines()
    )


def test_entrypoint_uses_one_resolved_interpreter():
    text = ENTRYPOINT.read_text()
    assert "PYTHON_BIN=" in text
    assert '"$PYTHON_BIN"' in text


def test_dockerfile_healthcheck_uses_health_endpoint():
    text = DOCKERFILE.read_text()
    assert "HEALTHCHECK" in text
    assert "/health" in text


def test_startup_uses_narrow_log_mount():
    text = STARTUP.read_text()
    assert "CONTAINER_LOG_DEST=/var/log/tunnel-proxy" in text
    assert '-v "$LOG_DIR:$CONTAINER_LOG_DEST"' in text
    # A broad mount of the host /var/log would let the container write anywhere.
    assert "-v /var/log:/var/log" not in text
    assert "-v /:/" not in text


# ---------------------------------------------------------------------------
# option validation happens before any docker work
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv,needle", [
    (["--action", "bogus"], "action must be"),
    (["--mode", "9"], "mode must be"),
    (["--action"], "requires a value"),
    (["--unknown"], "unknown argument"),
])
def test_startup_rejects_invalid_options_fast(argv, needle):
    result = subprocess.run(["bash", str(STARTUP), *argv],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 1
    assert needle in (result.stderr + result.stdout)


def test_startup_rejects_invalid_range_after_detect(tmp_path):
    """Range validation is a hard failure, not a silent default."""
    env, bin_dir = _mock_docker_env(tmp_path, healthy=False)
    result = subprocess.run(
        ["bash", str(STARTUP), "--action", "redeploy", "--mode", "3",
         "--range", "not-a-range", "--yes"],
        capture_output=True, text=True, timeout=60, env=env, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 1
    assert "invalid range" in (result.stderr + result.stdout)


# ---------------------------------------------------------------------------
# mock docker environment
# ---------------------------------------------------------------------------

_MOCK_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys

state_path = os.environ["MOCK_DOCKER_STATE"]
container = os.environ.get("MOCK_DOCKER_CONTAINER", "tunnel-proxy")
with open(state_path) as fh:
    state = json.load(fh)
argv = sys.argv[1:]
state.setdefault("commands", []).append(argv)
with open(state_path, "w") as fh:
    json.dump(state, fh)

def save():
    with open(state_path, "w") as fh:
        json.dump(state, fh)

def out(text):
    sys.stdout.write(text + "\n")

def remove(name):
    if name in state["containers"]:
        state["containers"].remove(name)

if not argv:
    sys.exit(0)
cmd = argv[0]

if cmd == "info":
    sys.exit(0)
if cmd == "image":
    # image inspect / build
    if "saved_config" in state:
        out(json.dumps([{"Id": "sha256:newimage"}]))
    sys.exit(0)
if cmd == "context":
    out(json.dumps([{"Endpoints": {"docker": {"Host": os.environ["DOCKER_HOST"]}}}]))
    sys.exit(0)
if cmd == "build":
    sys.exit(1 if state.get("build_failure") else 0)
if cmd == "inspect":
    args = argv[1:]
    fmt = ""
    if args and args[0] == "-f":
        fmt = args[1]
        names = args[2:]
    else:
        names = args
    name = names[-1] if names else ""
    if not fmt:
        if name in state["containers"] and "saved_config" in state:
            out(json.dumps([state["saved_config"]]))
        sys.exit(0 if name in state["containers"] else 1)
    if name not in state["containers"]:
        sys.exit(1)
    if ".Image" in fmt:
        out("sha256:previmage")
    elif "PortBindings" in fmt:
        out("80/tcp->0.0.0.0:80 ")
    elif "RestartPolicy" in fmt:
        out("unless-stopped")
    elif ".Created" in fmt:
        out("2026-01-01T00:00:00")
    elif fmt.strip().startswith("{{if .State.Health}}"):
        out("none" if state.get("no_healthcheck") else
            "healthy" if (state["restored"] or state["runs"] >= 2) else "unhealthy")
    elif "/" in fmt:
        out("running/healthy")
    elif ".State.Status" in fmt:
        out("running")
    else:
        out("running")
    sys.exit(0)
if cmd == "port":
    out("80/tcp -> 0.0.0.0:80")
    sys.exit(0)
if cmd == "ps":
    sys.exit(0)
if cmd in ("stop", "start", "restart"):
    sys.exit(0)
if cmd == "exec":
    sys.exit(0 if state.get("exec_healthy") else 1)
if cmd == "rename":
    old, new = argv[1], argv[2]
    state.setdefault("renames", []).append([old, new])
    remove(old)
    if new not in state["containers"]:
        state["containers"].append(new)
    if new == container:
        state["restored"] = True
    save()
    sys.exit(0)
if cmd == "rm":
    args = [a for a in argv[1:] if not a.startswith("-")]
    for name in args:
        remove(name)
    save()
    sys.exit(0)
if cmd == "run":
    name = container
    for i, a in enumerate(argv):
        if a == "--name" and i + 1 < len(argv):
            name = argv[i + 1]
    state["runs"] += 1
    state.setdefault("runs_log", []).append(argv[1:])
    if name not in state["containers"]:
        state["containers"].append(name)
    save()
    sys.exit(0)
if cmd == "logs":
    out("mock container log")
    sys.exit(0)
# Unknown subcommand: succeed quietly.
sys.exit(0)
'''

_MOCK_CURL = r'''#!/usr/bin/env python3
import sys
# No network / metadata service available.
sys.exit(1)
'''

_MOCK_GETENT = r'''#!/usr/bin/env python3
import sys
sys.exit(1)
'''


def _write_exec(path: Path, content: str):
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _mock_docker_env(tmp_path, *, healthy: bool):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    _write_exec(bin_dir / "docker", _MOCK_DOCKER)
    _write_exec(bin_dir / "curl", _MOCK_CURL)
    _write_exec(bin_dir / "getent", _MOCK_GETENT)

    state_path = tmp_path / "docker-state.json"
    state_path.write_text(json.dumps({
        "containers": ["tunnel-proxy"],
        "runs": 0,
        "restored": False,
        "renames": [],
        "runs_log": [],
        "commands": [],
    }))

    env_file = tmp_path / ".env"
    env_file.write_text(
        "WILDCARD_DOMAIN=tunnel.example.test\n"
        "SHARED_SECRET=a-strong-shared-secret\n"
        "DASHBOARD_PASSWORD=a-long-dashboard-password\n"
        "JWT_SECRET=a-high-entropy-jwt-secret\n"
        "HTTP_ONLY=true\n"
    )

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["ENV_FILE"] = str(env_file)
    env["MOCK_DOCKER_STATE"] = str(state_path)
    env["MOCK_DOCKER_CONTAINER"] = "tunnel-proxy"
    # Keep resource args deterministic and avoid touching real dirs.
    env["DATA_DIR"] = str(tmp_path / "data")
    env["LOG_DIR"] = str(tmp_path / "log")
    env["CONTAINER_MEMORY"] = "none"
    env["CONTAINER_CPUS"] = "none"
    (tmp_path / "data").mkdir(exist_ok=True)
    (tmp_path / "log").mkdir(exist_ok=True)
    return env, bin_dir


def test_unhealthy_deploy_restores_the_previous_container(tmp_path):
    env, _bin = _mock_docker_env(tmp_path, healthy=False)
    result = subprocess.run(
        ["bash", str(STARTUP), "--action", "redeploy", "--mode", "3",
         "--range", "20000-20100", "--yes"],
        capture_output=True, text=True, timeout=90,
        env=env, stdin=subprocess.DEVNULL,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 1, out
    assert "unhealthy" in out.lower(), out

    state = json.loads((tmp_path / "docker-state.json").read_text())
    # Exactly one new container was started and then rolled back.
    assert state["runs"] == 1
    assert state["restored"] is True
    assert state["containers"] == ["tunnel-proxy"]

    renames = state["renames"]
    assert any(old == "tunnel-proxy" and new.startswith("tunnel-proxy-backup-")
               for old, new in renames), renames
    backup_name = next(new for old, new in renames
                       if old == "tunnel-proxy" and new.startswith("tunnel-proxy-backup-"))
    assert [backup_name, "tunnel-proxy"] in renames, (
        "rollback must rename the *previous container* back, not just reuse an image")

    # The new container's mount set must be narrow (data + log dirs only).
    run_args = state["runs_log"][0]
    joined = "\n".join(run_args)
    assert f"-v\n{env['DATA_DIR']}:/data" in joined or f"{env['DATA_DIR']}:/data" in joined
    assert f"{env['LOG_DIR']}:/var/log/tunnel-proxy" in joined
    assert "/:/" not in joined
    assert "/var/log:/var/log" not in joined


def test_successful_deploy_keeps_new_container_and_drops_backup(tmp_path):
    """Control: a healthy deploy must NOT restore the backup."""
    # Make the first health check report healthy by pre-seeding runs=1.
    env, _bin = _mock_docker_env(tmp_path, healthy=True)
    state_path = Path(env["MOCK_DOCKER_STATE"])
    state = json.loads(state_path.read_text())
    state["runs"] = 1
    state_path.write_text(json.dumps(state))

    result = subprocess.run(
        ["bash", str(STARTUP), "--action", "redeploy", "--mode", "3",
         "--range", "20000-20100", "--yes"],
        capture_output=True, text=True, timeout=90,
        env=env, stdin=subprocess.DEVNULL,
    )
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    state = json.loads(state_path.read_text())
    assert state["runs"] == 2
    assert state["restored"] is False
    assert state["containers"] == ["tunnel-proxy"]


# ---------------------------------------------------------------------------
# image-only update: real shell/helper talking to a fake local Docker API
# ---------------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location("redeploy_config", SERVER_DIR / "redeploy_config.py")
REDEPLOY_CONFIG = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(REDEPLOY_CONFIG)


def _saved_config(tmp_path, network="bridge"):
    return {
        "Id": "a" * 64,
        "Config": {
            "Image": "tunnel-proxy:old", "Hostname": "saved-hostname",
            "Env": ["SHARED_SECRET=keep-this-secret", "HTTP_PORT=8088", "HTTP_ONLY=true"],
            "Entrypoint": ["/entrypoint.sh"], "Cmd": ["--saved-argument"],
            "Labels": {"deployment": "original"}, "WorkingDir": "/app",
            "Healthcheck": {"Test": ["CMD", "/usr/local/bin/linkpulse-healthcheck"]},
        },
        "HostConfig": {
            "NetworkMode": network, "Memory": 268435456, "NanoCpus": 750000000,
            "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 4},
            "Binds": [f"{tmp_path}/original-data:/data", f"{tmp_path}/original-log:/var/log/tunnel-proxy:ro"],
            "PortBindings": {} if network == "host" else {
                "8088/tcp": [{"HostIp": "127.0.0.2", "HostPort": "18088"}],
                "23001/udp": [{"HostIp": "::1", "HostPort": "23001"}],
            },
            "CapAdd": ["NET_BIND_SERVICE"], "CapDrop": ["NET_RAW"],
            "Sysctls": {} if network == "host" else {"net.ipv4.ip_unprivileged_port_start": "0"},
            "LogConfig": {"Type": "json-file", "Config": {"max-size": "5m"}},
        },
        "Mounts": [],
        "State": {"Paused": False},
        "NetworkSettings": {"Networks": {network: {
            "IPAMConfig": None, "Aliases": None,
            "IPAddress": "172.17.0.2", "EndpointID": "do-not-copy",
        }}},
    }


@pytest.fixture
def update_env(tmp_path):
    env, _ = _mock_docker_env(tmp_path, healthy=True)
    state_path = Path(env["MOCK_DOCKER_STATE"])
    state = json.loads(state_path.read_text())
    state["saved_config"] = _saved_config(tmp_path)
    state["runs"] = 1
    state_path.write_text(json.dumps(state))
    socket_path = tmp_path / "docker.sock"
    env["DOCKER_HOST"] = f"unix://{socket_path}"
    env.pop("DOCKER_CONTEXT", None)
    env["IMAGE"] = "tunnel-proxy:new"
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == "/version"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ApiVersion":"1.47"}')

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.path, body))
            state = json.loads(state_path.read_text())
            if state.get("create_failure"):
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"message":"SHARED_SECRET=keep-this-secret"}')
                return
            state["containers"].append("tunnel-proxy")
            state["runs"] += 1
            state_path.write_text(json.dumps(state))
            self.send_response(201)
            self.end_headers()
            self.wfile.write(b'{"Id":"new-container"}')

        def log_message(self, *args):
            pass

    server = socketserver.UnixStreamServer(str(socket_path), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield env, state_path, received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run_update(env, *args, input=None):
    return subprocess.run(
        ["bash", str(STARTUP), *args], capture_output=True, text=True,
        timeout=30, env=env, input=input,
    )


@pytest.mark.parametrize("network", ["bridge", "host", "custom-network"])
def test_update_preserves_saved_config_without_env_file(update_env, network):
    env, state_path, received = update_env
    Path(env["ENV_FILE"]).unlink()
    state = json.loads(state_path.read_text())
    original = _saved_config(state_path.parent, network)
    state["saved_config"] = original
    state_path.write_text(json.dumps(state))
    result = _run_update(env, "--action", "update", "--yes")
    assert result.returncode == 0, result.stdout + result.stderr
    endpoint, config = received[0]
    assert endpoint == "/v1.47/containers/create?name=tunnel-proxy"
    assert config["Image"] == "sha256:newimage"
    assert config["HostConfig"] == original["HostConfig"]
    assert all(config[key] == value for key, value in original["Config"].items() if key != "Image")
    assert config["NetworkingConfig"] == {"EndpointsConfig": {network: {}}}
    assert "keep-this-secret" not in result.stdout + result.stderr
    state = json.loads(state_path.read_text())
    commands = state["commands"]
    build = next(i for i, cmd in enumerate(commands) if cmd[0] == "build")
    stop = next(i for i, cmd in enumerate(commands) if cmd[0] == "stop")
    assert build < stop
    assert state["containers"] == ["tunnel-proxy"]
    assert not state["restored"]


def test_interactive_update_uses_selected_image_without_rebuild(update_env):
    env, state_path, received = update_env
    result = _run_update(env, "--no-rebuild", input="7\n")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(received) == 1
    assert not any(cmd[0] == "build" for cmd in json.loads(state_path.read_text())["commands"])
    assert "How do you want to deploy" not in result.stdout


@pytest.mark.parametrize("failure", ["build_failure", "create_failure", "unhealthy"])
def test_update_failures_leave_or_restore_original_container(update_env, failure):
    env, state_path, received = update_env
    state = json.loads(state_path.read_text())
    state[failure] = True
    if failure == "unhealthy":
        state["runs"] = 0
    state_path.write_text(json.dumps(state))
    result = _run_update(env, "--action", "update", "--yes")
    assert result.returncode == 1
    assert "keep-this-secret" not in result.stdout + result.stderr
    state = json.loads(state_path.read_text())
    assert state["containers"] == ["tunnel-proxy"]
    if failure == "build_failure":
        assert not received
        assert not any(cmd[0] == "stop" for cmd in state["commands"])
    else:
        assert state["restored"]
        backup = state["renames"][0][1]
        assert [backup, "tunnel-proxy"] in state["renames"]


@pytest.mark.parametrize("args", [
    ["--mode", "4"], ["--range", "24000-24001"], ["--bind", "127.0.0.1"],
    ["--rebuild", "--no-rebuild"],
])
def test_update_rejects_conflicting_options_without_stopping(update_env, args):
    env, state_path, received = update_env
    result = _run_update(env, "--action", "update", "--yes", *args)
    assert result.returncode == 1
    assert not received
    assert not any(cmd[0] == "stop" for cmd in json.loads(state_path.read_text())["commands"])


@pytest.mark.parametrize("unsafe", ["missing", "remote", "auto-remove", "paused"])
def test_update_rejects_unsafe_or_missing_container(update_env, unsafe):
    env, state_path, received = update_env
    state = json.loads(state_path.read_text())
    if unsafe == "missing":
        state["containers"] = []
    elif unsafe == "remote":
        env["DOCKER_HOST"] = "tcp://remote.example:2375"
    elif unsafe == "auto-remove":
        state["saved_config"]["HostConfig"]["AutoRemove"] = True
    else:
        state["saved_config"]["State"]["Paused"] = True
    state_path.write_text(json.dumps(state))
    result = _run_update(env, "--action", "update", "--no-rebuild", "--yes")
    assert result.returncode == 1
    assert not received
    assert not any(cmd[0] == "stop" for cmd in json.loads(state_path.read_text())["commands"])


def test_update_without_healthcheck_probes_inside_container(update_env):
    env, state_path, _ = update_env
    state = json.loads(state_path.read_text())
    state.update(no_healthcheck=True, exec_healthy=True)
    state_path.write_text(json.dumps(state))
    result = _run_update(env, "--action", "update", "--no-rebuild", "--yes")
    assert result.returncode == 0, result.stdout + result.stderr
    state = json.loads(state_path.read_text())
    assert any(cmd[:3] == ["exec", "tunnel-proxy", "python3"] for cmd in state["commands"])


def test_update_reuses_anonymous_volumes_and_only_requested_network_addresses(tmp_path):
    original = _saved_config(tmp_path, "custom")
    original["HostConfig"]["Mounts"] = None
    original["Mounts"] = [
        {"Type": "volume", "Name": "existing-anonymous", "Destination": "/extra", "RW": True},
        {"Type": "volume", "Name": "already-bound", "Destination": "/data", "RW": True},
    ]
    original["NetworkSettings"]["Networks"]["custom"].update(
        IPAMConfig={"IPv4Address": "172.20.0.10"},
        Aliases=["a" * 12, "a" * 64, "tunnel-proxy", "service-alias"],
        DriverOpts={"custom-option": "value"},
    )
    before = copy.deepcopy(original)
    config = REDEPLOY_CONFIG.create_config(original, "sha256:newimage")
    assert original == before
    assert config["HostConfig"]["Mounts"] == [{
        "Type": "volume", "Source": "existing-anonymous", "Target": "/extra", "ReadOnly": False,
    }]
    network = config["NetworkingConfig"]["EndpointsConfig"]["custom"]
    assert network["IPAMConfig"] == {"IPv4Address": "172.20.0.10"}
    assert network["Aliases"] == ["tunnel-proxy", "service-alias"]
    assert "IPAddress" not in network and "EndpointID" not in network


@pytest.mark.parametrize("publish_all", [False, True])
def test_update_pins_automatically_assigned_public_ports(tmp_path, publish_all):
    original = _saved_config(tmp_path)
    original["HostConfig"]["PublishAllPorts"] = publish_all
    original["HostConfig"]["PortBindings"] = {"8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}
    actual = {"8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32768"}]}
    if publish_all:
        actual["443/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": "32769"}]
    original["NetworkSettings"]["Ports"] = actual
    config = REDEPLOY_CONFIG.create_config(original, "sha256:newimage")
    assert config["HostConfig"]["PortBindings"] == actual
    assert not config["HostConfig"]["PublishAllPorts"]
