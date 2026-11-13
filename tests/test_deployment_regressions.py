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
import os
import shutil
import stat
import subprocess
import sys
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
    sys.exit(0)
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
        out("healthy" if (state["restored"] or state["runs"] >= 2) else "unhealthy")
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