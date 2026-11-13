#!/usr/bin/env python3
"""Smoke-test a packaged LinkPulse client binary.

Starts the binary in detached/offline mode (no server is listening), checks that
it registers managed state and can be listed, then lets the binary stop and
remove its own child process. Any failure after the spawn still runs cleanup.

The fallback cleanup never signals an unrelated or reused PID: it re-reads the
recorded process start time and re-verifies it immediately before escalating.

Pure standard library, so it can run in CI and locally with any Python 3.9+:

    python scripts/smoke_packaged_client.py my_proxy_client/dist/my_proxy-linux-amd64

On Windows this module intentionally never calls os.kill(pid, 0): CPython maps
ordinary signal numbers to TerminateProcess, so liveness/termination uses
OpenProcess + GetExitCodeProcess + TerminateProcess with full ctypes prototypes.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

STILL_ACTIVE = 259
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
ERROR_ACCESS_DENIED = 5


def _windows_kernel32():
    """Load kernel32 with complete argv/restype prototypes.

    Without argtypes, ctypes passes HANDLE as a 32-bit c_int, truncating
    64-bit handles. Every API used here is fully declared.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return ctypes, wintypes, kernel32


def process_start_time(pid):
    """Return a stable process start time, or None if it cannot be read.

    Mirrors my_proxy._proc_start_time: Linux /proc, macOS `ps`, Windows
    GetProcessTimes. A None result means ownership cannot be proven.
    """
    if not isinstance(pid, int) or pid <= 0:
        return None

    if sys.platform == "win32":
        try:
            ctypes, wintypes, kernel32 = _windows_kernel32()
        except Exception:
            return None
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return None
        try:
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                    handle, ctypes.byref(created), ctypes.byref(exited),
                    ctypes.byref(kernel), ctypes.byref(user)):
                return None
            return (created.dwHighDateTime << 32) | created.dwLowDateTime
        finally:
            kernel32.CloseHandle(handle)

    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(pid)],
                capture_output=True, text=True, timeout=5)
            text = (out.stdout or "").strip()
            if out.returncode != 0 or not text:
                return None
            return int(time.mktime(time.strptime(text, "%a %b %d %H:%M:%S %Y")))
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    try:
        content = Path(f"/proc/{int(pid)}/stat").read_text()
    except OSError:
        return None
    rparen = content.rfind(")")
    if rparen == -1:
        return None
    rest = content[rparen + 1:].split()
    if len(rest) < 20:
        return None
    try:
        return int(rest[19])
    except ValueError:
        return None


def pid_alive(pid):
    """True only if the process exists and is still running."""
    if not isinstance(pid, int) or pid <= 0:
        return False

    if sys.platform == "win32":
        try:
            ctypes, wintypes, kernel32 = _windows_kernel32()
        except Exception:
            return False
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            # Access denied means it exists but is not queryable.
            return ctypes.get_last_error() == ERROR_ACCESS_DENIED
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def terminate_verified(pid, recorded_start):
    """Stop `pid` only if its current start time still matches the record.

    Re-verifies identity immediately before escalation, so a reused PID is
    never signalled.
    """
    if not pid_alive(pid):
        return True
    if recorded_start is None:
        return False  # cannot prove ownership -> do not signal
    if process_start_time(pid) != recorded_start:
        return False

    if sys.platform == "win32":
        try:
            ctypes, wintypes, kernel32 = _windows_kernel32()
        except Exception:
            return False
        handle = kernel32.OpenProcess(
            PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            False, int(pid))
        if not handle:
            return False
        try:
            # Re-verify creation time on the *same handle* before terminating.
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            if not kernel32.GetProcessTimes(
                    handle, ctypes.byref(created), ctypes.byref(exited),
                    ctypes.byref(kernel), ctypes.byref(user)):
                return False
            if (created.dwHighDateTime << 32) | created.dwLowDateTime != recorded_start:
                return False
            if not kernel32.TerminateProcess(handle, 1):
                return False
            kernel32.WaitForSingleObject(handle, 5000)
        finally:
            kernel32.CloseHandle(handle)
        return not pid_alive(pid)

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)

    # Re-verify identity before escalating: the PID may have been reused.
    if not pid_alive(pid) or process_start_time(pid) != recorded_start:
        return True
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    time.sleep(0.2)
    return not pid_alive(pid) or process_start_time(pid) != recorded_start


def managed_records(state_dir):
    records = []
    for path in sorted(state_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        if isinstance(data, dict):
            records.append((path, data))
    return records


def main(argv):
    if len(argv) != 2:
        print(f"usage: {argv[0]} <packaged-client-binary>", file=sys.stderr)
        return 2
    binary = str(Path(argv[1]).resolve())
    if not Path(binary).is_file():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="linkpulse-smoke-"))
    state_dir = tmp / "clients"
    logs_dir = tmp / "logs"
    state_dir.mkdir()
    logs_dir.mkdir()
    # Machine identity lives OUTSIDE the managed dir, so the managed dir holds
    # exactly one {managed_id}.json per child.
    identity_file = tmp / "machine-identity.json"

    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(tmp)
    env["LINKPULSE_STATE_DIR"] = str(state_dir)
    env["LINKPULSE_LOGS_DIR"] = str(logs_dir)
    env.pop("MY_PROXY_TOKEN", None)
    env.pop("MY_PROXY_SERVER", None)

    def run(*args, timeout=120):
        return subprocess.run(
            [binary, *args], capture_output=True, text=True,
            env=env, timeout=timeout)

    client_id = None
    child_pid = None
    recorded_start = None
    managed_path = None

    try:
        helped = run("--help", timeout=60)
        assert helped.returncode == 0, helped.stdout + helped.stderr

        # The spawn itself is inside the try: a TimeoutExpired here can still
        # leave a child behind, and the finally below recovers managed records.
        try:
            start = run(
                "http", "1", "--detach", "--no-dashboard",
                "--server", "127.0.0.1:1", "--token", "smoke-secret",
                "--retry-interval", "1",
                "--state-file", str(identity_file))
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"detach command timed out: {exc}") from exc

        assert start.returncode == 0, start.stdout + start.stderr
        assert "started in background" in start.stdout, start.stdout

        deadline = time.time() + 20
        while time.time() < deadline:
            ready = [(p, d) for p, d in managed_records(state_dir)
                     if isinstance(d.get("pid"), int) and d["pid"] > 0]
            if ready:
                managed_path, data = ready[0]
                break
            time.sleep(0.2)
        assert managed_path is not None, "detached client never wrote managed state"

        # Use the managed id (file stem / recorded managed_id) as the
        # management handle; `clients list` prints the machine client_id field.
        managed_id = data.get("managed_id") or managed_path.stem
        client_id = data.get("client_id") or managed_id
        child_pid = data["pid"]
        recorded_start = data.get("start_time")
        assert managed_path.name == f"{managed_id}.json", managed_path.name

        listed = run("clients", "list", timeout=60)
        assert listed.returncode == 0, listed.stdout + listed.stderr
        assert client_id in listed.stdout, listed.stdout

        deleted = run("clients", "delete", str(managed_id), timeout=60)
        assert deleted.returncode == 0, deleted.stdout + deleted.stderr
        assert not managed_path.exists(), f"state file still present: {managed_path}"
    finally:
        if child_pid and not terminate_verified(child_pid, recorded_start):
            print(f"warning: could not verify/stop child pid {child_pid}",
                  file=sys.stderr)
        for path, data in managed_records(state_dir):
            pid = data.get("pid")
            if isinstance(pid, int) and pid > 0:
                terminate_verified(pid, data.get("start_time"))
            try:
                path.unlink()
            except OSError:
                pass

    print("packaged client smoke OK:", client_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except AssertionError as exc:
        print(f"smoke FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except subprocess.TimeoutExpired as exc:
        print(f"smoke FAILED (timeout): {exc}", file=sys.stderr)
        raise SystemExit(1)