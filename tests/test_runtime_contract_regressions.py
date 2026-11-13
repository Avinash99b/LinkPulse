"""Runtime contract tests (second pass).

Covers config/env edge cases and cross-component contracts that the first pass
missed:
  * a KEY_PATH-only override must survive config loading;
  * missing WILDCARD_DOMAIN must fail (not inherit the built-in default);
  * invalid boolean env values must fail instead of silently becoming False;
  * dashboard public addresses must follow the *effective* TLS state;
  * process CPU must be cached, not a back-to-back 0.0 sample;
  * a client rejected for server capacity must keep retrying, not exit as if
    its token were wrong;
  * HELLO replay at the exact skew boundary stays rejected after pruning;
  * an unsigned logout token cannot revoke a valid session;
  * logout in one dashboard context cannot revoke another context's session;
  * the real server subprocess hard-fails on placeholder/missing config.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _linkpulse_harness as H  # noqa: E402
import protocol  # noqa: E402
import proxy_server as ps  # noqa: E402
import dashboard  # noqa: E402
import my_proxy  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_dashboard_state():
    dashboard._ACTIVE_JTI.clear()
    dashboard._REVOKED_JTI.clear()
    dashboard._LOGIN_ATTEMPTS.clear()
    yield
    dashboard._ACTIVE_JTI.clear()
    dashboard._REVOKED_JTI.clear()
    dashboard._LOGIN_ATTEMPTS.clear()


@pytest.fixture
def iso_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("LINKPULSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LINKPULSE_LOGS_DIR", str(tmp_path / "logs"))
    for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER", "MY_PROXY_TLS",
                 "MY_PROXY_CA_CERT", "MY_PROXY_RETRY_INTERVAL"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


class FakeDashboardCtx:
    def __init__(self, password="top-secret", jwt="test-jwt-secret-change-me"):
        self.config = {
            "dashboard_password": password,
            "jwt_secret": jwt,
            "wildcard_domain": "example.test",
            "http_only": False,
        }
        self.clients = {}
        self.start_time = 0.0
        self.recent_logs = []
        self.advertise_https = False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_jwt(secret: str, header: dict, claims) -> str:
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{payload}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64(sig)}"


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# ---------------------------------------------------------------------------
# config / env edge cases
# ---------------------------------------------------------------------------

def test_key_path_only_override_is_respected(monkeypatch, tmp_path):
    monkeypatch.setenv("WILDCARD_DOMAIN", "tunnel.example.test")
    monkeypatch.setenv("KEY_PATH", "/custom/control-key.pem")
    monkeypatch.delenv("CERT_PATH", raising=False)
    cfg = ps.load_config()
    assert cfg["tls"]["key_path"] == "/custom/control-key.pem", (
        "KEY_PATH was overwritten when CERT_PATH was not set")
    assert cfg["tls"]["cert_path"].endswith("/tunnel.example.test/fullchain.pem")


def test_missing_wildcard_domain_fails_validation(monkeypatch):
    monkeypatch.setenv("SHARED_SECRET", "a-strong-shared-secret")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "a-long-dashboard-password")
    monkeypatch.setenv("JWT_SECRET", "a-high-entropy-jwt-secret-0123456789abcdef")
    monkeypatch.delenv("WILDCARD_DOMAIN", raising=False)
    cfg = ps.load_config()
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)


def test_invalid_boolean_env_is_rejected(monkeypatch):
    monkeypatch.setenv("HTTP_ONLY", "definitely-not-a-bool")
    with pytest.raises(RuntimeError):
        ps.load_config()
    monkeypatch.setenv("HTTP_ONLY", "true")
    monkeypatch.setenv("CONTROL_TLS", "sometimes")
    with pytest.raises(RuntimeError):
        ps.load_config()


def test_server_subprocess_hard_fails_on_placeholder_secret(iso_env):
    env = os.environ.copy()
    env.update({
        "SHARED_SECRET": "CHANGE_ME",
        "WILDCARD_DOMAIN": "tunnel.example.test",
        "DASHBOARD_PASSWORD": "a-long-dashboard-password",
        "JWT_SECRET": "a-high-entropy-jwt-secret-0123456789abcdef",
        "HTTP_ONLY": "true",
        "CONTROL_PORT": str(H.free_port()),
        "HTTP_PORT": str(H.free_port()),
        "HTTPS_PORT": str(H.free_port()),
        "DASHBOARD_PORT": str(H.free_port()),
        "DB_PATH": str(iso_env / "bad.db"),
        "LOG_FILE": str(iso_env / "bad.log"),
    })
    result = subprocess.run(
        [sys.executable, "proxy_server.py"], cwd=str(H.SERVER_DIR),
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert "Startup failed" in combined
    assert "SHARED_SECRET" in combined


# ---------------------------------------------------------------------------
# dashboard effective TLS + process CPU
# ---------------------------------------------------------------------------

def test_dashboard_public_address_follows_effective_tls():
    ctx = FakeDashboardCtx()
    ctx.config["http_only"] = False
    ctx.advertise_https = False  # HTTP_ONLY=false but no local cert / no upstream TLS
    tunnel = SimpleNamespace(
        type="http", subdomain="myapp", remote_port=None,
        connection_count=0, bytes_in=0, bytes_out=0,
    )
    session = SimpleNamespace(
        client_id="cid", tunnels={"tid": tunnel}, connected_at=0,
        bytes_in=0, bytes_out=0, streams={},
    )
    ctx.clients = {"cid": [session]}
    stats = dashboard.build_stats(ctx)
    address = stats["clients"][0]["tunnels"][0]["public_address"]
    assert address.startswith("http://"), (
        f"advertised scheme must match the effective listener, got {address}")


def test_process_cpu_is_cached_not_back_to_back_zero(monkeypatch):
    """A correct implementation creates the Process object once and samples CPU
    exactly once per refresh (an explicit initial prime may add one sample
    total). It must not prime+read back-to-back, which reports 0.0."""

    class FakeProcess:
        def __init__(self, owner):
            self.owner = owner

        def cpu_percent(self, interval=None):
            self.owner.cpu_calls += 1
            return 12.5

        def memory_info(self):
            return SimpleNamespace(rss=64 * 1024 * 1024)

    class FakePsutil:
        def __init__(self):
            self.instances = 0
            self.cpu_calls = 0

        def Process(self):
            self.instances += 1
            return FakeProcess(self)

    fake = FakePsutil()
    monkeypatch.setattr(dashboard, "psutil", fake)
    ctx = FakeDashboardCtx()
    first = dashboard.build_stats(ctx)["process"]["cpu_percent"]
    second = dashboard.build_stats(ctx)["process"]["cpu_percent"]
    assert first == 12.5 and second == 12.5
    assert fake.instances == 1, (
        "a new psutil.Process object was created per refresh instead of cached")
    assert fake.cpu_calls in (2, 3), (
        f"cpu_percent was sampled {fake.cpu_calls} times for two refreshes; "
        "expected one per refresh (plus at most one initial prime)")


# ---------------------------------------------------------------------------
# server-at-capacity is retryable, not an auth failure
# ---------------------------------------------------------------------------

class CapacityServer:
    def __init__(self):
        self.server = None
        self.port = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        try:
            header = await asyncio.wait_for(reader.readexactly(protocol.HEADER_LEN), timeout=5)
            _magic, _ver, _ftype, _sid, length = struct.unpack("!2sBBII", header)
            if length:
                await reader.readexactly(length)
            body = json.dumps({
                "error": "server at capacity",
                # Modern contract: an explicit retryable marker, not a
                # guessed heuristic on the error string.
                "retryable": True,
            }).encode()
            writer.write(protocol.encode_frame(
                protocol.FrameType.HELLO_FAIL, 0, body))
            await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def stop(self):
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()


def test_capacity_rejection_is_retried_not_treated_as_bad_token(iso_env):
    async def _run():
        server = CapacityServer()
        await server.start()
        env = os.environ.copy()
        env["XDG_CONFIG_HOME"] = str(iso_env / "config")
        env["LINKPULSE_STATE_DIR"] = str(iso_env / "state")
        env["LINKPULSE_LOGS_DIR"] = str(iso_env / "logs")
        for name in ("MY_PROXY_TOKEN", "MY_PROXY_SERVER"):
            env.pop(name, None)
        proc = await asyncio.create_subprocess_exec(
            sys.executable, str(H.CLIENT_DIR / "my_proxy.py"),
            "http", "1",
            "--server", f"127.0.0.1:{server.port}",
            "--token", "test-secret",
            "--no-dashboard",
            "--state-file", str(iso_env / "client-state.json"),
            "--retry-interval", "1",
            "--grace-time", "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        try:
            await asyncio.sleep(2.5)
            alive = proc.returncode is None
            if alive:
                proc.terminate()
            out, _ = await proc.communicate()
            text = out.decode(errors="replace")
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await server.stop()

        assert alive, (
            "client exited after a capacity rejection instead of retrying; "
            f"output: {text[-600:]}")
        assert "check --token" not in text, (
            "capacity rejection was misreported as an authentication/token error")
        assert ("capacity" in text.lower()) or ("retrying" in text.lower()), text[-600:]

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# HELLO replay at the exact skew boundary
# ---------------------------------------------------------------------------

class FakeTime:
    def __init__(self, wall: float, mono: float):
        self.wall = wall
        self.mono = mono

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, delta: float):
        self.wall += delta
        self.mono += delta


def test_replay_at_exact_skew_boundary_survives_prune(monkeypatch):
    fake = FakeTime(wall=1_700_000_000.0, mono=1_000.0)
    monkeypatch.setattr(protocol, "time", fake)
    monkeypatch.setattr(ps, "time", fake)

    payload = protocol.build_hello_payload("a-strong-shared-secret")
    seen: dict = {}
    ok, _cid, err = protocol.verify_hello_payload(payload, "a-strong-shared-secret", seen)
    assert ok and err is None

    # Move to exactly ts + skew: the timestamp is still acceptable, so the
    # nonce must not have been pruned yet.
    fake.advance(protocol.HELLO_TIMESTAMP_SKEW_SECONDS)
    ps._prune_nonces(SimpleNamespace(seen_nonces=seen))
    assert seen, "nonce was pruned at the exact edge of the validity window"

    ok2, _cid2, err2 = protocol.verify_hello_payload(payload, "a-strong-shared-secret", seen)
    assert not ok2 and err2 == "replayed nonce"


# ---------------------------------------------------------------------------
# dashboard logout token validation / context isolation
# ---------------------------------------------------------------------------

def test_unsigned_logout_token_cannot_revoke_a_good_session():
    now = int(time.time())

    def _forged_token(ctx, jti, *, signing_secret, header):
        return _sign_jwt(signing_secret, header, {
            "iss": "linkpulse-dashboard", "iat": now, "exp": now + 3600,
            "jti": jti, "pwv": dashboard._password_version(ctx),
        })

    # Case 1: correct HMAC signature but header alg=none (must be rejected by
    # the alg check, not merely by the signature).
    # Case 2: HS256 header but signed with the wrong secret (must be rejected
    # by signature verification).
    for label, signing_secret, header in (
        ("alg=none", None, {"alg": "none", "typ": "JWT"}),
        ("bad-signature", "the-wrong-secret", {"alg": "HS256", "typ": "JWT"}),
    ):
        ctx = FakeDashboardCtx()
        good = dashboard._issue_session(ctx)
        assert dashboard._valid_token(ctx, good)
        jti = _claims(good)["jti"]
        forged = _forged_token(
            ctx, jti,
            signing_secret=ctx.config["jwt_secret"] if signing_secret is None else signing_secret,
            header=header)
        assert forged != good
        status, _b, _c, _e = dashboard.build_response(
            ctx, "/dashboard/logout", "POST",
            {"cookie": f"{dashboard._SESSION_COOKIE}={forged}"})
        assert status == 303
        assert dashboard._valid_token(ctx, good) is True, (
            f"a {label} logout token revoked a valid session by copying its jti")


def test_logout_is_scoped_to_its_dashboard_context():
    a = FakeDashboardCtx(password="password-a")
    b = FakeDashboardCtx(password="password-b")
    token_a = dashboard._issue_session(a)
    token_b = dashboard._issue_session(b)
    dashboard.build_response(
        a, "/dashboard/logout", "POST",
        {"cookie": f"{dashboard._SESSION_COOKIE}={token_a}"})
    assert dashboard._valid_token(a, token_a) is False
    assert dashboard._valid_token(b, token_b) is True, (
        "logging out one dashboard context invalidated another context's session")