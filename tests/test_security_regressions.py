"""Security / protocol / configuration regression tests.

Covers the wire-protocol validation surface, HELLO replay protection,
dashboard session handling (JWT shape, revocation, login throttling, cookie
flags), fail-fast configuration validation, and native control-channel TLS.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import shutil
import ssl
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

sys.path.insert(0, str(H.SERVER_DIR))
import dashboard  # noqa: E402

sys.path.insert(0, str(H.CLIENT_DIR))
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
    monkeypatch.delenv("MY_PROXY_TOKEN", raising=False)
    monkeypatch.delenv("MY_PROXY_SERVER", raising=False)
    return tmp_path


class FakeDashboardContext:
    def __init__(self, password="top-secret", jwt="test-jwt-secret-change-me"):
        self.config = {
            "dashboard_password": password,
            "jwt_secret": jwt,
            "wildcard_domain": "example.test",
            "http_only": True,
        }
        self.clients = {}
        self.start_time = 0.0
        self.recent_logs = []


def _raw_header(magic=b"TN", version=1, ftype=1, stream_id=0, length=0) -> bytes:
    return __import__("struct").pack("!2sBBII", magic, version, int(ftype), stream_id, length)


def _expect_protocol_error(data: bytes):
    async def _read():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        with pytest.raises(protocol.ProtocolError):
            await protocol.read_frame(reader)

    asyncio.run(_read())


# ---------------------------------------------------------------------------
# protocol framing validation
# ---------------------------------------------------------------------------

def test_protocol_rejects_oversized_length():
    _expect_protocol_error(_raw_header(length=protocol.MAX_ALLOWED_LENGTH + 1))


def test_protocol_rejects_bad_magic():
    _expect_protocol_error(_raw_header(magic=b"XX"))


def test_protocol_rejects_unknown_version():
    _expect_protocol_error(_raw_header(version=2))


def test_protocol_enforces_fixed_frame_sizes():
    # PING must be empty; WINDOW_UPDATE must be exactly 4 bytes.
    _expect_protocol_error(_raw_header(ftype=int(protocol.FrameType.PING), length=1) + b"x")
    _expect_protocol_error(
        _raw_header(ftype=int(protocol.FrameType.STREAM_WINDOW_UPDATE), length=3) + b"abc")


def test_protocol_rejects_oversized_udp_datagram():
    _expect_protocol_error(
        _raw_header(ftype=int(protocol.FrameType.UDP_DATAGRAM),
                    length=protocol.UDP_MAX_DATAGRAM + 1))


def test_protocol_constants_match_contract():
    assert protocol.UDP_MAX_DATAGRAM == 65507
    assert protocol.PROTO_VERSION == 1
    assert protocol.MAX_WINDOW_CREDIT == 2 * protocol.INITIAL_WINDOW
    assert protocol.STREAM_CAPABILITY in protocol.SERVER_CAPABILITIES


# ---------------------------------------------------------------------------
# HELLO authentication / replay
# ---------------------------------------------------------------------------

def test_hello_replay_is_rejected(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            payload = H.hello_payload(server.secret)
            reader, writer = await H.raw_connect(server)
            first = await H.raw_hello(reader, writer, payload)
            assert first.type == protocol.FrameType.HELLO_OK
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

            reader2, writer2 = await H.raw_connect(server)
            second = await H.raw_hello(reader2, writer2, payload)
            assert second.type == protocol.FrameType.HELLO_FAIL
            assert "replay" in json.loads(second.payload.decode())["error"].lower()
            writer2.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_hello_wrong_secret_is_rejected(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            reader, writer = await H.raw_connect(server)
            frame = await H.raw_hello(reader, writer,
                                      H.hello_payload("a-different-secret"))
            assert frame.type == protocol.FrameType.HELLO_FAIL
            assert "signature" in json.loads(frame.payload.decode())["error"].lower()
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_hello_timestamp_skew_is_rejected(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            reader, writer = await H.raw_connect(server)
            stale = H.hello_payload(server.secret, ts=int(time.time()) - 3600)
            frame = await H.raw_hello(reader, writer, stale)
            assert frame.type == protocol.FrameType.HELLO_FAIL
            assert "skew" in json.loads(frame.payload.decode())["error"].lower()
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_hello_wrong_payload_length_is_rejected(iso_env):
    async def _run():
        server = await H.start_server(iso_env)
        try:
            reader, writer = await H.raw_connect(server)
            writer.write(protocol.encode_frame(
                protocol.FrameType.HELLO, 0, b"x" * (protocol.HELLO_PAYLOAD_LEN - 1)))
            await writer.drain()
            frame = await H.read_frame_timeout(reader)
            assert frame.type == protocol.FrameType.HELLO_FAIL
            writer.close()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_replayed_nonce_retained_through_validity_window():
    """A nonce must stay rejected for the whole 60s timestamp-skew window.

    The retention expiry is derived from the HELLO timestamp, not the receive
    time, so a replay cannot be stretched by arriving late."""
    seen = {}
    payload = protocol.build_hello_payload("secret-value")
    ok, cid, err = protocol.verify_hello_payload(payload, "secret-value", seen)
    assert ok and err is None
    # Simulate a cleanup pass that runs 'now': the entry must survive.
    cutoff = time.time() - protocol.HELLO_TIMESTAMP_SKEW_SECONDS
    retained = {k: v for k, v in seen.items() if v >= cutoff}
    assert retained, "nonce was pruned while still inside the validity window"
    ok2, _cid2, err2 = protocol.verify_hello_payload(payload, "secret-value", retained)
    assert not ok2 and err2 == "replayed nonce"


# ---------------------------------------------------------------------------
# dashboard session / JWT handling
# ---------------------------------------------------------------------------

def _sign_jwt(secret: str, header: dict, claims) -> str:
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    head = b64(json.dumps(header, separators=(",", ":")).encode())
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{payload}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64(sig)}"


def test_unsigned_alg_none_jwt_is_rejected():
    ctx = FakeDashboardContext()
    now = int(time.time())
    claims = {"iss": "linkpulse-dashboard", "iat": now, "exp": now + 3600,
              "jti": "abc", "pwv": dashboard._password_version(ctx)}
    token = _sign_jwt(ctx.config["jwt_secret"], {"alg": "none", "typ": "JWT"}, claims)
    # Even though it is "signed" with the secret, the header says none -> reject.
    assert dashboard._valid_token(ctx, token) is False


def test_jwt_with_non_object_claims_is_rejected():
    ctx = FakeDashboardContext()
    secret = ctx.config["jwt_secret"]
    for bad_claims in ([1, 2, 3], "not-an-object", 42, None):
        token = _sign_jwt(secret, {"alg": "HS256", "typ": "JWT"}, bad_claims)
        assert dashboard._valid_token(ctx, token) is False


def test_signed_token_not_issued_by_server_is_rejected():
    """Only server-issued (registered) sessions are valid, even with a good sig."""
    ctx = FakeDashboardContext()
    now = int(time.time())
    claims = {"iss": "linkpulse-dashboard", "iat": now, "exp": now + 3600,
              "jti": "never-issued", "pwv": dashboard._password_version(ctx)}
    token = _sign_jwt(ctx.config["jwt_secret"], {"alg": "HS256", "typ": "JWT"}, claims)
    assert dashboard._valid_token(ctx, token) is False


def test_logout_revokes_the_token():
    ctx = FakeDashboardContext()
    token = dashboard._issue_session(ctx)
    assert dashboard._valid_token(ctx, token)
    status, _body, _ct, _extra = dashboard.build_response(
        ctx, "/dashboard/logout", "POST", {"cookie": f"{dashboard._SESSION_COOKIE}={token}"})
    assert status == 303
    assert dashboard._valid_token(ctx, token) is False


def test_password_rotation_invalidates_existing_tokens():
    ctx = FakeDashboardContext()
    token = dashboard._issue_session(ctx)
    assert dashboard._valid_token(ctx, token)
    ctx.config["dashboard_password"] = "a-brand-new-password"
    assert dashboard._valid_token(ctx, token) is False


def test_login_throttle_returns_429_with_retry_after():
    ctx = FakeDashboardContext()
    headers = {"content-type": "application/x-www-form-urlencoded"}
    for _ in range(5):
        status, _b, _c, _e = dashboard.build_response(
            ctx, "/dashboard/login", "POST", headers, b"password=wrong", peer="203.0.113.7")
        assert status == 401
    status, _b, _c, extra = dashboard.build_response(
        ctx, "/dashboard/login", "POST", headers, b"password=wrong", peer="203.0.113.7")
    assert status == 429
    assert "Retry-After:" in extra
    # A different peer is unaffected.
    status2, _b, _c, _e = dashboard.build_response(
        ctx, "/dashboard/login", "POST", headers, b"password=wrong", peer="203.0.113.8")
    assert status2 == 401


def test_session_cookie_is_secure_only_from_actual_tls_state():
    ctx = FakeDashboardContext()
    headers = {"content-type": "application/x-www-form-urlencoded"}
    _s, _b, _c, insecure = dashboard.build_response(
        ctx, "/dashboard/login", "POST", headers, b"password=top-secret", secure=False)
    assert "Secure" not in insecure
    _s, _b, _c, secure = dashboard.build_response(
        ctx, "/dashboard/login", "POST", headers, b"password=top-secret", secure=True)
    assert "Secure" in secure


def test_dashboard_unknown_route_404_and_health_available():
    ctx = FakeDashboardContext()
    assert dashboard.build_response(ctx, "/nope")[0] == 404
    status, body, _ct, _extra = dashboard.build_response(ctx, "/health")
    assert status == 200 and body == b"healthy\n"


def test_dashboard_process_cpu_is_process_not_host(monkeypatch):
    calls = {}

    class FakeProcess:
        def cpu_percent(self, interval=None):
            calls["process"] = True
            return 3.5

        def memory_info(self):
            return SimpleNamespace(rss=64 * 1024 * 1024)

    class FakePsutil:
        Process = FakeProcess

        @staticmethod
        def cpu_percent(interval=None):
            calls["host"] = True
            return 99.0

    monkeypatch.setattr(dashboard, "psutil", FakePsutil)
    stats = dashboard.build_stats(FakeDashboardContext())
    assert stats["process"]["cpu_percent"] == 3.5
    assert calls.get("process") and not calls.get("host")


def test_dashboard_html_escapes_dynamic_values():
    html = dashboard._dashboard_html().decode()
    # No raw interpolation of attacker-influenced fields into markup.
    assert "esc(c.client_id" in html
    assert "esc(t.tunnel_id" in html
    assert "safeAddr(t.public_address)" in html
    assert "${t.public_address}" not in html


# ---------------------------------------------------------------------------
# configuration fail-fast validation
# ---------------------------------------------------------------------------

def _valid_config():
    cfg = json.loads(json.dumps(ps.DEFAULT_CONFIG))
    cfg["shared_secret"] = "a-strong-shared-secret"
    cfg["wildcard_domain"] = "tunnel.example.test"
    cfg["dashboard_password"] = "a-long-dashboard-password"
    cfg["jwt_secret"] = "a-high-entropy-jwt-secret-0123456789abcdef"
    return cfg


def test_validate_config_accepts_a_valid_config():
    ps.validate_config(_valid_config())


@pytest.mark.parametrize("secret", ["", "CHANGE_ME", "change_me", "secret", "short"])
def test_validate_config_rejects_placeholder_or_short_secret(secret):
    cfg = _valid_config()
    cfg["shared_secret"] = secret
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)


def test_validate_config_rejects_missing_domain_and_dashboard_secrets():
    cfg = _valid_config()
    cfg["wildcard_domain"] = ""
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)
    cfg = _valid_config()
    cfg["dashboard_password"] = ""
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)
    cfg = _valid_config()
    cfg["jwt_secret"] = "CHANGE_ME"
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)


def test_validate_config_rejects_invalid_ports_ranges_and_timeouts():
    cfg = _valid_config()
    cfg["http"]["port"] = 70000
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)

    cfg = _valid_config()
    cfg["tcp"]["port_range"] = [30000, 20000]
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)

    cfg = _valid_config()
    cfg["heartbeat_interval_seconds"] = 100
    cfg["heartbeat_timeout_seconds"] = 50
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)

    cfg = _valid_config()
    cfg["http_reconnect_grace_seconds"] = -1
    with pytest.raises(RuntimeError):
        ps.validate_config(cfg)


def test_load_config_rejects_non_integer_env(monkeypatch):
    monkeypatch.setenv("HTTP_RECONNECT_GRACE_SECONDS", "not-a-number")
    with pytest.raises(RuntimeError):
        ps.load_config()


def test_load_config_reads_reconnect_and_limit_env(monkeypatch):
    monkeypatch.setenv("HTTP_RECONNECT_GRACE_SECONDS", "3")
    monkeypatch.setenv("HTTP_RECONNECT_MAX_WAITERS_PER_NAME", "4")
    monkeypatch.setenv("HTTP_RECONNECT_MAX_WAITERS", "5")
    monkeypatch.setenv("MAX_CLIENTS", "7")
    monkeypatch.setenv("UDP_IDLE_TIMEOUT", "9")
    cfg = ps.load_config()
    assert cfg["http_reconnect_grace_seconds"] == 3
    assert cfg["http_reconnect_max_waiters_per_name"] == 4
    assert cfg["http_reconnect_max_waiters"] == 5
    assert cfg["limits"]["max_clients"] == 7
    assert cfg["limits"]["udp_idle_timeout"] == 9


# ---------------------------------------------------------------------------
# native control TLS (openssl is used to mint a throwaway self-signed cert)
# ---------------------------------------------------------------------------

def _make_self_signed(tmp_path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not available")
    cert = tmp_path / "control-cert.pem"
    key = tmp_path / "control-key.pem"
    # Use a config file rather than `-addext`: LibreSSL (the system openssl on
    # macOS) does not implement every OpenSSL 1.1.1 command-line extension flag.
    config = tmp_path / "control-openssl.cnf"
    config.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = localhost\n"
        "[v3]\n"
        "subjectAltName = DNS:localhost,IP:127.0.0.1\n"
    )
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-set_serial", "1", "-config", str(config)],
        check=True, capture_output=True, timeout=60,
    )
    return str(cert), str(key)


def _client_ssl_context(cert_path, *, trust=True):
    if trust:
        ctx = ssl.create_default_context(cafile=cert_path)
    else:
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def test_control_tls_trusted_certificate_succeeds(iso_env):
    cert, key = _make_self_signed(iso_env)

    async def _run():
        server = await H.start_server(iso_env, control_tls=True,
                                      control_cert=cert, control_key=key)
        try:
            ctx = _client_ssl_context(cert, trust=True)
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", server.control_port, ssl=ctx, server_hostname="localhost")
            frame = await H.raw_hello(reader, writer, H.hello_payload(server.secret))
            assert frame.type == protocol.FrameType.HELLO_OK
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        finally:
            await server.stop()

    asyncio.run(_run())


def test_control_tls_untrusted_certificate_fails(iso_env):
    cert, key = _make_self_signed(iso_env)

    async def _run():
        server = await H.start_server(iso_env, control_tls=True,
                                      control_cert=cert, control_key=key)
        try:
            ctx = _client_ssl_context(cert, trust=False)
            with pytest.raises(ssl.SSLError):
                await asyncio.open_connection(
                    "127.0.0.1", server.control_port, ssl=ctx, server_hostname="localhost")
        finally:
            await server.stop()

    asyncio.run(_run())


def test_control_tls_with_missing_certificates_fails_startup():
    cfg = _valid_config()
    cfg["control"]["tls"] = True
    cfg["control"]["cert_path"] = "/nonexistent/control-cert.pem"
    cfg["control"]["key_path"] = "/nonexistent/control-key.pem"
    cfg["tls"]["cert_path"] = "/nonexistent/cert.pem"
    cfg["tls"]["key_path"] = "/nonexistent/key.pem"
    with pytest.raises(RuntimeError):
        ps._load_control_ssl_context(cfg)


def test_client_tls_context_always_verifies():
    ctx = my_proxy.TunnelClient._make_ssl_context(SimpleNamespace(ca_cert=None))
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED