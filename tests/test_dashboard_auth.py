"""Security regression tests for LinkPulse dashboard authentication."""
import json
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1] / "tunnel-proxy"
sys.path.insert(0, str(SERVER_DIR))
import dashboard


class FakeContext:
    def __init__(self, password="top-secret"):
        self.config = {"dashboard_password": password, "jwt_secret": "test-jwt-secret-change-me", "wildcard_domain": "example.test"}
        self.clients = {}
        self.start_time = 0
        self.recent_logs = []


def test_stats_are_not_public_without_session():
    ctx = FakeContext()
    status, body, content_type, headers = dashboard.build_response(ctx, "/api/stats")
    assert status == 401
    assert json.loads(body) == {"error": "authentication_required"}
    assert "no-store" in headers


def test_dashboard_returns_login_not_data_before_auth():
    ctx = FakeContext()
    status, body, content_type, _ = dashboard.build_response(ctx, "/dashboard/")
    assert status == 200
    assert b"Dashboard password" in body
    assert b"Connected Clients" not in body


def test_login_issues_http_only_signed_session():
    ctx = FakeContext()
    headers = {"content-type": "application/x-www-form-urlencoded", "host": "example.test"}
    status, _, _, extra = dashboard.build_response(ctx, "/dashboard/login", "POST", headers, b"password=top-secret")
    assert status == 303
    cookie_line = next(x for x in extra.split("\r\n") if x.startswith("Set-Cookie:"))
    cookie = cookie_line.split(":", 1)[1].strip().split(";", 1)[0]
    assert "HttpOnly" in cookie_line and "SameSite=Strict" in cookie_line
    assert "Secure" not in cookie_line  # direct helper call isn't a TLS listener
    status, body, content_type, _ = dashboard.build_response(ctx, "/api/stats", "GET", {"cookie": cookie})
    assert status == 200
    assert json.loads(body)["clients"] == []


def test_wrong_password_does_not_issue_session():
    ctx = FakeContext()
    headers = {"content-type": "application/x-www-form-urlencoded"}
    status, body, _, extra = dashboard.build_response(ctx, "/dashboard/login", "POST", headers, b"password=wrong")
    assert status == 401
    assert b"Invalid password" in body
    assert "Set-Cookie" not in extra


def test_session_is_signed_and_logout_expires_cookie():
    ctx = FakeContext()
    token = dashboard._issue_session(ctx)
    cookie = f"{dashboard._SESSION_COOKIE}={token}"
    assert dashboard._valid_session(ctx, cookie)
    assert not dashboard._valid_session(ctx, cookie + "x")
    status, _, _, headers = dashboard.build_response(ctx, "/dashboard/logout", "POST", {})
    assert status == 303
    assert "Max-Age=0" in headers


def test_unconfigured_password_or_jwt_secret_fails_closed_and_unknown_routes_404():
    ctx = FakeContext("")
    assert dashboard.build_response(ctx, "/api/stats")[0] == 503
    ctx = FakeContext()
    ctx.config["jwt_secret"] = ""
    assert dashboard.build_response(ctx, "/api/stats")[0] == 503
    ctx.config["jwt_secret"] = "test-jwt-secret-change-me"
    assert dashboard.build_response(ctx, "/not-a-route")[0] == 404

def test_health_remains_available_without_dashboard_password():
    ctx = FakeContext("")
    status, body, _, _ = dashboard.build_response(ctx, "/health")
    assert status == 200 and body == b"healthy\n"


def test_jwt_cookie_and_bearer_auth_are_valid_for_month():
    ctx = FakeContext()
    token = dashboard._issue_session(ctx)
    assert dashboard._valid_token(ctx, token)
    import base64
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert claims["exp"] - claims["iat"] == 31 * 24 * 60 * 60
    status, body, _, _ = dashboard.build_response(ctx, "/api/stats", "GET", {"authorization": "Bearer " + token})
    assert status == 200 and json.loads(body)["clients"] == []
    assert not dashboard._valid_token(ctx, token + "x")


def test_dashboard_public_url_respects_http_only_mode():
    from types import SimpleNamespace

    ctx = FakeContext()
    tunnel = SimpleNamespace(
        type="http", subdomain="myapp", remote_port=None,
        connection_count=0, bytes_in=0, bytes_out=0,
    )
    session = SimpleNamespace(
        client_id="client-123", tunnels={"tunnel-123": tunnel},
        connected_at=0, bytes_in=0, bytes_out=0, streams={},
    )
    ctx.clients = {session.client_id: [session]}

    # TLS is the normal mode, so the dashboard should advertise HTTPS.
    ctx.config["http_only"] = False
    stats = dashboard.build_stats(ctx)
    assert stats["clients"][0]["tunnels"][0]["public_address"] == "https://myapp.example.test"

    # Explicit HTTP-only deployments should keep displaying HTTP.
    ctx.config["http_only"] = True
    stats = dashboard.build_stats(ctx)
    assert stats["clients"][0]["tunnels"][0]["public_address"] == "http://myapp.example.test"
