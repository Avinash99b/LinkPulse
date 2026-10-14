"""
dashboard.py -- Minimal, dependency-light, read-only status dashboard.

The dashboard is private by default. Dashboard HTML and data are served only
when a server-validated login session is present. Set DASHBOARD_PASSWORD in
the environment; without it, the dashboard fails closed and returns 503.
The standalone listener also defaults to loopback.

Implemented with raw asyncio streams to keep dependencies minimal.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import hashlib
import hmac
import time
import urllib.parse

try:
    import psutil
except ImportError:  # optional dependency
    psutil = None

log = logging.getLogger("dashboard")

_SESSION_COOKIE = "linkpulse_dashboard_session"
_SESSION_TTL_SECONDS = 31 * 24 * 60 * 60
_MAX_REQUEST_LINE = 8192
_MAX_HEADERS_BYTES = 16384
_MAX_BODY_BYTES = 8192


def _password(ctx) -> str:
    return str(ctx.config.get("dashboard_password", "") or "")


def _jwt_secret(ctx) -> str:
    return str(ctx.config.get("jwt_secret", "") or "")


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _issue_session(ctx) -> str:
    """Issue a compact HS256 JWT valid for 31 days."""
    if not _jwt_secret(ctx):
        raise RuntimeError("JWT_SECRET is required")
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"iss": "linkpulse-dashboard", "iat": now, "exp": now + _SESSION_TTL_SECONDS}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = hmac.new(_jwt_secret(ctx).encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def _valid_token(ctx, token: str) -> bool:
    secret = _jwt_secret(ctx)
    if not secret or not token or len(token) > 4096:
        return False
    try:
        import base64
        head, payload, signature = token.split(".")
        header_data = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        expected = hmac.new(secret.encode(), f"{head}.{payload}".encode(), hashlib.sha256).digest()
        now = int(time.time())
        return (header_data == {"alg": "HS256", "typ": "JWT"}
                and hmac.compare_digest(supplied, expected)
                and claims.get("iss") == "linkpulse-dashboard"
                and isinstance(claims.get("exp"), int) and now < claims["exp"]
                and isinstance(claims.get("iat"), int) and claims["iat"] <= now + 60
                and claims["exp"] - claims["iat"] <= _SESSION_TTL_SECONDS)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _valid_session(ctx, cookie_header: str) -> bool:
    token = ""
    for part in cookie_header.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            if key == _SESSION_COOKIE:
                token = value
                break
    return _valid_token(ctx, token)


def _login_html(error: str = "") -> bytes:
    message = '<p class="error">Invalid password. Please try again.</p>' if error else ""
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive">
<title>LinkPulse · Private Dashboard</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0c1018;color:#e7ecf5;font:16px system-ui,-apple-system,Segoe UI,sans-serif;padding:24px}
main{width:min(100%,390px);padding:30px;background:#141b27;border:1px solid #2a3547;border-radius:18px;box-shadow:0 24px 70px #0005}h1{font-size:23px;margin:0 0 8px}.sub{color:#99a8bc;font-size:14px;margin:0 0 24px}label{display:block;font-size:13px;color:#bdc8d8;margin:0 0 8px}input{width:100%;padding:13px 14px;border:1px solid #344258;border-radius:10px;background:#0d1420;color:#fff;font:inherit;outline:none}input:focus{border-color:#6ea8fe;box-shadow:0 0 0 3px #6ea8fe26}button{margin-top:14px;width:100%;border:0;border-radius:10px;padding:13px;background:#6ea8fe;color:#07111f;font-weight:700;font-size:15px;cursor:pointer}button:focus-visible{outline:3px solid #fff;outline-offset:3px}.error{color:#ff9c9c;font-size:13px;margin:0 0 14px}.foot{margin-top:20px;font-size:12px;color:#8190a5;text-align:center}
</style></head><body><main><h1>LinkPulse</h1><p class="sub">Private control dashboard · Authentication required</p>{message}<form method="post" action="/dashboard/login" autocomplete="on"><label for="password">Dashboard password</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus maxlength="1024"><button type="submit">Unlock dashboard</button></form><div class="foot">Your password is verified by the server.</div></main></body></html>""").replace("{message}", message).encode()


def _dashboard_html() -> bytes:
    # Existing dashboard UI, with an explicit logout action and no credentials in JS.
    return _HTML.replace('<div class="sub" id="subtitle">loading...</div>',
                         '<div class="sub" id="subtitle">loading...</div><form method="post" action="/dashboard/logout" style="margin:-10px 0 22px;text-align:right"><button type="submit" style="background:#252d3b;color:#d8dbe2;border:1px solid #3a465a;border-radius:8px;padding:8px 12px;cursor:pointer">Lock dashboard</button></form>').encode()


def _response(status: int, body: bytes, content_type: str, extra_headers: str = "") -> tuple[int, bytes, str, str]:
    return status, body, content_type, extra_headers

_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tunnel Proxy Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#d8dbe2; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:#8a90a2; font-size:13px; margin-bottom:20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin-bottom:24px; }
  .card { background:#171a21; border:1px solid #262b36; border-radius:10px; padding:14px 16px; }
  .card .label { font-size:12px; color:#8a90a2; text-transform:uppercase; letter-spacing:.04em; }
  .card .value { font-size:24px; font-weight:600; margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #262b36; }
  th { color:#8a90a2; font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
  .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; background:#26314a; color:#8fb3ff; margin-right:4px; }
  .tag.tcp { background:#312a1a; color:#e8b96a; }
  section { margin-bottom:28px; }
  h2 { font-size:15px; margin:0 0 10px; color:#c3c7d1; }
  #log { background:#0b0d11; border:1px solid #262b36; border-radius:10px; padding:10px 14px; height:220px; overflow-y:auto; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; white-space:pre-wrap; }
  .empty { color:#565c6c; font-style:italic; padding:14px; }
</style>
</head>
<body>
<h1>Tunnel Proxy</h1>
<div class="sub" id="subtitle">loading...</div>

<div class="grid" id="summary-cards"></div>

<section>
  <h2>Connected Clients &amp; Tunnels</h2>
  <div id="clients"></div>
</section>

<section>
  <h2>Recent Log Messages</h2>
  <div id="log"></div>
</section>

<script>
function fmtBytes(n) {
  if (n === undefined) return "0 B";
  const u = ["B","KB","MB","GB","TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtUptime(s) {
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  return (d ? d+"d " : "") + (h ? h+"h " : "") + m+"m";
}
async function refresh() {
  let data;
  try { const response = await fetch('/api/stats', {credentials:'same-origin', cache:'no-store'}); if (response.status === 401) { location.replace('/dashboard/login'); return; } if (!response.ok) return; data = await response.json(); } catch (e) { return; }

  document.getElementById('subtitle').textContent =
    `uptime ${fmtUptime(data.uptime_seconds)} \u00b7 ${data.clients.length} client(s) connected \u00b7 server time ${new Date(data.server_time*1000).toLocaleString()}`;

  let totalTunnels = 0, bytesIn = 0, bytesOut = 0, streams = 0;
  data.clients.forEach(c => {
    totalTunnels += c.tunnels.length;
    bytesIn += c.bytes_in; bytesOut += c.bytes_out;
    streams += c.active_streams;
  });

  const cards = [
    ["Connected clients", data.clients.length],
    ["Active tunnels", totalTunnels],
    ["Active streams", streams],
    ["Bytes in", fmtBytes(bytesIn)],
    ["Bytes out", fmtBytes(bytesOut)],
  ];
  if (data.process && data.process.cpu_percent !== undefined) {
    cards.push(["CPU", data.process.cpu_percent.toFixed(1) + "%"]);
    cards.push(["RAM (RSS)", data.process.rss_mb + " MB"]);
  }
  document.getElementById('summary-cards').innerHTML = cards.map(([l,v]) =>
    `<div class="card"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');

  const clientsEl = document.getElementById('clients');
  if (!data.clients.length) {
    clientsEl.innerHTML = '<div class="empty">No clients connected.</div>';
  } else {
    clientsEl.innerHTML = data.clients.map(c => `
      <table style="margin-bottom:14px;">
        <thead><tr>
          <th colspan="6">Client ${c.client_id.slice(0,12)}&hellip; &middot; connected ${fmtUptime(c.connected_for)} ago &middot; ${fmtBytes(c.bytes_in)} in / ${fmtBytes(c.bytes_out)} out</th>
        </tr>
        <tr><th>Tunnel</th><th>Type</th><th>Public address</th><th>Connections</th><th>Bytes in</th><th>Bytes out</th></tr></thead>
        <tbody>
        ${ c.tunnels.length ? c.tunnels.map(t => `
          <tr>
            <td>${t.tunnel_id.slice(0,8)}</td>
            <td><span class="tag ${t.type}">${t.type}</span></td>
            <td>${t.public_address}</td>
            <td>${t.connections}</td>
            <td>${fmtBytes(t.bytes_in)}</td>
            <td>${fmtBytes(t.bytes_out)}</td>
          </tr>`).join('') : '<tr><td colspan="6" class="empty">No active tunnels</td></tr>' }
        </tbody>
      </table>
    `).join('');
  }

  document.getElementById('log').textContent = data.recent_logs.join('\\n');
  const logEl = document.getElementById('log');
  logEl.scrollTop = logEl.scrollHeight;
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def build_stats(ctx) -> dict:
    now = time.time()
    clients = []
    for cid, sessions in list(ctx.clients.items()):
        for session in sessions:
            tunnels = []
            for tid, t in list(session.tunnels.items()):
                if t.type == "http":
                    scheme = "http" if ctx.config.get("http_only") else "https"
                    public_address = f"{scheme}://{t.subdomain}.{ctx.config['wildcard_domain']}"
                elif t.type == "udp":
                    public_address = f"udp://{ctx.config['wildcard_domain']}:{t.remote_port}"
                else:
                    public_address = f"tcp://{ctx.config['wildcard_domain']}:{t.remote_port}"
                tunnels.append({
                    "tunnel_id": tid,
                    "type": t.type,
                    "public_address": public_address,
                    "connections": t.connection_count,
                    "bytes_in": t.bytes_in,
                    "bytes_out": t.bytes_out,
                })
            clients.append({
                "client_id": cid,
                "connected_since": session.connected_at,
                "connected_for": round(now - session.connected_at),
                "tunnels": tunnels,
                "bytes_in": session.bytes_in,
                "bytes_out": session.bytes_out,
                "active_streams": len(session.streams),
            })

    proc_stats = {}
    if psutil:
        try:
            p = psutil.Process()
            proc_stats = {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "rss_mb": round(p.memory_info().rss / (1024 * 1024), 1),
            }
        except Exception:
            pass

    return {
        "uptime_seconds": round(now - ctx.start_time),
        "clients": clients,
        "recent_logs": list(ctx.recent_logs),
        "process": proc_stats,
        "server_time": now,
    }


def build_response(ctx, path: str, method: str = "GET", headers: dict | None = None,
                   body: bytes = b"") -> tuple[int, bytes, str, str]:
    """Return (status, body, content-type, extra headers) for dashboard routes."""
    headers = headers or {}
    parsed = urllib.parse.urlsplit(path)
    route = parsed.path
    password = _password(ctx)
    if route == "/health":
        return _response(200, b"healthy\n", "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")
    if not password or not _jwt_secret(ctx):
        return _response(503, b"Dashboard authentication is not configured. Set DASHBOARD_PASSWORD and JWT_SECRET.\n",
                         "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")

    cookie = headers.get("cookie", "")
    auth_header = headers.get("authorization", "")
    bearer = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    authenticated = _valid_token(ctx, bearer) or _valid_session(ctx, cookie)
    if route in ("/", "/dashboard", "/dashboard/") and method == "GET":
        if authenticated:
            return _response(200, _dashboard_html(), "text/html; charset=utf-8",
                             "Cache-Control: no-store\r\n")
        return _response(200, _login_html(), "text/html; charset=utf-8",
                         "Cache-Control: no-store\r\n")

    if route == "/dashboard/login" and method == "GET":
        return _response(200, _login_html(), "text/html; charset=utf-8", "Cache-Control: no-store\r\n")

    if route == "/dashboard/login" and method == "POST":
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/x-www-form-urlencoded":
            return _response(415, b"Unsupported Media Type\n", "text/plain; charset=utf-8",
                             "Cache-Control: no-store\r\n")
        try:
            fields = urllib.parse.parse_qs(body.decode("utf-8", errors="strict"), max_num_fields=8)
            supplied = fields.get("password", [""])[0]
        except (UnicodeDecodeError, ValueError):
            supplied = ""
        if len(supplied) > 1024 or not hmac.compare_digest(supplied.encode(), password.encode()):
            return _response(401, _login_html(error=True), "text/html; charset=utf-8",
                             "Cache-Control: no-store\r\n")
        token = _issue_session(ctx)
        cookie_flags = f"Set-Cookie: {_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={_SESSION_TTL_SECONDS}"
        # Set from the actual TLS listener (not an untrusted client header).
        if getattr(ctx, "dashboard_secure_cookie", False):
            cookie_flags += "; Secure"
        return _response(303, b"", "text/plain; charset=utf-8",
                         cookie_flags + "\r\nLocation: /dashboard/\r\nCache-Control: no-store\r\n")

    if route == "/dashboard/logout" and method == "POST":
        return _response(303, b"", "text/plain; charset=utf-8",
                         f"Set-Cookie: {_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\nLocation: /dashboard/login\r\nCache-Control: no-store\r\n")

    if route == "/api/stats" and method == "GET":
        if not authenticated:
            return _response(401, b'{"error":"authentication_required"}', "application/json",
                             "Cache-Control: no-store\r\n")
        return _response(200, json.dumps(build_stats(ctx)).encode(), "application/json",
                         "Cache-Control: no-store\r\n")

    return _response(404, b"Not Found\n", "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")


async def handle_dashboard_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx):
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        if len(request_line) > _MAX_REQUEST_LINE:
            writer.write(b"HTTP/1.1 414 URI Too Long\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        # Bound header memory consumption and parse headers needed for auth.
        header_bytes = 0
        headers = {}
        while True:
            h = await asyncio.wait_for(reader.readline(), timeout=5)
            header_bytes += len(h)
            if header_bytes > _MAX_HEADERS_BYTES:
                writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
            if h in (b"\r\n", b""):
                break
            if b":" in h:
                key, value = h.decode("latin-1").split(":", 1)
                headers[key.strip().lower()] = value.strip()
        try:
            method, path, _ = request_line.decode("latin-1").split(None, 2)
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        method = method.upper()
        content_length = headers.get("content-length", "0")
        try:
            size = int(content_length)
        except ValueError:
            size = -1
        if size < 0 or size > _MAX_BODY_BYTES:
            writer.write(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        body = await asyncio.wait_for(reader.readexactly(size), timeout=5) if size else b""
        status, response_body, content_type, extra_headers = build_response(ctx, path, method, headers, body)
        reasons = {200: "OK", 303: "See Other", 401: "Unauthorized", 404: "Not Found",
                   413: "Payload Too Large", 415: "Unsupported Media Type", 503: "Service Unavailable"}
        reason = reasons.get(status, "Error")
        response_headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"X-Content-Type-Options: nosniff\r\n"
            f"X-Frame-Options: DENY\r\n"
            f"Referrer-Policy: no-referrer\r\n"
            f"Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            f"{extra_headers}"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        writer.write(response_headers + response_body)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    except Exception:
        log.exception("dashboard connection error")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def serve_dashboard(ctx):
    cfg = ctx.config["dashboard"]
    # A TLS-terminating reverse proxy can set DASHBOARD_COOKIE_SECURE=true.
    ctx.dashboard_secure_cookie = str(os.environ.get("DASHBOARD_COOKIE_SECURE", "false")).lower() in ("1", "true", "yes")
    server = await asyncio.start_server(
        lambda r, w: handle_dashboard_conn(r, w, ctx), cfg["host"], cfg["port"]
    )
    log.info("Dashboard listening on %s:%s", cfg["host"], cfg["port"])
    async with server:
        await server.serve_forever()
