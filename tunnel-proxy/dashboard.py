"""
dashboard.py -- Minimal, dependency-light, authenticated status dashboard.

The dashboard is private by default. Dashboard HTML and data are served only
when a server-validated login session is present. Set DASHBOARD_PASSWORD and
JWT_SECRET in the environment; without either, the dashboard fails closed and
returns 503. The standalone listener also defaults to loopback.

Implemented with raw asyncio streams to keep dependencies minimal.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import secrets
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
_MAX_TOKEN_LEN = 4096
_MAX_ACTIVE_SESSIONS = 512
_MAX_REVOKED = 4096
_LOGIN_WINDOW_SECONDS = 60
_LOGIN_MAX_ATTEMPTS = 5
_MAX_LOGIN_PEERS = 2048
# Bound concurrent standalone-dashboard connections. The authenticated public
# listener has its own admission cap; this is the separate loopback listener
# used in HTTP-only mode, where unauthenticated slow clients must not be able
# to accumulate handler tasks without limit.
_MAX_CONCURRENT_CONNS = 128

# Legacy module-level aliases retained for compatibility with existing test
# fixtures that clear them. Actual session state is per-context (below) so
# two dashboard contexts in one process can never see or revoke each other's
# tokens.
_ACTIVE_JTI: dict[str, float] = {}
_REVOKED_JTI: dict[str, float] = {}
_LOGIN_ATTEMPTS: dict[str, collections.deque] = {}


def _registries(ctx) -> dict:
    """Per-context, bounded session/login/process state."""
    store = getattr(ctx, "_dashboard_state", None)
    if store is None:
        store = {"active": {}, "revoked": {}, "logins": {}, "process": None}
        try:
            ctx._dashboard_state = store
        except Exception:
            # Contexts that forbid attribute assignment fall back to the
            # module-level aliases (still bounded by the same limits).
            store = {
                "active": _ACTIVE_JTI,
                "revoked": _REVOKED_JTI,
                "logins": _LOGIN_ATTEMPTS,
                "process": None,
            }
    return store


def _password(ctx) -> str:
    return str(ctx.config.get("dashboard_password", "") or "")


def _jwt_secret(ctx) -> str:
    return str(ctx.config.get("jwt_secret", "") or "")


def _password_version(ctx) -> str:
    """A keyed digest of the current password.

    HMAC (keyed by JWT_SECRET) rather than a plain hash, so the token embeds
    no offline-checkable password digest. Rotating the password invalidates
    every previously issued session; rotating the JWT secret does too.
    """
    secret = _jwt_secret(ctx)
    if not secret:
        return ""
    return hmac.new(secret.encode(), ("linkpulse-pwv:" + _password(ctx)).encode(),
                    hashlib.sha256).hexdigest()[:24]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _prune_registry(registry: dict, now: float, cap: int):
    expired = [k for k, exp in registry.items() if exp <= now]
    for k in expired:
        registry.pop(k, None)
    while len(registry) > cap:
        oldest = min(registry, key=registry.get)
        registry.pop(oldest, None)


def _issue_session(ctx) -> str:
    """Issue a compact HS256 JWT valid for 31 days."""
    secret = _jwt_secret(ctx)
    if not secret:
        raise RuntimeError("JWT_SECRET is required")
    now = int(time.time())
    jti = secrets.token_hex(16)
    exp = now + _SESSION_TTL_SECONDS
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {
        "iss": "linkpulse-dashboard",
        "iat": now,
        "exp": exp,
        "jti": jti,
        "pwv": _password_version(ctx),
    }
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    store = _registries(ctx)
    _prune_registry(store["active"], now, _MAX_ACTIVE_SESSIONS - 1)
    store["active"][jti] = exp
    return f"{signing_input}.{_b64url(signature)}"


def _parse_token(token: str):
    """Return the (header, claims, signing_input, signature) or None."""
    if not token or len(token) > _MAX_TOKEN_LEN or token.count(".") != 2:
        return None
    head, payload, signature = token.split(".")
    try:
        header_data = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return header_data, claims, f"{head}.{payload}", supplied


def _valid_token(ctx, token: str) -> bool:
    secret = _jwt_secret(ctx)
    if not secret:
        return False
    parsed = _parse_token(token)
    if parsed is None:
        return False
    header_data, claims, signing_input, supplied = parsed
    # Reject malformed JSON shapes: header and claims must be JSON objects.
    if not isinstance(header_data, dict) or not isinstance(claims, dict):
        return False
    expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        return False
    now = int(time.time())
    if header_data != {"alg": "HS256", "typ": "JWT"}:
        return False
    if claims.get("iss") != "linkpulse-dashboard":
        return False
    iat, exp = claims.get("iat"), claims.get("exp")
    # Exact, positive integers only (bool is an int subclass -> reject).
    if type(iat) is not int or type(exp) is not int or iat <= 0 or exp <= 0:
        return False
    if not (iat - 60 <= now < exp):
        return False
    if exp - iat > _SESSION_TTL_SECONDS:
        return False
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        return False
    if claims.get("pwv") != _password_version(ctx):
        return False
    store = _registries(ctx)
    if store["revoked"].get(jti, 0) > now:
        return False
    if jti not in store["active"]:
        return False
    return True


def _token_jti(token: str):
    parsed = _parse_token(token)
    if parsed is None or not isinstance(parsed[1], dict):
        return None
    jti = parsed[1].get("jti")
    return jti if isinstance(jti, str) and jti else None


def _extract_token(headers: dict) -> str:
    auth_header = headers.get("authorization", "")
    bearer = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if bearer:
        return bearer
    cookie_header = headers.get("cookie", "")
    for part in cookie_header.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            if key == _SESSION_COOKIE:
                return value
    return ""


def _valid_session(ctx, cookie_header: str) -> bool:
    token = ""
    for part in (cookie_header or "").split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            if key == _SESSION_COOKIE:
                token = value
                break
    return _valid_token(ctx, token)


def _check_login_rate(ctx, peer: str) -> tuple[bool, int]:
    """Per-peer, per-context login throttle (5 attempts / 60 s)."""
    if not peer:
        return True, 0
    logins = _registries(ctx)["logins"]
    now = time.monotonic()
    attempts = logins.get(peer)
    if attempts is None:
        attempts = collections.deque()
        if len(logins) >= _MAX_LOGIN_PEERS:
            oldest = min(logins, key=lambda k: logins[k][-1] if logins[k] else 0)
            logins.pop(oldest, None)
        logins[peer] = attempts
    while attempts and now - attempts[0] > _LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
        retry_after = int(_LOGIN_WINDOW_SECONDS - (now - attempts[0])) + 1
        return False, max(1, retry_after)
    attempts.append(now)
    return True, 0


def _login_html(error: str = "") -> bytes:
    message = '<p class="error" role="alert">Invalid password. Please try again.</p>' if error else ""
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
  caption { text-align:left; color:#8a90a2; font-size:12px; padding:0 0 6px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #262b36; }
  th { color:#8a90a2; font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
  .tag { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; background:#26314a; color:#8fb3ff; margin-right:4px; }
  .tag.tcp { background:#312a1a; color:#e8b96a; }
  .tag.lease { background:#1f3326; color:#6ee7a0; }
  section { margin-bottom:28px; }
  h2 { font-size:15px; margin:0 0 10px; color:#c3c7d1; }
  #log { background:#0b0d11; border:1px solid #262b36; border-radius:10px; padding:10px 14px; height:220px; overflow-y:auto; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12px; white-space:pre-wrap; }
  .empty { color:#565c6c; font-style:italic; padding:14px; }
</style>
</head>
<body>
<h1>Tunnel Proxy</h1>
<div class="sub" id="subtitle">loading...</div>

<div class="grid" id="summary-cards" aria-label="Summary"></div>

<section aria-labelledby="clients-heading">
  <h2 id="clients-heading">Connected Clients &amp; Tunnels</h2>
  <div id="clients"></div>
</section>

<section aria-labelledby="log-heading">
  <h2 id="log-heading">Recent Log Messages</h2>
  <div id="log" role="log" aria-live="polite" aria-label="Recent server log messages"></div>
</section>

<script>
function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
    return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c];
  });
}
function safeAddr(u) {
  if (typeof u !== "string") return "";
  try {
    const p = new URL(u);
    if (["http:", "https:", "tcp:", "udp:"].indexOf(p.protocol) !== -1) return esc(u);
  } catch (e) {}
  return "";
}
function typeClass(t) { return (t === "http" || t === "tcp" || t === "udp") ? t : ""; }
function modeName(m) { return (m === "lease") ? "lease" : "handoff"; }
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
    `<div class="card"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></div>`).join('');

  const clientsEl = document.getElementById('clients');
  if (!data.clients.length) {
    clientsEl.innerHTML = '<div class="empty">No clients connected.</div>';
  } else {
    clientsEl.innerHTML = data.clients.map(c => `
      <table style="margin-bottom:14px;">
        <caption>Client ${esc(c.client_id.slice(0,12))}&hellip; &middot; connected ${fmtUptime(c.connected_for)} ago &middot; ${fmtBytes(c.bytes_in)} in / ${fmtBytes(c.bytes_out)} out</caption>
        <thead><tr><th scope="col">Tunnel</th><th scope="col">Type</th><th scope="col">Mode</th><th scope="col">Public address</th><th scope="col">Connections</th><th scope="col">Bytes in</th><th scope="col">Bytes out</th></tr></thead>
        <tbody>
        ${ c.tunnels.length ? c.tunnels.map(t => `
          <tr>
            <td>${esc(t.tunnel_id.slice(0,8))}</td>
            <td><span class="tag ${typeClass(t.type)}">${esc(t.type)}</span></td>
            <td><span class="tag ${t.mode === 'lease' ? 'lease' : ''}">${esc(modeName(t.mode))}</span></td>
            <td>${safeAddr(t.public_address)}</td>
            <td>${esc(t.connections)}</td>
            <td>${fmtBytes(t.bytes_in)}</td>
            <td>${fmtBytes(t.bytes_out)}</td>
          </tr>`).join('') : '<tr><td colspan="7" class="empty">No active tunnels</td></tr>' }
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
    # Advertise the scheme actually in effect (a local HTTPS listener or a
    # trusted upstream terminator), not merely the config flag. FakeContexts
    # without the attribute fall back to the HTTP_ONLY meaning.
    effective_https = getattr(ctx, "advertise_https", not ctx.config.get("http_only"))
    clients = []
    for cid, sessions in list(ctx.clients.items()):
        for session in sessions:
            tunnels = []
            for tid, t in list(session.tunnels.items()):
                if t.type == "http":
                    scheme = "https" if effective_https else "http"
                    public_address = f"{scheme}://{t.subdomain}.{ctx.config['wildcard_domain']}"
                elif t.type == "udp":
                    public_address = f"udp://{ctx.config['wildcard_domain']}:{t.remote_port}"
                else:
                    public_address = f"tcp://{ctx.config['wildcard_domain']}:{t.remote_port}"
                tunnels.append({
                    "tunnel_id": tid,
                    "type": t.type,
                    # Duck-typed tunnel objects (and tunnels created by an
                    # older server) may not carry an ownership mode.
                    "mode": getattr(t, "mode", "handoff"),
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
    store = _registries(ctx)
    if psutil:
        try:
            # Reuse one Process object across dashboard refreshes: creating a
            # new one per request makes back-to-back cpu_percent() calls
            # always report 0. Prime it once, then read the delta.
            p = store.get("process")
            if p is None:
                p = psutil.Process()
                p.cpu_percent(interval=None)
                store["process"] = p
            proc_stats = {
                "cpu_percent": p.cpu_percent(interval=None),
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
                   body: bytes = b"", secure: bool = False, peer: str | None = None):
    """Return (status, body, content-type, extra headers) for dashboard routes.

    `secure` reflects the *actual* listener (or trusted upstream) TLS state so
    the session cookie gets the Secure flag consistently -- it is never read
    from a client-controlled header. `peer` is the connecting IP for the
    login throttle.
    """
    headers = headers or {}
    parsed = urllib.parse.urlsplit(path)
    route = parsed.path
    password = _password(ctx)
    if route == "/health":
        return _response(200, b"healthy\n", "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")
    if not password or not _jwt_secret(ctx):
        return _response(503, b"Dashboard authentication is not configured. Set DASHBOARD_PASSWORD and JWT_SECRET.\n",
                         "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")

    token = _extract_token(headers)
    authenticated = _valid_token(ctx, token)
    if route in ("/", "/dashboard", "/dashboard/") and method == "GET":
        if authenticated:
            return _response(200, _dashboard_html(), "text/html; charset=utf-8",
                             "Cache-Control: no-store\r\n")
        return _response(200, _login_html(), "text/html; charset=utf-8",
                         "Cache-Control: no-store\r\n")

    if route == "/dashboard/login" and method == "GET":
        return _response(200, _login_html(), "text/html; charset=utf-8", "Cache-Control: no-store\r\n")

    if route == "/dashboard/login" and method == "POST":
        allowed, retry_after = _check_login_rate(ctx, peer)
        if not allowed:
            return _response(429, b"Too many login attempts. Please wait and try again.\n",
                             "text/plain; charset=utf-8",
                             f"Retry-After: {retry_after}\r\nCache-Control: no-store\r\n")
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
        if secure:
            cookie_flags += "; Secure"
        return _response(303, b"", "text/plain; charset=utf-8",
                         cookie_flags + "\r\nLocation: /dashboard/\r\nCache-Control: no-store\r\n")

    if route == "/dashboard/logout" and method == "POST":
        # Only revoke a token we actually issued and that is still valid;
        # an unsigned/garbage token must not let anyone poison the registry.
        if token and _valid_token(ctx, token):
            jti = _token_jti(token)
            if jti:
                store = _registries(ctx)
                now = int(time.time())
                _prune_registry(store["revoked"], now, _MAX_REVOKED - 1)
                store["revoked"][jti] = now + _SESSION_TTL_SECONDS
                store["active"].pop(jti, None)
        return _response(303, b"", "text/plain; charset=utf-8",
                         f"Set-Cookie: {_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0\r\nLocation: /dashboard/login\r\nCache-Control: no-store\r\n")

    if route == "/api/stats" and method == "GET":
        if not authenticated:
            return _response(401, b'{"error":"authentication_required"}', "application/json",
                             "Cache-Control: no-store\r\n")
        return _response(200, json.dumps(build_stats(ctx)).encode(), "application/json",
                         "Cache-Control: no-store\r\n")

    return _response(404, b"Not Found\n", "text/plain; charset=utf-8", "Cache-Control: no-store\r\n")


async def handle_dashboard_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx,
                                secure: bool = False):
    try:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        except (asyncio.LimitOverrunError, ValueError):
            writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        if len(request_line) > _MAX_REQUEST_LINE:
            writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        # Bound header memory consumption and parse headers needed for auth.
        header_bytes = 0
        headers = {}
        while True:
            try:
                h = await asyncio.wait_for(reader.readline(), timeout=5)
            except (asyncio.LimitOverrunError, ValueError):
                writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return
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
        peer = (writer.get_extra_info("peername") or ("?", 0))[0]
        status, response_body, content_type, extra_headers = build_response(
            ctx, path, method, headers, body, secure=secure, peer=peer)
        reasons = {200: "OK", 303: "See Other", 401: "Unauthorized", 404: "Not Found",
                   413: "Payload Too Large", 415: "Unsupported Media Type",
                   429: "Too Many Requests", 503: "Service Unavailable"}
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
    secure = str(os.environ.get("DASHBOARD_COOKIE_SECURE", "false")).lower() in ("1", "true", "yes")
    ctx.dashboard_secure_cookie = secure  # retained for compatibility

    active = 0
    tasks: set[asyncio.Task] = set()

    def _accept(reader, writer):
        nonlocal active
        if active >= _MAX_CONCURRENT_CONNS:
            # Reject without spawning a task: an over-cap flood must not create
            # unbounded coroutine state of its own.
            try:
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                writer.close()
            except Exception:
                pass
            return
        active += 1

        async def _run():
            nonlocal active
            try:
                await handle_dashboard_conn(reader, writer, ctx, secure=secure)
            finally:
                active -= 1

        task = asyncio.create_task(_run())
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(_accept, cfg["host"], cfg["port"])
    log.info("Dashboard listening on %s:%s", cfg["host"], cfg["port"])
    # ``start_server`` already serves; wait on an Event instead of
    # serve_forever(). On 3.12, serve_forever() itself awaits wait_closed()
    # while handling cancellation, which would let a slow unauthenticated
    # handler block this finally (and therefore shutdown) until its per-read
    # timeouts.
    stop_forever = asyncio.Event()
    try:
        await stop_forever.wait()
    finally:
        # Cancel-and-await owned handlers before waiting on the listener, so a
        # slow unauthenticated client cannot delay shutdown indefinitely.
        server.close()
        pending = [t for t in tasks if not t.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        tasks.clear()
        try:
            await server.wait_closed()
        except Exception:
            pass
