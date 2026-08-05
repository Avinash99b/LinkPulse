"""
dashboard.py -- Minimal, dependency-light, read-only status dashboard.

Deliberately NOT an admin panel: it exposes GET / (HTML) and
GET /api/stats (JSON) only. No mutation endpoints, no authentication
(per spec), so bind it to a trusted interface / put it behind your own
reverse-auth if you expose it publicly.

Implemented with raw asyncio streams rather than a web framework to keep
dependencies minimal -- the request handling needed here (a couple of
fixed GET routes) is simple enough not to warrant one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

try:
    import psutil
except ImportError:  # optional dependency
    psutil = None

log = logging.getLogger("dashboard")

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
  try { data = await (await fetch('/api/stats')).json(); } catch (e) { return; }

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
    for cid, session in list(ctx.clients.items()):
        tunnels = []
        for tid, t in list(session.tunnels.items()):
            if t.type == "http":
                public_address = f"http://{t.subdomain}.{ctx.config['wildcard_domain']}"
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


async def handle_dashboard_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ctx):
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=5)
        # Drain (and ignore) the rest of the headers -- we don't need them.
        while True:
            h = await asyncio.wait_for(reader.readline(), timeout=5)
            if h in (b"\r\n", b""):
                break

        try:
            _, path, _ = request_line.decode(errors="replace").split(None, 2)
        except ValueError:
            writer.close()
            return

        if path.startswith("/api/stats"):
            body = json.dumps(build_stats(ctx)).encode()
            content_type = "application/json"
        elif path == "/" or path.startswith("/?"):
            body = _HTML.encode()
            content_type = "text/html; charset=utf-8"
        else:
            body = b"not found"
            header = (
                f"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(header + body)
            await writer.drain()
            writer.close()
            return

        header = (
            f"HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        writer.write(header + body)
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    except Exception:
        log.exception("dashboard connection error")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve_dashboard(ctx):
    cfg = ctx.config["dashboard"]
    server = await asyncio.start_server(
        lambda r, w: handle_dashboard_conn(r, w, ctx), cfg["host"], cfg["port"]
    )
    log.info("Dashboard listening on %s:%s", cfg["host"], cfg["port"])
    async with server:
        await server.serve_forever()
