# Self-Hosted Tunneling Proxy

A minimal, self-hosted alternative to ngrok. One `proxy_server.py`, no external services (SQLite + local files only), automatic wildcard DNS routing, HTTP host-based routing, and randomly allocated TCP ports for raw TCP tunnels.

```
                                          ┌────────────────────────────────────┐
    HTTP  app.tunnel.example.com          │         Single container           │
    ───────────────────────────────────▶  │  :80  haproxy (HTTP front door)    │
                                          │         │                          │
    WebSocket control (/ws)               │         ▼                          │
    ───────────────────────────────────▶  │   nginx :8088 (HTTP)               │
                                          │         │                          │
                                          │   proxy_server.py                  │◀───multiplexed───▶  client
                                          │  - /ws control (auth)              │      connection     (your
                                          │  - HTTP router                     │                       laptop /
                                          │  - TCP listeners                  │                       server)
                                          │  - SQLite bookkeeping             │
                                          └────────────────────────────────────┘
```

## Key Features

- **Authentication**: HMAC-SHA256 challenge-response (no shared secret sent over wire)
- **HTTP routing**: Host header–based. `app.tunnel.example.com` → tunnels traffic to the registered client
- **TCP routing**: Random port allocation (or preferred port, if free). Concurrent TCP listeners, one per tunnel
- **Multiplexing**: One persistent WebSocket connection carries many logical streams. Each stream = one HTTP request-connection or one TCP connection
- **Flow control**: Per-stream, credit-based (HTTP/2 style). Backpressure-aware. Prevents one slow tunnel from stalling others
- **Single public port**: Port 80 for HTTP tunnels, the dashboard, *and* the WebSocket control plane. Works with cloud platforms that terminate TLS at the edge and forward HTTP to the container.
- **SSL termination**: Handled externally (Render, Cloudflare, or your own nginx). Proxy server runs HTTP only.
- **Dashboard**: Real-time client/tunnel status, bytes transferred, connection counts, uptime, logs, optional CPU/RAM
- **SQLite**: Lightweight persistence for bookkeeping & observability
- **No external services**: Just the proxy binary + SQLite + local files
- **Docker ready**: Single container (supervisord runs tunnel-proxy + nginx + haproxy), multi-stage build, resource limits optimized for 512MB RAM / 0.5 vCPU
- **Environment-based config**: No config files needed, all via environment variables
- **Auto directory creation**: DB and log directories created automatically

## Quick Start

### 1. Manual Docker Run (Recommended)

```bash
# Copy environment template
cp .env.example .env

# Edit with your values
# Required: SHARED_SECRET, WILDCARD_DOMAIN
vim .env

# Build
docker build -t tunnel-proxy .

# Run - port 80 (HTTP tunnels + dashboard + WebSocket control) exposed
docker run -d \
  --name tunnel-proxy \
  -p 80:80 \
  --env-file .env \
  -v tunnel-proxy-data:/data \
  -v tunnel-proxy-logs:/var/log/tunnel-proxy \
  tunnel-proxy

# Check health
curl http://localhost/health
```

### 2. Direct Python Run (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Run with environment variables
SHARED_SECRET="your-secret" \
WILDCARD_DOMAIN="tunnel.example.com" \
HTTP_PORT=8080 \
python3 proxy_server.py
```

> The dev run binds HTTP (tunnels + `/ws` control plane) on `:8080` and dashboard on `:8081` directly (no HAProxy/nginx in front).

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHARED_SECRET` | **Yes** | - | Authentication secret (generate with `openssl rand -hex 32`) |
| `WILDCARD_DOMAIN` | **Yes** | - | Wildcard domain for tunnels (e.g., `tunnel.example.com`) |
| `HTTP_HOST` | No | `0.0.0.0` | HTTP server bind host (tunnels + `/ws` control plane) |
| `HTTP_PORT` | No | `8080` | HTTP server port |
| `TCP_PORT_MIN` | No | `20000` | TCP port range minimum |
| `TCP_PORT_MAX` | No | `20100` | TCP port range maximum |
| `DASHBOARD_HOST` | No | `0.0.0.0` | Dashboard bind host |
| `DASHBOARD_PORT` | No | `8081` | Dashboard port |
| `HTTP_ONLY` | No | `true` | Use http:// URLs |
| `HEARTBEAT_INTERVAL` | No | `20` | Heartbeat interval (seconds) |
| `HEARTBEAT_TIMEOUT` | No | `60` | Heartbeat timeout (seconds) |
| `STALE_GRACE_SECONDS` | No | `300` | Stale client cleanup grace |
| `DB_PATH` | No | `/data/tunnel_proxy.db` | SQLite database path |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `LOG_FILE` | No | `/var/log/tunnel-proxy/tunnel_proxy.log` | Log file path |

**Only `SHARED_SECRET` and `WILDCARD_DOMAIN` are required.** All other variables have sensible defaults.

**Directories are auto-created**: The server automatically creates `/data` and `/var/log/tunnel-proxy` directories if they don't exist.

## Container Architecture

One public port, three internal processes under supervisord:

```
:80  (haproxy) ──────────────────────────── HTTP tunnels + dashboard + /ws control
  └─ → nginx http :8088
        ├─ /dashboard/, /api/ → dashboard :8081
        └─ everything else    → proxy_server :8080 (tunnel HTTP + WebSocket /ws)
```

- **haproxy** — HTTP front door on the single public port 80 (`haproxy.cfg`)
- **nginx** — HTTP reverse proxy routing dashboard vs tunnel traffic (`nginx.conf`)
- **proxy_server.py** — the tunnel proxy itself (`supervisord.conf`)

**Why one port?** The client control plane is a WebSocket that rides on the same HTTP listener as the tunnels, so port 80 carries everything. Render (and most cloud platforms) terminate HTTPS at the edge and forward HTTP to the container's port 80.

**Render / persistent disk note:** The container includes an `entrypoint.sh` that runs as root on startup, `chown`s all writable directories (`/data`, `/var/log/...`, `/run/...`) to the `tunnelproxy` user, then hands off to supervisord. This makes the container work with Render's persistent disks (which mount as root) without permission issues.

## Render Deployment

### Manual Render Setup

1. Create a new Web Service
2. Use Docker runtime with `Dockerfile`
3. Set plan to **Starter** (512MB RAM, 0.5 CPU)
4. Add **required** environment variables:
   - `SHARED_SECRET`
   - `WILDCARD_DOMAIN`
5. Add persistent disk at `/data` (1GB)
6. Set **Ports** to `80` (HTTP)
7. Deploy

**Note:** Render handles HTTPS termination automatically on port 443 and forwards HTTP to container port 80. The WebSocket control plane and all tunnels ride that same port. Point `*.yourdomain` and `yourdomain` at the service.

## SSL/TLS

**HTTPS termination is handled externally** (Render, Cloudflare, or your own reverse proxy). The container exposes HTTP on port 80 only. No SSL certificates, Let's Encrypt, or certbot needed.

## Client Usage

```bash
# Using the reference client
python3 examples/reference_client.py \
  --server ws://your-server/ws \
  --secret your-shared-secret \
  --local-http 127.0.0.1:3000 \
  --subdomain myapp
```

> Point the client at the WebSocket endpoint on **port 80** (`/ws`). HTTP tunnels are automatically available on port 80 (via your HTTPS front). TCP tunnels allocate their ports from the configured `TCP_PORT_MIN`…`TCP_PORT_MAX` range.

Your app will be available at `https://myapp.tunnel.example.com` (via your HTTPS-terminating front).

## Monitoring

- Dashboard: `http://your-server:80/dashboard/`
- API: `http://your-server:80/api/stats`
- Health: `http://your-server:80/health`

## Project Structure

```
proxy_server.py       Main server (entry point)
protocol.py           Canonical wire protocol (frames, auth, constants)
storage.py            SQLite persistence (clients/tunnels bookkeeping)
dashboard.py          Read-only status dashboard (HTML + JSON API)
config.example.json   Config template (legacy)
requirements.txt      Optional deps (psutil)
examples/reference_client.py  Illustrative client implementation
haproxy.cfg           HAProxy config: HTTP front door on :80
nginx.conf            Nginx config: HTTP proxy (:8088)
supervisord.conf      Runs proxy_server.py + nginx + haproxy in one container
entrypoint.sh         Root entrypoint: chowns mounted volumes, starts supervisord
Dockerfile            Single multi-stage build for everything
DEPLOYMENT.md         Detailed deployment guide
```

## Architecture

### Protocol at a Glance

**Transport**: one RFC 6455 WebSocket per client (`protocol.py`, `ws.py`).
- **text messages** = JSON control (`hello`, tunnel open/close, stream open/close, window updates)
- **binary messages** = stream data: `[stream_id u32be][payload...]`

**Authentication** (HELLO payload, 72 bytes, HMAC-SHA256):
```
[ClientID:16] [Timestamp:8] [Nonce:16] [HMAC-SHA256:32]
```
Resists replay and proves knowledge of shared secret without sending it.

**Multiplexing** (Stream ID):
- A single WebSocket connection carries many logical streams; each stream = 1 HTTP request-connection or 1 TCP connection
- Control traffic (auth, tunnel lifecycle) rides in JSON text messages

**Flow control**:
- Per-stream, credit-based: both sides start with a 256 KiB send window
- Sender consumes credit before sending stream data
- Receiver sends back `window_update` after flushing (batched every 128 KiB)
- Simple backpressure: slow consumer naturally throttles sender

### Key Design Principles

1. **WebSocket + JSON control** — Framing/ordering/keep-alive handled by RFC 6455; JSON control messages on top; binary messages with a 4-byte stream id for stream data
2. **No external services** — SQLite + local files only. Scales from laptop to modest production
3. **Per-stream flow control** — Backpressure-aware, prevents one slow tunnel from starving others
4. **Replay-protected auth** — HMAC-SHA256 + timestamp checks + nonce tracking; no secret sent over wire
5. **Stable reconnect behavior** — Clients persist their ID, routes aren't "reserved" ahead of time (first-come first-served), allows graceful recovery without complex state sync
6. **SSL termination externalized** — Handled by Render/Cloudflare/etc., keeps proxy server simple and focused
7. **Single public port** — Port 80 carries HTTP tunnels, the dashboard, and the WebSocket control plane. Works with cloud platforms that terminate TLS at the edge.
8. **Observability, not governance** — SQLite bookkeeping, dashboard, and logs are for transparency; routing is purely in-memory and rebuilt on reconnect
9. **Minimal dependencies** — Asyncio (stdlib), sqlite3 (stdlib), psutil (optional). Main server has zero required external packages
10. **Environment-based config** — No config files, all via environment variables for container-friendly deployment
11. **Auto directory creation** — DB and log directories created automatically

## Production Checklist

- [ ] Set `SHARED_SECRET` to a long random value (`openssl rand -hex 32`)
- [ ] Set `WILDCARD_DOMAIN` to your actual domain
- [ ] Ensure DNS has `*.yourdomain` and `yourdomain` pointing to the server
- [ ] Expose port 80 (HTTP tunnels + WebSocket control plane); verify both work
- [ ] Configure custom domain / HTTPS termination in front (Render, Cloudflare, etc.)
- [ ] Bind dashboard to `127.0.0.1` or put it behind reverse-proxy auth
- [ ] Set `tcp.port_range` to your preferred allocation pool
- [ ] Set resource limits appropriate for your infrastructure
- [ ] Monitor `tunnel_proxy.log` and the `/api/stats` dashboard

## Resource Optimization

The server is optimized for low-resource environments:

- **Memory**: ~50-100MB base, +~10MB per 1000 active connections
- **CPU**: Single-threaded asyncio, minimal overhead
- **Connection limits**: Configurable via `INITIAL_WINDOW` (256KB per stream)

### Recommended limits for Render (512MB, 0.5 vCPU):

```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
    reservations:
      cpus: '0.1'
      memory: 256M
```

---

**Total project: ~1,600 lines of code + ~1,000 lines of docs. Ready for self-hosting.**