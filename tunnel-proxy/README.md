# Self-Hosted Tunneling Proxy

A minimal, self-hosted alternative to ngrok. One `proxy_server.py`, no external services (SQLite + local files only), automatic wildcard DNS routing, HTTP host-based routing, and randomly allocated TCP ports for raw TCP tunnels.

```
                                          ┌────────────────────────────────────┐
    HTTP  app.tunnel.example.com          │         Single container           │
    ───────────────────────────────────▶  │  :80  haproxy (HTTP only)          │
                                          │         │                          │
    Control channel (client)              │  :9000 nginx stream (raw TCP)      │
    ───────────────────────────────────▶  │         │                          │
                                          │   nginx :8088 (HTTP)               │  persistent
                                          │         │                          │◀───multiplexed───▶  client
                                          │   proxy_server.py                 │      connection     (your
                                          │  - control channel (auth)         │                       laptop /
                                          │  - HTTP router                    │                       server)
                                          │  - TCP listeners                  │
                                          │  - SQLite bookkeeping             │
                                          └────────────────────────────────────┘
```

## Key Features

- **Authentication**: HMAC-SHA256 challenge-response (no shared secret sent over wire)
- **HTTP routing**: Host header–based. `app.tunnel.example.com` → tunnels traffic to the registered client
- **TCP routing**: Random port allocation (or preferred port, if free). Concurrent TCP listeners, one per tunnel
- **Multiplexing**: One persistent connection carries many logical streams. Each stream = one HTTP request-connection or one TCP connection
- **Flow control**: Per-stream, credit-based (HTTP/2 style). Backpressure-aware. Prevents one slow tunnel from stalling others
- **Two public ports**: Port 80 for HTTP tunnels/dashboard, port 9000 for raw TCP control channel. This avoids the issue of cloud platforms terminating TLS at the edge and forwarding only HTTP.
- **SSL termination**: Handled externally (Render, Cloudflare, or your own nginx). Proxy server runs HTTP only.
- **Private dashboard**: Server-validated password login, signed expiring HttpOnly session cookie, authenticated stats API, no wildcard CORS; dashboard listener defaults to loopback
- **SQLite**: Lightweight persistence for bookkeeping & observability
- **No external services**: Just the proxy binary + SQLite + local files
- **Docker ready**: Single container (supervisord runs tunnel-proxy + nginx + haproxy), multi-stage build, resource limits optimized for 512MB RAM / 0.5 vCPU
- **Environment-based config**: No config files needed, all via environment variables
- **Auto directory creation**: DB and log directories created automatically

## Quick Start

### 1. Docker (recommended)

```bash
cp .env.example .env      # SHARED_SECRET, WILDCARD_DOMAIN, DASHBOARD_PASSWORD, JWT_SECRET (+ certbot creds)
vim .env

# Interactive: inspects the machine first (container, image, database,
# certbot certificates, DNS, busy ports), then asks what to do.
./startup.sh

# Non-interactive equivalents:
./startup.sh --action restart                                    # restart as-is (fastest)
./startup.sh --action redeploy --mode 3 --range 20000-20100 -y   # http + tcp + udp
./startup.sh --action rebuild  --mode 3 --range 20000-20100 -y   # rebuild, then swap
```

Manual equivalent of the default layout (HTTP + TCP + UDP tunnels):

```bash
docker build -t tunnel-proxy .

docker run -d --name tunnel-proxy --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 9000:9000 \
  -p 20000-20100:20000-20100 \
  -p 20000-20100:20000-20100/udp \
  -e TCP_PORT_MIN=20000 -e TCP_PORT_MAX=20100 \
  -e UDP_PORT_MIN=20000 -e UDP_PORT_MAX=20100 \
  --env-file .env \
  -v /data:/data \
  -v /var/log:/var/log \
  tunnel-proxy

# Check health
curl http://localhost/health
```

HTTP-only (two public ports plus the control channel — no raw TCP/UDP tunnels):

```bash
docker run -d --name tunnel-proxy --restart unless-stopped \
  -p 80:80 -p 443:443 -p 9000:9000 \
  --env-file .env \
  -v /data:/data -v /var/log:/var/log \
  tunnel-proxy
```

`/data` holds the SQLite database **and** `/data/letsencrypt`, so replacing or
restarting the container keeps client history and reuses existing certificates.

### Ports and tunnel types

| Port(s) | Needed for | Notes |
|---------|------------|-------|
| `80` | `/health`, HTTP tunnels, apex→HTTPS redirect | Always publish |
| `443` | HTTPS tunnels + dashboard | Unless `HTTP_ONLY=true` / external TLS |
| `9000` | Control channel (`CONTROL_PORT`) | Every client connects here |
| `TCP_PORT_MIN..TCP_PORT_MAX` | raw `tcp` tunnels | Publish **1:1** (`-p 20000-20100:20000-20100`) |
| `UDP_PORT_MIN..UDP_PORT_MAX` | raw `udp` tunnels | Same range with `/udp` |

- **HTTP tunnels never need extra ports**: every `http` tunnel is routed by the
  `Host` header / subdomain through the shared 80/443 listener, so 80/443+9000
  is enough for any number of HTTP tunnels. Raw `tcp`/`udp` tunnels are the only
  ones that consume a dedicated public port.
- `EXPOSE` in the Dockerfile is documentation only; nothing is reachable from
  outside the container unless it is published with `-p` (or `--network host`).
  Publishing must also be 1:1: the server advertises the container-side port
  number, so `-p 30000:20000` would advertise a port nobody can reach.
- The server only verifies that an allocated port is *bindable inside the
  container*. An unpublished port therefore shows up as a `ready` tunnel that is
  unreachable from the internet — keep the published range and the
  `TCP_PORT_MIN/MAX` (and `UDP_*`) values identical.
- Keep the range small (~100 ports). Each published port costs an iptables DNAT
  rule (and, with Docker's default userland proxy, a proxy listener); a range
  like `10000-65535` is impractical and often rejected by cloud firewalls.
- With bridge networking Docker routes published ports through its own
  DNAT/FORWARD rules, so a restrictive host `INPUT` chain does **not** block
  them. With `--network host` (or the direct Python run) the server binds the
  host directly and the host firewall must allow 80, 443, 9000 and the range.
- On Oracle Cloud (and any cloud) the VCN security list / NSG must also allow
  those ports — that is outside the host.

### 2. Direct Python Run (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Run with environment variables
SHARED_SECRET="your-secret" \
WILDCARD_DOMAIN="tunnel.example.com" \
DASHBOARD_PASSWORD="choose-a-long-unique-password" \
HTTP_PORT=8080 \
python3 proxy_server.py
```

> The dev run binds control on `:9000`, HTTP on `:8080`, and dashboard on `:8081` directly (no HAProxy/nginx in front).

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHARED_SECRET` | **Yes** | - | Authentication secret (generate with `openssl rand -hex 32`) |
| `WILDCARD_DOMAIN` | **Yes** | - | Wildcard domain for tunnels (e.g., `tunnel.example.com`) |
| `DASHBOARD_PASSWORD` | **Yes for dashboard** | - | Password required to unlock dashboard |
| `JWT_SECRET` | **Yes for dashboard** | - | High-entropy HS256 JWT signing secret |
| `CONTROL_HOST` | No | `0.0.0.0` | Control channel bind host |
| `CONTROL_PORT` | No | `9000` | Control channel port (clients connect here) |
| `HTTP_HOST` | No | `0.0.0.0` | HTTP server bind host |
| `HTTP_PORT` | No | `80` | HTTP server port |
| `HTTPS_HOST` | No | `0.0.0.0` | HTTPS server bind host |
| `HTTPS_PORT` | No | `443` | HTTPS server port |
| `TCP_PORT_MIN` | No | `10000` | TCP tunnel port range minimum (publish it!) |
| `TCP_PORT_MAX` | No | `65535` | TCP tunnel port range maximum (publish it!) |
| `UDP_PORT_MIN` | No | `10000` | UDP tunnel port range minimum (publish it!) |
| `UDP_PORT_MAX` | No | `65535` | UDP tunnel port range maximum (publish it!) |
| `DASHBOARD_HOST` | No | `127.0.0.1` | Standalone dashboard bind host (loopback only by default) |
| `DASHBOARD_PORT` | No | `8081` | Dashboard port |
| `HTTP_ONLY` | No | `true` | Use http:// URLs |
| `HEARTBEAT_INTERVAL` | No | `20` | Heartbeat interval (seconds) |
| `HEARTBEAT_TIMEOUT` | No | `60` | Heartbeat timeout (seconds) |
| `STALE_GRACE_SECONDS` | No | `300` | Stale client cleanup grace |
| `DB_PATH` | No | `/data/tunnel_proxy.db` | SQLite database path |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `LOG_FILE` | No | `/var/log/tunnel-proxy/tunnel_proxy.log` | Log file path |

**`SHARED_SECRET` and `WILDCARD_DOMAIN` are required for the tunnel service. Set both `DASHBOARD_PASSWORD` and `JWT_SECRET`; the panel fails closed if either is unset. Generate `JWT_SECRET` with `openssl rand -hex 32`. Dashboard JWT sessions persist for 31 days. API clients may authenticate with `Authorization: Bearer <JWT>`. Use HTTPS whenever the dashboard is reachable beyond localhost.**

**Directories are auto-created**: The server automatically creates `/data` and `/var/log/tunnel-proxy` directories if they don't exist.

## Container Architecture

One container, one process: `entrypoint.sh` fixes volume ownership, provisions
or reuses the wildcard certificate with certbot (DNS challenge), then `exec`s
`proxy_server.py`, which binds every port itself.

```
:80        proxy_server.py  ── /health, apex→HTTPS redirect, HTTP tunnels
:443       proxy_server.py  ── HTTPS tunnels + dashboard (apex domain)
:9000      proxy_server.py  ── control channel (raw TCP, no TLS)
RANGE/tcp  proxy_server.py  ── one listener per raw TCP tunnel
RANGE/udp  proxy_server.py  ── one UDP socket per raw UDP tunnel
```

- **`entrypoint.sh`** — runs as root: `chown`s `/data` and `/var/log/...`,
  symlinks `/etc/letsencrypt` to `/data/letsencrypt`, renews the certificate if
  it is missing or expires within 30 days, starts cron for renewals, then drops
  into the server.
- **`proxy_server.py`** — the tunnel server: HTTP(S) routing by `Host`,
  per-tunnel TCP/UDP listeners, control channel, dashboard.
- **`startup.sh`** — deployment helper (detects existing state, builds,
  swaps/restarts the container, waits for health, rolls back on failure).

**Why separate ports?** HTTP(S) tunnels multiplex over 80/443 by `Host` header,
but the control channel is a raw TCP protocol (`TN` magic bytes) that cannot
ride over HTTP, so it needs its own port. Raw `tcp`/`udp` tunnels each need a
public port of their own, which is why the range above exists.

**Persistent data:** everything mutable lives under `/data` (`tunnel_proxy.db`,
`letsencrypt/`), so mounting `/data` is enough to keep state across rebuilds.

## Render Deployment

### Manual Render Setup

1. Create a new Web Service
2. Use Docker runtime with `Dockerfile`
3. Set plan to **Starter** (512MB RAM, 0.5 CPU)
4. Add **required** environment variables:
   - `SHARED_SECRET`
   - `WILDCARD_DOMAIN`
  - `DASHBOARD_PASSWORD` (long, unique secret)
  - `JWT_SECRET` (random signing key, e.g. `openssl rand -hex 32`)
5. Add persistent disk at `/data` (1GB)
6. Set **Ports** to `80` (HTTP) and `9000` (TCP control channel)
7. Deploy

**Note:** Render handles HTTPS termination automatically on port 443 and forwards HTTP to container port 80. The control channel uses a separate TCP port (9000) which Render exposes as a TCP load balancer target. Point `*.yourdomain` and `yourdomain` at the service.

Render cannot expose an arbitrary port range, so on Render only `http` tunnels
work — `tcp`/`udp` tunnels need a host/VPS where you can publish
`TCP_PORT_MIN..TCP_PORT_MAX` (see [Ports and tunnel types](#ports-and-tunnel-types)).

## SSL/TLS

The container terminates HTTPS itself: `entrypoint.sh` requests a wildcard
certificate (`*.<WILDCARD_DOMAIN>` + the apex) via certbot's DNS challenge on
first start, stores it in `/data/letsencrypt`, reuses it on later starts when it
is valid for more than 30 days, and renews it daily via cron.

- Needs `DNS_PROVIDER` + credentials (`CF_API_TOKEN` for Cloudflare) and
  `CERTBOT_EMAIL`; otherwise set `HTTP_ONLY=true` and put TLS in front yourself.
- Set `EXTERNAL_SSL=true` to skip certbot entirely when a proxy/reverse proxy
  terminates TLS for you.
- `startup.sh` reports the certificate it finds (path + expiry) before deploying,
  so a restart or redeploy never re-requests a valid certificate.
- Clients always reach the control channel as **raw TCP on 9000**, not TLS.

## Client Usage

```bash
# Using the reference client
python3 examples/reference_client.py \
  --server your-server:9000 \
  --secret your-shared-secret \
  --local-http 127.0.0.1:3000 \
  --subdomain myapp
```

> Point the client at **port 9000** for the control channel. HTTP tunnels are automatically available on port 80 (via your HTTPS front).

Your app will be available at `https://myapp.tunnel.example.com` (via your HTTPS-terminating front).

### Tunnel ownership modes

Public names (subdomain / TCP port / UDP port) are shared, so the server needs
a rule for a second client that asks for a name already in use. Each tunnel
declares its mode in `TUNNEL_OPEN_REQUEST` (clients expose this as `--lease`):

| mode | behaviour |
|------|-----------|
| `handoff` (default) | Newest claimant wins. The previous owner is revoked (`TUNNEL_CLOSE` with `reason="handoff"` and a message), its streams are aborted, and the newcomer gets the name. |
| `lease` | The name is reserved. Other clients are refused (`status="error"`, `reason="leased"`) and the holder keeps serving. A client asking for a lease over a name that is already in use is refused too (`reason="in_use"`). |

Reconnects are never treated as a conflict: the same client process (same
`client_id` and `instance_id`) reclaims its own registration, including a
leased one. Two processes on one machine share the persisted `client_id` but
send different `instance_id`s, so they count as two competing clients — which
is what makes `--lease` meaningful when the same machine runs two clients for
the same name.

A lease lives as long as the owning session: once the client is unreachable
past `heartbeat_timeout_seconds` the server drops the session and the name
returns to the pool. Leases are therefore exclusive but never permanent, which
keeps the "routes are rebuilt on reconnect, nothing is reserved forever"
design intact.

## Monitoring

- Dashboard: `https://your-domain/dashboard/` (requires `DASHBOARD_PASSWORD` and `JWT_SECRET`)
- Stats API: `/api/stats` (requires a valid dashboard session; no wildcard CORS)
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
nginx.conf            Nginx config: HTTP proxy (:8088) + stream control (:9000)
supervisord.conf      Runs proxy_server.py + nginx + haproxy in one container
entrypoint.sh         Root entrypoint: chowns mounted volumes, starts supervisord
Dockerfile            Single multi-stage build for everything
DEPLOYMENT.md         Detailed deployment guide
```

## Architecture

### Protocol at a Glance

**Frame format** (12-byte header + variable payload):
```
[Magic:2] [Ver:1] [Type:1] [StreamID:4] [Length:4] [Payload:...]
  "TN"     1      enum      0 = control  bytes
```

**Authentication** (binary HELLO payload, 72 bytes):
```
[ClientID:16] [Timestamp:8] [Nonce:16] [HMAC-SHA256:32]
```
Resists replay and proves knowledge of shared secret without sending it.

**Multiplexing** (Stream ID):
- Stream 0: control (HELLO, PING, tunnel open/close, errors)
- Stream 1+: individual tunneled connections (each stream = 1 HTTP request or 1 TCP conn)

**Flow control**:
- Per-stream, credit-based: both sides start with 256 KiB send window
- Sender consumes credit before sending `STREAM_DATA`
- Receiver sends back `STREAM_WINDOW_UPDATE` after flushing (batched every 128 KiB)
- Simple backpressure: slow consumer naturally throttles sender

### Key Design Principles

1. **Simple binary protocol** — No JSON for hot-path data, just 12-byte headers + carefully chosen payloads
2. **No external services** — SQLite + local files only. Scales from laptop to modest production
3. **Per-stream flow control** — Backpressure-aware, prevents one slow tunnel from starving others
4. **Replay-protected auth** — HMAC-SHA256 + timestamp checks + nonce tracking; no secret sent over wire
5. **Stable reconnect behavior** — Clients persist their ID, routes aren't "reserved" ahead of time (first-come first-served), allows graceful recovery without complex state sync. Contested names are resolved by the tunnel's **ownership mode**: `handoff` (default — newest claimant wins, previous owner is revoked with an explanatory message) or `lease` (name reserved; other claimants are refused until the holder's session ends)
6. **SSL termination externalized** — Handled by Render/Cloudflare/etc., keeps proxy server simple and focused
7. **Two public ports** — Port 80 for HTTP, port 9000 for raw TCP control. Works with cloud platforms that terminate TLS at the edge.
8. **Observability, not governance** — SQLite bookkeeping, dashboard, and logs are for transparency; routing is purely in-memory and rebuilt on reconnect
9. **Minimal dependencies** — Asyncio (stdlib), sqlite3 (stdlib), psutil (optional). Main server has zero required external packages
10. **Environment-based config** — No config files, all via environment variables for container-friendly deployment
11. **Auto directory creation** — DB and log directories created automatically

## Production Checklist

- [ ] Set `SHARED_SECRET` to a long random value (`openssl rand -hex 32`)
- [ ] Set `WILDCARD_DOMAIN` to your actual domain
- [ ] Ensure DNS has `*.yourdomain` and `yourdomain` pointing to the server
- [ ] Expose ports 80 (HTTP) and 9000 (control); verify both work
- [ ] Configure custom domain / HTTPS termination in front (Render, Cloudflare, etc.)
- [x] Dashboard binds to `127.0.0.1` by default and enforces server-side password sessions
- [ ] Set `tcp.port_range` to your preferred allocation pool
- [ ] Set resource limits appropriate for your infrastructure
- [ ] Monitor `tunnel_proxy.log` and the authenticated `/api/stats` dashboard

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