# Deployment Guide for Tunnel Proxy

This document describes how to deploy the tunnel proxy server using Docker.

## Architecture Overview

A single container runs three processes under supervisord. **One public port is exposed:**

- **Port 80** — everything: HTTP tunnels, dashboard, and the `/ws` WebSocket control-plane endpoint, via HAProxy → nginx → proxy_server.

```
Internet  ─────────────────────▶  :80  (haproxy) ──────────────▶  nginx :8088
                                                                    ├─ /dashboard/, /api/ → dashboard :8081
                                                                    └─ everything else     → proxy_server :8080
                                                                        ├─ HTTP tunnels (Host-header routed)
                                                                        └─ /ws WebSocket control plane (client)
```

**Why one port?** The client control plane is a WebSocket that rides on the same HTTP listener as the tunnels (see `protocol.py`), so a single port 80 carries everything. Cloud platforms terminate HTTPS at the edge and forward **HTTP** to the container's port 80.

## Quick Start

### 1. Create `.env` file

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your values
```

**Required variables:**
- `SHARED_SECRET` - Generate with: `openssl rand -hex 32`
- `WILDCARD_DOMAIN` - Your wildcard domain (e.g., `tunnel.example.com`)

All other settings have sensible defaults and don't need to be set.

### 2. Build and run

```bash
# Build the single container
docker build -t tunnel-proxy .

# Run - port 80 (HTTP tunnels + dashboard + WebSocket control) exposed
docker run -d \
  --name tunnel-proxy \
  -p 80:80 \
  --env-file .env \
  -v tunnel-proxy-data:/data \
  -v tunnel-proxy-logs:/var/log/tunnel-proxy \
  tunnel-proxy
```

### 3. Verify deployment

```bash
# Check logs
docker logs -f tunnel-proxy

# Test health endpoint (via haproxy -> nginx)
curl http://localhost/health

# Test dashboard (via haproxy -> nginx -> dashboard)
curl http://localhost/dashboard/
curl http://localhost/api/stats
```

## Environment Variables

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

## Render Deployment

### Manual Render setup

1. Create a new Web Service
2. Use Docker runtime with `Dockerfile`
3. Set plan to **Starter** (512MB RAM, 0.5 CPU)
4. Add **required** environment variables:
   - `SHARED_SECRET`
   - `WILDCARD_DOMAIN`
5. Add persistent disk at `/data` (1GB)
6. Set **Ports** to `80` (HTTP)
7. Deploy

**Note:** Render handles HTTPS termination automatically on port 443 and forwards HTTP to container port 80. The WebSocket control plane and all tunnels ride on that same port. Point `*.yourdomain` and `yourdomain` at the service.

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

## SSL/TLS

**HTTPS termination is handled externally** (Render, Cloudflare, or your own reverse proxy). The container exposes HTTP on port 80 only. No SSL certificates, Let's Encrypt, or certbot needed.

## Monitoring

- Dashboard: `http://your-server:80/dashboard/`
- API: `http://your-server:80/api/stats`
- Health: `http://your-server:80/health`

## Client Usage

```bash
# Using the reference client
python3 examples/reference_client.py \
  --server your-server:80/ws \
  --secret your-shared-secret \
  --local-http 127.0.0.1:3000 \
  --subdomain myapp
```

> Point the client at the WebSocket endpoint on **port 80** (`/ws`). HTTP tunnels are automatically available on port 80 (via your HTTPS front). TCP tunnels allocate their own public ports from the configured `TCP_PORT_MIN`…`TCP_PORT_MAX` range.

Your app will be available at `https://myapp.tunnel.example.com` (via your HTTPS-terminating front).

## Troubleshooting

### Check logs
```bash
docker logs -f tunnel-proxy
# Inside the container:
docker exec tunnel-proxy cat /var/log/nginx/error.log
docker exec tunnel-proxy cat /var/log/supervisor/haproxy.err.log
docker exec tunnel-proxy cat /var/log/tunnel-proxy/tunnel_proxy.log
```

### Verify process status inside the container
```bash
docker exec tunnel-proxy ps aux | grep -E "haproxy|nginx|python"
```

### Verify connectivity
```bash
# Test control channel (client connects to :80/ws)
python3 examples/reference_client.py --server your-server:80/ws --secret ... --local-http 127.0.0.1:3000

# Test HTTP routing
curl -H "Host: test.tunnel.example.com" http://your-server:80
```

### Control channel not working?
- Confirm the client is connecting to **port 80 `/ws`** (WebSocket), not a raw TCP port
- Confirm haproxy + nginx are running: `docker exec tunnel-proxy ss -tlnp | grep -E '80|8088'`

### Database issues
```bash
# Check database
docker exec tunnel-proxy sqlite3 /data/tunnel_proxy.db ".tables"
```