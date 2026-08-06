# Deployment Guide for Tunnel Proxy

This document describes how to deploy the tunnel proxy server using Docker.

## Architecture Overview

A single container runs three processes under supervisord. **Two public ports are exposed:**

- **Port 80** — HTTP (tunnels + dashboard) via HAProxy → nginx http
- **Port 9000** — Control channel (raw TCP) via nginx stream → proxy_server

```
:80  (haproxy) ──────────────────────────── HTTP tunnels + dashboard
  │  HTTP only (no protocol sniffing)
  └─ → nginx http :8088
        ├─ /dashboard/, /api/ → dashboard :8081
        └─ everything else     → proxy_server :8080 (tunnel HTTP)

:9000 (nginx stream) ───────────────────── Control channel (client connection)
  │  raw TCP, no TLS
  └─ → proxy_server :9001 (control channel)
```

**Why two ports?** Render (and most cloud platforms) terminate HTTPS at the edge and forward **HTTP** to the container. The control channel is a raw TCP protocol (`TN` magic bytes) that can't ride over HTTP/HTTPS. Separate port 9000 keeps the control channel as raw TCP while port 80 handles HTTP traffic.

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

# Run - ports 80 (HTTP) and 9000 (control) exposed
docker run -d \
  --name tunnel-proxy \
  -p 80:80 \
  -p 9000:9000 \
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
| `CONTROL_HOST` | No | `0.0.0.0` | Control channel bind host |
| `CONTROL_PORT` | No | `9001` | Control channel port (internal; nginx stream fronts it at `:9000`) |
| `HTTP_HOST` | No | `0.0.0.0` | HTTP server bind host |
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

> In the container, `CONTROL_PORT` is set to `9001` so that nginx's stream module (listening on `:9000`) can front the control channel. Do not change it back to `9000` in `.env` — that would collide with nginx's listener.

## Render Deployment

### Manual Render setup

1. Create a new Web Service
2. Use Docker runtime with `Dockerfile`
3. Set plan to **Starter** (512MB RAM, 0.5 CPU)
4. Add **required** environment variables:
   - `SHARED_SECRET`
   - `WILDCARD_DOMAIN`
5. Add persistent disk at `/data` (1GB)
6. Set **Ports** to `80` (HTTP) and `9000` (TCP control channel)
7. Deploy

**Note:** Render handles HTTPS termination automatically on port 443 and forwards HTTP to container port 80. The control channel uses a separate TCP port (9000) which Render exposes as a TCP load balancer target. Point `*.yourdomain` and `yourdomain` at the service.

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

**HTTPS termination is handled externally** (Render, Cloudflare, or your own reverse proxy). The container runs HTTP only on port 80. The control channel uses raw TCP on port 9000 (no TLS). No SSL certificates, Let's Encrypt, or certbot needed.

## Monitoring

- Dashboard: `http://your-server:80/dashboard/`
- API: `http://your-server:80/api/stats`
- Health: `http://your-server:80/health`

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
# Test control channel (client connects to :9000)
python3 examples/reference_client.py --server your-server:9000 --secret ... --local-http 127.0.0.1:3000

# Test HTTP routing
curl -H "Host: test.tunnel.example.com" http://your-server:80
```

### Control channel not working?
- Confirm the client is connecting to **port 9000** (nginx stream), not 80
- Confirm nginx stream is running: `docker exec tunnel-proxy ss -tlnp | grep 9000`
- The magic is the first 2 bytes `"TN"` (0x544e)

### Database issues
```bash
# Check database
docker exec tunnel-proxy sqlite3 /data/tunnel_proxy.db ".tables"
```