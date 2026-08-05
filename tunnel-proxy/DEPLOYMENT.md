# Deployment Guide for Tunnel Proxy

This document describes how to deploy the tunnel proxy server using Docker.

## Architecture Overview

A single container runs three processes under supervisord. **Only port 80 is exposed publicly.**

```
:80  (haproxy) ──────────────────────────── only externally exposed port
  │  sniffs first 2 bytes: "TN" (0x544e)?
  ├─ YES → backend control  → nginx stream :9000 → proxy_server :9001 (control channel)
  └─ NO  → backend http     → nginx http   :8088
                                ├─ /dashboard/, /api/ → dashboard :8081
                                └─ everything else     → proxy_server :8080 (tunnel HTTP)
```

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

# Run - only port 80 is exposed
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
6. Set the **Port** to `80` (HAProxy front door)
7. Deploy

**Note:** Render handles HTTPS termination automatically. The container exposes HTTP on port 80 only; the proxy server itself runs HTTP only.

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

**HTTPS termination is handled externally** (Render, Cloudflare, or your own reverse proxy). The container runs HTTP only. No SSL certificates, Let's Encrypt, or certbot needed.

## Monitoring

- Dashboard: `http://your-server:80/dashboard/`
- API: `http://your-server:80/api/stats`
- Health: `http://your-server:80/health`

## Client Usage

```bash
# Using the reference client
python3 examples/reference_client.py \
  --server your-server:80 \
  --secret your-shared-secret \
  --local-http 127.0.0.1:3000 \
  --subdomain myapp
```

> Point the client at the **public port (80)**. HAProxy sniffs the control protocol (`"TN"` magic) and routes it to the control channel automatically — the client does not need a separate control port.

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
# Test control channel through the public port (client connects to :80)
python3 examples/reference_client.py --server your-server:80 --secret ... --local-http 127.0.0.1:3000

# Test HTTP routing
curl -H "Host: test.tunnel.example.com" http://your-server:80
```

### Protocol sniffing not working?
- Confirm the client is connecting to **port 80** (HAProxy), not 9000
- Confirm HAProxy sees the connection: `docker exec tunnel-proxy cat /var/log/supervisor/haproxy.err.log`
- The magic is the first 2 bytes `"TN"` (0x544e) — verify with `nc -v your-server 80` and check the log

### Database issues
```bash
# Check database
docker exec tunnel-proxy sqlite3 /data/tunnel_proxy.db ".tables"
```