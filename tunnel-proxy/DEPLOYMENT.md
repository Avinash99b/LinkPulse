# Deployment Guide for Tunnel Proxy

This document describes how to deploy the tunnel proxy server using Docker.

## Quick Start with Docker Compose

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

### 2. Start services

```bash
# Start tunnel-proxy and nginx
docker-compose up -d
```

### 3. Verify deployment

```bash
# Check logs
docker-compose logs -f tunnel-proxy

# Test health endpoint
curl http://localhost/health

# Test dashboard
curl http://localhost:8081/api/stats
```

## Manual Docker Run

### Build images

```bash
# Build tunnel-proxy
docker build -t tunnel-proxy .

# Build nginx
docker build -t tunnel-proxy-nginx -f Dockerfile.nginx .
```

### Run tunnel-proxy

```bash
docker run -d \
  --name tunnel-proxy \
  -e SHARED_SECRET="your-secret" \
  -e WILDCARD_DOMAIN="tunnel.example.com" \
  -p 9000:9000 \
  -p 8080:8080 \
  -p 8081:8081 \
  -v tunnel-proxy-data:/data \
  -v tunnel-proxy-logs:/var/log/tunnel-proxy \
  tunnel-proxy
```

### Run nginx (HTTP only)

```bash
docker run -d \
  --name tunnel-proxy-nginx \
  -e WILDCARD_DOMAIN="tunnel.example.com" \
  -e NGINX_UPSTREAM_HOST="tunnel-proxy" \
  -e NGINX_UPSTREAM_PORT="8080" \
  -p 80:80 \
  tunnel-proxy-nginx
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SHARED_SECRET` | **Yes** | - | Authentication secret (generate with `openssl rand -hex 32`) |
| `WILDCARD_DOMAIN` | **Yes** | - | Wildcard domain for tunnels (e.g., `tunnel.example.com`) |
| `CONTROL_HOST` | No | `0.0.0.0` | Control channel bind host |
| `CONTROL_PORT` | No | `9000` | Control channel port |
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

## Render Deployment

### Manual Render setup

1. Create a new Web Service
2. Use Docker runtime with `Dockerfile`
3. Set plan to **Starter** (512MB RAM, 0.5 CPU)
4. Add **required** environment variables:
   - `SHARED_SECRET`
   - `WILDCARD_DOMAIN`
5. Add persistent disk at `/data` (1GB)
6. Deploy

**Note:** Render handles HTTPS termination automatically. The tunnel proxy runs HTTP only on port 8080.

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

**Render handles HTTPS termination automatically.** The tunnel proxy runs HTTP only. No SSL certificates, Let's Encrypt, or certbot needed.

## Monitoring

- Dashboard: `http://localhost:8081` (or via your Render URL)
- API: `http://localhost:8081/api/stats`
- Health: `http://localhost/health`

## Client Usage

```bash
# Using the reference client
python3 examples/reference_client.py \
  --server your-server:9000 \
  --secret your-shared-secret \
  --local-http 127.0.0.1:3000 \
  --subdomain myapp
```

Your app will be available at `https://myapp.tunnel.example.com` (via Render's HTTPS)

## Troubleshooting

### Check logs
```bash
docker-compose logs -f tunnel-proxy
docker-compose logs -f nginx
```

### Verify connectivity
```bash
# Test control channel
nc -zv your-server 9000

# Test HTTP
curl -H "Host: test.tunnel.example.com" http://your-server
```

### Database issues
```bash
# Check database
sqlite3 /data/tunnel_proxy.db ".tables"
```