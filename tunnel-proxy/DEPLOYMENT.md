# Deployment Guide — LinkPulse Server

Deploy `tunnel-proxy` as a single container or a direct Python process. There
is no nginx/HAProxy/supervisord layer: `proxy_server.py` binds every public
port and terminates HTTPS itself.

## What gets exposed

| Port | Purpose |
|------|---------|
| 80 | `/health`, apex→HTTPS redirect, HTTP tunnels |
| 443 | HTTPS tunnels + dashboard |
| 9000 | Control channel for clients (raw TCP unless `CONTROL_TLS=true`) |
| 20000–20100/tcp | Raw TCP tunnels (default pool; one port per tunnel) |
| 20000–20100/udp | Raw UDP tunnels (default pool) |

HTTP tunnels share 80/443 via the `Host` header; only TCP/UDP tunnels consume a
dedicated port. Change the range with `TCP_PORT_MIN/MAX` and
`UDP_PORT_MIN/MAX` — and publish exactly that range.

## 1. Prepare configuration

```bash
cp .env.example .env
```

Required:

| Variable | Notes |
|----------|-------|
| `SHARED_SECRET` | `openssl rand -hex 32` |
| `WILDCARD_DOMAIN` | Apex domain; apex and `*.<domain>` must resolve here |
| `DASHBOARD_PASSWORD` | Long, unique password (minimum 8 characters) |
| `JWT_SECRET` | `openssl rand -hex 32` (minimum 32 characters) |

Certbot (DNS challenge) additionally needs `DNS_PROVIDER`, that provider's
credentials (Cloudflare: `CF_API_TOKEN`) and `CERTBOT_EMAIL`.

The server validates required values before opening listeners and fails on
missing/placeholder secrets. Without a usable certificate it also fails unless
you explicitly choose `HTTP_ONLY=true`, `EXTERNAL_SSL=true`, or
`ALLOW_HTTP_FALLBACK=true`.

## 2. Build

```bash
docker build -t tunnel-proxy .
```

The image pins the Python base and installs certbot and its DNS plugin into the
same interpreter/environment that renewal uses, so provisioning and cron renew
cannot disagree about plugin availability. Runtime dependencies are Python
stdlib plus optional `psutil`.

## 3. Run

### Host networking (recommended on a VPS)

```bash
docker run -d --name tunnel-proxy --restart unless-stopped \
  --network host \
  --cap-add NET_BIND_SERVICE \
  -e TCP_PORT_MIN=20000 -e TCP_PORT_MAX=20100 \
  -e UDP_PORT_MIN=20000 -e UDP_PORT_MAX=20100 \
  --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy \
  tunnel-proxy
```

The container binds 80/443/9000 and the whole tunnel range directly; `-p` is
unnecessary and ignored. Pass `--cap-add NET_BIND_SERVICE` so the unprivileged
server can bind ports 80/443 under any Docker configuration. Open those ports
on the host and in the cloud security list/NSG. Host networking avoids one
Docker NAT rule + userland proxy process per published port, which matters on
small (1 vCPU) instances.

### Bridge networking (small ranges only)

```bash
docker run -d --name tunnel-proxy --restart unless-stopped \
  -p 80:80 -p 443:443 -p 9000:9000 \
  -p 20000-20100:20000-20100 \
  -p 20000-20100:20000-20100/udp \
  -e TCP_PORT_MIN=20000 -e TCP_PORT_MAX=20100 \
  -e UDP_PORT_MIN=20000 -e UDP_PORT_MAX=20100 \
  --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy \
  tunnel-proxy
```

Publish 1:1 only. A port the server can bind inside the container but Docker
does not publish will appear “ready” and be unreachable from the internet.

### HTTP-only (no certificate / no 443)

```bash
docker run -d --name tunnel-proxy --restart unless-stopped \
  -p 80:80 -p 9000:9000 \
  -e HTTP_ONLY=true \
  --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy \
  tunnel-proxy
```

The dashboard then binds `DASHBOARD_HOST:DASHBOARD_PORT` (loopback by
default). Publish it through your own authenticated reverse proxy if needed.

### External TLS termination

Set `EXTERNAL_SSL=true` to skip certbot, and terminate TLS in a front proxy
that forwards to the server's HTTP listener. Keep the control channel on 9000
(or configure control TLS). Ensure the public URL scheme the server advertises
(`HTTP_ONLY` vs HTTPS) matches what clients will actually reach.

### Direct Python run (development)

```bash
SHARED_SECRET=... WILDCARD_DOMAIN=... \
DASHBOARD_PASSWORD=... JWT_SECRET=... \
HTTP_ONLY=true HTTP_PORT=8080 HTTPS_PORT=8443 DASHBOARD_PORT=8081 \
python3 proxy_server.py
```

## 4. Certificates and renewal

- `entrypoint.sh` runs as root only for initialization: create/chown `/data`
  and `/var/log/tunnel-proxy`, provision the wildcard certificate with certbot (DNS
  challenge), install a root-owned renewal cron entry, then `exec` the server
  as the unprivileged `tunnelproxy` user.
- Certificates live in `/data/letsencrypt` (`/etc/letsencrypt` is a symlink),
  so rebuilding the container reuses them.
- Renewal is a separate root-owned cron job running a wrapper that invokes the
  pinned `/opt/venv/bin/certbot` (the same interpreter that installed the
  plugins); it is not a background task of `proxy_server.py`. Renewed
  certificates are reloaded in place for both public HTTPS and control TLS;
  changing the configured certificate paths requires a restart.
- Private keys must not be world-readable. The container keeps certificate
  directories traversable and key files at root:`tunnelproxy` mode 0640 so the
  unprivileged server can read them without exposing them to all users.
- If provisioning fails, startup fails. Do not rely on a silent HTTP fallback;
  `ALLOW_HTTP_FALLBACK=true` is an explicit operator decision.

## 5. Verify

```bash
docker logs -f tunnel-proxy

# /health always returns 200, including when apex HTTPS redirect is enabled
curl -si http://localhost/health | head -1

# Unauthenticated dashboard stats must be rejected
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/api/stats   # 401

# Certificate (when HTTPS is enabled)
openssl s_client -connect localhost:443 -servername "$WILDCARD_DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

Then start a client:

```bash
python3 ../my_proxy_client/my_proxy.py http 3000 \
  --server "$WILDCARD_DOMAIN:9000" --token "$SHARED_SECRET" -u myapp
curl -I "https://myapp.$WILDCARD_DOMAIN/"
```

## 6. Rollback and redeploy

`startup.sh` can do the mechanical part:

```bash
./startup.sh --action redeploy --mode 4 --range 20000-20100 --yes
./startup.sh --action rebuild  --mode 4 --range 20000-20100 --yes
```

Behaviour:

- Builds the new image **before** touching the running container.
- Keeps the previous container (stopped/renamed as a backup) until the new one
  passes its health check.
- On failure, removes the failed container and restores the previous container
  with its **exact original configuration** (ports, environment, mounts,
  network mode), not merely the previous image with defaults.
- `--yes`/`-y` makes redeploy non-interactive; `--no-rebuild` skips the build;
  invalid `--action`/`--mode`/range values are rejected before changes.
- The helper does not delete persistent data under `/data`.

Manual rollback:

```bash
docker stop tunnel-proxy && docker rename tunnel-proxy tunnel-proxy-failed
docker start <previous-container-name>
```

## Platform notes

### HTTP-only PaaS

A platform that forwards HTTP/HTTPS to the container can serve HTTP tunnels
**only if clients can also reach the raw TCP control port** (default 9000).
The control channel cannot ride over HTTP, so an HTTP-only platform still
needs a public raw TCP port or another path to 9000 (for example a VPN). If
neither is available, the deployment is unsupported. Raw TCP/UDP tunnels
additionally require public raw ports (or a range) forwarded unchanged, which
most HTTP PaaS platforms do not provide. **Do not promise TCP/UDP tunnels on
such a platform**; use a VPS with a public IP for those.

### Oracle Cloud / other clouds

Open the ports in both the host firewall and the VCN security list / NSG.
Docker bridge-published ports bypass the host `INPUT` chain via Docker's own
rules, but host networking and direct runs do not.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Startup exits on `SHARED_SECRET`/`WILDCARD_DOMAIN` | Set real values; placeholders are rejected |
| Startup exits on certificates | DNS apex + wildcard, provider plugin/credentials, key readability; or set `HTTP_ONLY`/`EXTERNAL_SSL`/`ALLOW_HTTP_FALLBACK` |
| `Authentication failed: invalid signature` | Client token ≠ `SHARED_SECRET` |
| HTTP tunnel 404 | Wrong subdomain, or the name is unknown |
| HTTP tunnel 503 + `Retry-After: 2` | Client dropped and the reconnect wait expired/queue was full |
| TCP/UDP tunnel ready but unreachable | Port not published or blocked; range mismatch |
| Dashboard refuses to start | `DASHBOARD_PASSWORD`/`JWT_SECRET` missing or placeholder; startup validation fails |
| Dashboard 429 | Login throttled (5 attempts/60 s) |
| Container unhealthy during startup | Too many published ports on a small host; use host networking / a small range |

```bash
docker top tunnel-proxy
docker exec tunnel-proxy cat /var/log/tunnel-proxy/tunnel_proxy.log
docker logs --tail 100 tunnel-proxy
```