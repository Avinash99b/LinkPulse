# LinkPulse Server (`tunnel-proxy`)

The server side of LinkPulse: it accepts authenticated, multiplexed client
connections and routes public HTTP, TCP and UDP traffic back through them.
It runs as one asyncio process and binds every public port itself.

```
 browser ── :443 (HTTPS) ─┐
 client  ── :9000 (TCP) ──┤ proxy_server.py ── one persistent connection per client process
 public  ── :20000+ ──────┘   (in-memory routing, SQLite bookkeeping)
```

- Stdlib only; `psutil` is optional (adds CPU/RAM to the dashboard).
- Python 3.11 recommended (the Docker image); local tests run on 3.12.13.
- Configuration is **environment variables only**. `config.example.json` is a
  legacy shape reference and is never read.

## Quick start (Docker)

```bash
cp .env.example .env      # fill in the required values (below)
docker build -t tunnel-proxy .

# Recommended on a VPS: host networking, no per-port NAT/proxy overhead
docker run -d --name tunnel-proxy --restart unless-stopped \
  --network host \
  --cap-add NET_BIND_SERVICE \
  --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy \
  tunnel-proxy
```

With `--network host` the container binds 80, 443, 9000 and the tunnel range
directly; `--cap-add NET_BIND_SERVICE` lets the unprivileged server bind low
ports portably. Open those ports in the host firewall and the cloud security
list/NSG. With bridge networking, publish only a small range:

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

Mapping must be 1:1: the server advertises the container-side port, so
`-p 30000:20000` would advertise an unreachable port. The server only checks
that a port is bindable inside the container; an unpublished port looks
“ready” but is unreachable.

`/data` holds the SQLite database and `/data/letsencrypt`; mounting it
preserves client history and certificates across rebuilds.
`/var/log/tunnel-proxy` holds
the server and certbot logs.

Check health:

```bash
curl -si http://localhost/health | head -1
# /health always returns 200, including when HTTPS redirect is active
```

Optional helper (interactive or non-interactive) that detects existing
container/image/certificates/DNS, builds, waits for health, and restores the
previous container if the new one fails:

```bash
./startup.sh
./startup.sh --action redeploy --mode 4 --range 20000-20100 --yes
./startup.sh --action rebuild  --mode 4 --range 20000-20100 --yes
```

## Direct run (development)

```bash
SHARED_SECRET="$(openssl rand -hex 32)" \
WILDCARD_DOMAIN="tunnel.example.com" \
DASHBOARD_PASSWORD="a-long-password" \
JWT_SECRET="$(openssl rand -hex 32)" \
HTTP_ONLY=true HTTP_PORT=8080 HTTPS_PORT=8443 DASHBOARD_PORT=8081 \
python3 proxy_server.py
```

`HTTP_ONLY=true` avoids certificates and serves the dashboard on the standalone
`DASHBOARD_HOST:DASHBOARD_PORT` listener (loopback by default). Without
`HTTP_ONLY`, the server expects readable certificates at the configured paths
and fails startup if it cannot get them (see TLS below).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SHARED_SECRET` | — (required) | Client authentication secret |
| `WILDCARD_DOMAIN` | — (required) | Apex domain; `*.<domain>` must resolve to this host |
| `DASHBOARD_PASSWORD` | — (required) | Dashboard login password (min 8 chars; validated at startup) |
| `JWT_SECRET` | — (required) | HS256 signing secret for dashboard sessions (min 32 chars) |
| `CONTROL_HOST` | `0.0.0.0` | Control listener host |
| `CONTROL_PORT` | `9000` | Control channel port |
| `CONTROL_TLS` | `false` | Wrap the control channel in TLS |
| `CONTROL_CERT_PATH` | public cert path | Certificate for control TLS |
| `CONTROL_KEY_PATH` | public key path | Key for control TLS |
| `HTTP_HOST` / `HTTP_PORT` | `0.0.0.0` / `80` | Public HTTP listener |
| `HTTPS_HOST` / `HTTPS_PORT` | `0.0.0.0` / `443` | Public HTTPS listener |
| `TCP_PORT_MIN` / `TCP_PORT_MAX` | `20000` / `20100` | TCP tunnel port pool |
| `UDP_PORT_MIN` / `UDP_PORT_MAX` | `20000` / `20100` | UDP tunnel port pool |
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | `127.0.0.1` / `8081` | Standalone dashboard (HTTP-only mode) |
| `HTTP_ONLY` | `false` | No HTTPS listener; use `http://` public URLs |
| `EXTERNAL_SSL` | `false` | Skip certbot provisioning; a front proxy terminates TLS |
| `ALLOW_HTTP_FALLBACK` | `false` | Permit startup without a certificate (explicit downgrade) |
| `HEARTBEAT_INTERVAL` | `20` | Server ping interval (seconds) |
| `HEARTBEAT_TIMEOUT` | `60` | Drop an unresponsive client after this long |
| `STALE_GRACE_SECONDS` | `300` | Stale bookkeeping cleanup grace |
| `DB_PATH` | `/data/tunnel_proxy.db` | SQLite path |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `LOG_FILE` | `/var/log/tunnel-proxy/tunnel_proxy.log` | Log file |
| `HTTP_RECONNECT_GRACE_SECONDS` | `8` | Max wait for an unexpectedly dropped HTTP owner (`0` disables) |
| `HTTP_RECONNECT_MAX_WAITERS_PER_NAME` | `16` | Queued requests per subdomain |
| `HTTP_RECONNECT_MAX_WAITERS` | `128` | Queued requests globally |
| `MAX_CLIENTS` | `128` | Concurrent client sessions |
| `MAX_TUNNELS_PER_CLIENT` | `32` | Tunnels per client session |
| `MAX_STREAMS_PER_CLIENT` | `256` | Active streams per client session |
| `MAX_PENDING_HTTP_CONNECTIONS` | `256` | Pending HTTP connections |
| `UDP_MAX_PEERS_PER_TUNNEL` | `128` | Distinct UDP peers tracked per tunnel |
| `UDP_IDLE_TIMEOUT` | `60` | UDP peer idle expiry (seconds) |
| `STREAM_WRITE_TIMEOUT` | `30` | Stream write timeout (seconds) |

Required values are validated at startup: missing or placeholder
`SHARED_SECRET`/`WILDCARD_DOMAIN` and missing dashboard credentials fail loudly
instead of serving an insecure default. `DASHBOARD_PASSWORD` must be at least 8
characters and `JWT_SECRET` at least 32; generate `JWT_SECRET` with
`openssl rand -hex 32`. Dashboard sessions are HS256 JWTs valid for at most 31
days and are held in memory, so a server restart, logout, or dashboard-password
rotation invalidates them; API clients may send
`Authorization: Bearer <JWT>`. Use HTTPS whenever the dashboard is reachable
beyond localhost.

Directories for the database and log file are created automatically.

## Ports

| Port(s) | Purpose |
|---------|---------|
| 80 | `/health`, apex→HTTPS redirect, HTTP tunnels |
| 443 | HTTPS tunnels and dashboard (apex domain) |
| 9000 | Control channel (raw TCP, optional native TLS) |
| 20000–20100/tcp | One port per raw TCP tunnel |
| 20000–20100/udp | One port per raw UDP tunnel |

- HTTP tunnels share 80/443 and need no additional public HTTP port, but every
  tunnel still needs the control port 9000. Only TCP/UDP tunnels consume a
  dedicated public port.

## TLS and certificates

In the Docker image, `entrypoint.sh` runs as root to create/chown volumes, then
uses certbot (DNS challenge) to obtain a wildcard certificate for
`*.<WILDCARD_DOMAIN>` and the apex, storing it under `/data/letsencrypt`
(symlinked from `/etc/letsencrypt`). It then starts `proxy_server.py` as the
unprivileged `tunnelproxy` user. Certificate renewal is a separate daily cron
entry running `certbot renew`; renewed certificates are reloaded in place for
both the public HTTPS listener and control TLS (polled). Changing the
configured certificate paths requires a restart.

- Needs `DNS_PROVIDER` plus its credential (for Cloudflare: `CF_API_TOKEN`)
  and `CERTBOT_EMAIL`. Build the matching `certbot-dns-<provider>` plugin in
  the image/venv used for renewal so provisioning and renewal share one
  interpreter.
- `EXTERNAL_SSL=true` skips certbot when a reverse proxy terminates TLS.
- `HTTP_ONLY=true` skips certificate handling entirely.
- Without a certificate the server fails startup. `ALLOW_HTTP_FALLBACK=true`
  is the explicit opt-in to an HTTP-only run; never treat silent downgrade as
  normal.
- Keep private keys non-world-readable. The container makes the certificate
  directories traversable and sets key files to root:`tunnelproxy` mode 0640 so
  the unprivileged server can read them without exposing them to every user.
- **Control TLS** is separate from public HTTPS: `CONTROL_TLS=true` plus
  `CONTROL_CERT_PATH`/`CONTROL_KEY_PATH` (defaults: the public certificate).
  Clients must use `--tls` and validate the certificate (system trust store or
  `--ca-cert`); there is no insecure-skip-verify option. Plaintext control is
  acceptable only over a private network (VPN/WireGuard/SSH).

## HTTP reconnect waiting

When an HTTP tunnel's client connection drops unexpectedly, the server does not
immediately return 404:

1. The request headers and client socket are held while the name is
   re-registered, up to `HTTP_RECONNECT_GRACE_SECONDS` (default 8).
2. The waiting request is then forwarded to whoever currently owns the name —
   the reconnected client or a new legitimate claimant.
3. No application-level request-body accumulation, spooling, or replay. Only
   the pre-route request head is retained; the normal bounded TCP/asyncio
   receive path may hold some bytes with backpressure.
4. Unknown subdomains → immediate `404`. A known name whose wait expires (or a
   full queue) → `503` with `Retry-After: 2`. Grace `0` → immediate `404`.
5. An explicit close or a handoff does not create a waiting hint and does not
   extend a lease. The grace starts when the server *detects* the disconnect
   (heartbeat/inactivity), not necessarily when the physical link died.
6. Per-name and global waiter caps bound memory (`16` / `128` by default).

This is not stream resumption: open WebSocket connections and in-flight bodies
are still aborted on disconnect.

## Running and monitoring

- Dashboard: `https://<WILDCARD_DOMAIN>/` or `/dashboard/` (login required).
  In HTTP-only mode: `http://<DASHBOARD_HOST>:<DASHBOARD_PORT>/`.
- Stats API: `GET /api/stats` with a dashboard session or bearer JWT; no
  wildcard CORS.
- Health: `GET /health` (unauthenticated, always available).
- Logs: the console and `LOG_FILE`; the dashboard shows recent log lines.
  There is no built-in rotation, so bound the log file with logrotate, the
  container log driver, or your platform's log retention.

Dashboard login is throttled (5 attempts/60 s → `429`), sessions are in-memory
HS256 JWTs valid for at most 31 days, and logout or a password rotation
invalidates them; a server restart clears all sessions.

## Client usage

Use the real client in `my_proxy_client/`:

```bash
python3 ../my_proxy_client/my_proxy.py http 3000 \
  --server your-server:9000 --token "$SHARED_SECRET" -u myapp
```

A reference implementation for protocol work lives at
`examples/reference_client.py`. Point clients at **port 9000**, the control
channel.

Public URLs are `https://<subdomain>.<WILDCARD_DOMAIN>` (or `http://` when
`HTTP_ONLY=true`). The server echoes the granted subdomain in
`TUNNEL_OPEN_RESPONSE`, including for auto-assigned names.

## Tunnel ownership

| Mode | Behaviour |
|------|-----------|
| `handoff` (default) | Newest claimant wins; the previous owner gets `TUNNEL_CLOSE reason="handoff"` and stops serving that name. |
| `lease` | Reserved for the session. Other clients get `reason="leased"`; a lease request over an in-use name gets `reason="in_use"`. |

A reconnect of the same client process reclaims its own registration,
including a lease. Leases end when the owning session ends (heartbeat
timeout), so no name is reserved forever. A duplicate tunnel ID is rejected;
it never creates orphaned names or listeners.

## Deployment platforms

HTTP tunnels require a host that can serve 80/443 **and** expose the raw TCP
control port (default 9000) to clients. The control channel cannot ride over
HTTP; a platform that only forwards HTTP needs another path to 9000 (for
example a VPN), otherwise the deployment is unsupported. Raw TCP/UDP tunnels
also need a public raw TCP or UDP port (or range) forwarded unchanged. Most
HTTP PaaS platforms do not provide arbitrary raw TCP/UDP ports, so do not
promise TCP/UDP tunnels there; use a VPS with a public IP for those.

## Project structure

```
proxy_server.py       Server entry point (binds every port)
protocol.py           Canonical wire protocol
storage.py            SQLite bookkeeping
dashboard.py          Authenticated dashboard + JSON API
entrypoint.sh         Root init: volumes, certbot, cron, then server
startup.sh            Optional interactive deploy helper
Dockerfile            Direct-server container (no nginx/haproxy/supervisor)
.env.example          Environment template
config.example.json   Legacy shape reference only (not parsed)
requirements.txt      Optional psutil
examples/reference_client.py
DEPLOYMENT.md         Deployment detail
```

## Troubleshooting

- **Startup fails “SHARED_SECRET/WILDCARD_DOMAIN”**: set both; placeholders are
  rejected. The default secret in the source is not usable.
- **Startup fails on certificates**: check DNS (`*.<domain>` and apex), the
  certbot provider plugin/credentials, and key readability. For an intentional
  HTTP-only run set `HTTP_ONLY=true` (or `EXTERNAL_SSL=true` with a front
  proxy), or `ALLOW_HTTP_FALLBACK=true`.
- **`Authentication failed: invalid signature`**: client token does not match
  `SHARED_SECRET`.
- **Tunnel is `ready` but unreachable**: the port is not published/allowed on
  the host/cloud firewall, or the published port and `TCP_PORT_MIN/MAX` do not
  match.
- **Dashboard refuses to start**: `DASHBOARD_PASSWORD` or `JWT_SECRET` is
  unset or still a placeholder; startup fails validation.
- **Dashboard 429**: too many login attempts; wait a minute.
- **HTTP request gets 404 right after a client restart**: the name is not a
  known tunnel, or the grace was exceeded. A 503 means it was known but the
  wait expired.