# AGENTS.md — LinkPulse

## Project Overview

Self-hosted tunneling system (ngrok alternative) with two standalone components:

| Component | Path | Entry Point | Language | Dependencies |
|-----------|------|-------------|----------|--------------|
| Server | `tunnel-proxy/` | `proxy_server.py` | Python 3.9+ | stdlib only (psutil optional for dashboard) |
| Client | `my_proxy_client/` | `my_proxy.py` | Python 3.9+ | stdlib only |

**Shared protocol**: Both implement the same binary framed protocol (`protocol.py` in server, duplicated in `my_proxy.py`). Do not modify protocol logic without updating both.

---

## Developer Commands

### Server (tunnel-proxy/)

```bash
# Direct run (dev)
SHARED_SECRET="your-secret" WILDCARD_DOMAIN="tunnel.example.com" python3 proxy_server.py

# Docker build & run (production)
docker build -t tunnel-proxy .
docker run -d -p 80:80 -p 9000:9000 --env-file .env -v tunnel-proxy-data:/data tunnel-proxy

# Docker health check hits :8080 (proxy_server.py internal HTTP port)
```

**Required env vars**: `SHARED_SECRET`, `WILDCARD_DOMAIN`  
**All config via env vars** — no config files used in Docker/production.

### Client (my_proxy_client/)

```bash
# Direct run
python3 my_proxy.py http 8080 --token <secret> --server host:9000

# Or with env vars
export MY_PROXY_SERVER=host:9000
export MY_PROXY_TOKEN=<secret>
python3 my_proxy.py http 8080

# Multi-tunnel config
python3 my_proxy.py start tunnels.json --token <secret>
```

---

## Architecture Notes

- **Protocol**: Binary framed (12-byte header + payload), HMAC-SHA256 challenge-response auth, per-stream credit-based flow control (256 KiB windows), multiplexed over single TCP connection
- **Tunnel ownership modes** (client flag `--lease`, per-tunnel `"mode"` in JSON configs): public names (subdomain / TCP port / UDP port) are shared. `handoff` (default) means the newest claimant wins and the previous owner receives a `TUNNEL_CLOSE` with `reason="handoff"` (it logs `Tunnel 'x' was handed off to a new client` and exits if it has no tunnels left). `lease` reserves the name: other clients are refused with `reason="leased"`, and a lease request over an already-used name is refused with `reason="in_use"`. A reconnect of the same client process (`client_id` + `instance_id`) always reclaims its own registration.
- **Client identity**: `client_id` is shared by all client processes on a machine (persisted state file); `instance_id` is per process, so the server can distinguish a reconnect from a second competing process on the same machine.
- **Reconnect policy**: the client retries every `--retry-interval` seconds (default 5s) *forever*; `--grace-time` only escalates log level. Failed tunnel registrations (name in use/leased, no ports) are also retried every interval.
- **Server ports**: 
  - `:80` (HTTP) / `:443` (HTTPS) for HTTP tunnels + dashboard
  - `:9000` for control channel
- **Container**: direct `proxy_server.py` execution managed by `entrypoint.sh`
- **entrypoint.sh** runs as root to `chown` mounted volumes and handle certbot SSL provision, then runs `proxy_server.py`
- **Certificates**: Handled directly by certbot (Cloudflare/DNS challenge) inside container or external SSL

---

## Code Conventions

- **Zero external deps** (stdlib only) — intentional design, do not add dependencies
- **Protocol duplication**: `protocol.py` is the canonical source; `my_proxy.py` copies it verbatim. Keep in sync.
- **Asyncio throughout** — single-threaded, no threading
- **SQLite** for bookkeeping (`/data/tunnel_proxy.db`), directories auto-created

---

## Testing & Verification

Tests live in `tests/` (pytest). `tests/test_tunnel_modes.py` covers the
handoff/lease/instance-id rules and the client's indefinite reconnect loop;
`tests/test_end_to_end.py` covers detached clients and process management.

```bash
pytest tests/ -q
```

For manual verification:

```bash
# Server health
curl http://localhost/health

# Dashboard
curl http://localhost/api/stats | jq .

# Client round-trip
python3 my_proxy.py http 8080 --token <secret> --server host:9000
# In another terminal:
curl https://<subdomain>.tunnel.example.com/
```

Handy local run (no TLS, non-privileged ports): set `HTTP_PORT`,
`CONTROL_PORT`, `DASHBOARD_PORT`, `DB_PATH`, `LOG_FILE`, `HTTP_ONLY=true` and
point the client at `127.0.0.1:<CONTROL_PORT>`.

---

## Common Gotchas

1. **Control channel port**: Client connects directly to **port 9000**
2. **Two public ports**: 80/443 (HTTP/HTTPS) and 9000 (raw TCP control)
3. **Shared secret mismatch** → "Authentication failed: invalid signature"
4. **Windows Ctrl+C**: Fixed in current version (uses `signal.signal()` not `loop.add_signal_handler()`)
5. **DNS**: Wildcard `*.WILDCARD_DOMAIN` must resolve to server IP
6. **Persistent disks** (Render): `/data` mount requires entrypoint `chown` — handled by `entrypoint.sh`
7. **Same name, two clients**: default `handoff` mode gives the name to the newest client and the
   older one logs "handed off" and exits; use `--lease` to reserve a name. Two processes on one
   machine share `client_id` but have different `instance_id`s, so they compete (they are not
   mistaken for one client reconnecting).
8. **A lease lasts as long as its session**: after `HEARTBEAT_TIMEOUT` the server drops an
   unreachable owner and the name is free again (no permanent reservations).

---

## File Locations for Quick Reference

```
tunnel-proxy/
├── proxy_server.py      # Main server (894 lines)
├── protocol.py          # Canonical wire protocol (215 lines) — SOURCE OF TRUTH
├── storage.py           # SQLite persistence
├── dashboard.py         # Read-only status dashboard
├── nginx.conf           # HTTP proxy + stream config
├── haproxy.cfg          # HTTP front door
├── supervisord.conf     # Process manager config
├── entrypoint.sh        # Root entrypoint (chowns volumes)
├── Dockerfile           # Multi-stage build
├── DEPLOYMENT.md        # Detailed deployment guide
└── examples/reference_client.py

my_proxy_client/
├── my_proxy.py          # Single-file client (includes protocol copy)
├── config.example.json  # Multi-tunnel config template (supports "mode")
└── PROTOCOL.md          # Protocol spec (for implementers)

tests/
├── test_tunnel_modes.py    # handoff/lease/instance-id + retry-forever tests
└── test_end_to_end.py      # detached clients, process management
```