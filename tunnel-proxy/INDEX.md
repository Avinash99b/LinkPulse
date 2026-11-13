# LinkPulse Server — Project Index

The server is one asyncio process (`proxy_server.py`) that binds every public
port itself: HTTP/HTTPS for tunnels and the dashboard, a raw control channel,
and one listener per TCP/UDP tunnel. SQLite is bookkeeping only. No nginx,
HAProxy or supervisord is involved.

Configuration is environment-only. Python 3.11 is recommended (Docker image);
local tests run on Python 3.12.13.

## File map

| File | Purpose |
|------|---------|
| `proxy_server.py` | Entry point: auth, routing, HTTP/TCP/UDP listeners, flow control, shutdown, limits |
| `protocol.py` | Canonical wire protocol: frames, HELLO, capabilities, UDP, constants |
| `storage.py` | SQLite client/tunnel bookkeeping (never used for live routing) |
| `dashboard.py` | Password/JWT dashboard HTML and `/api/stats` |
| `entrypoint.sh` | Root init: volumes, certbot, cron renewal, then unprivileged server |
| `startup.sh` | Optional deploy helper: detect state, build, health-wait, rollback |
| `Dockerfile` | Single container, direct server execution |
| `.env.example` | Complete environment template |
| `config.example.json` | Legacy shape reference only — the server does not parse it |
| `requirements.txt` | Optional `psutil` (dashboard CPU/RAM) |
| `examples/reference_client.py` | Illustrative protocol client |
| `README.md` | Server guide (setup, ports, env, TLS, reconnect waiting) |
| `DEPLOYMENT.md` | Docker/VPS deployment, certificates, rollback, platform limits |

## Quick orientation

```bash
cp .env.example .env      # SHARED_SECRET, WILDCARD_DOMAIN, DASHBOARD_PASSWORD, JWT_SECRET
docker build -t tunnel-proxy .
docker run -d --name tunnel-proxy --restart unless-stopped \
  --network host --cap-add NET_BIND_SERVICE --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy tunnel-proxy
curl -i http://localhost/health
```

Public ports:

| Port | Purpose |
|------|---------|
| 80 | `/health`, apex→HTTPS redirect, HTTP tunnels |
| 443 | HTTPS tunnels + dashboard |
| 9000 | Control channel |
| 20000–20100 TCP/UDP | One port per raw tunnel (configurable range) |

## What it does

- **Authentication**: HMAC-SHA256 HELLO over `client_id || timestamp || nonce`
  with 60-second skew and replay-tracked nonces. Authentication is one-way; no
  server challenge is involved.
- **HTTP routing**: by `Host` header / subdomain over the shared 80/443
  listeners.
- **TCP/UDP routing**: a dedicated public port per tunnel, allocated from the
  configured range.
- **Multiplexing**: one control connection per client process; independent
  streams with per-stream credit (256 KiB initial window, 64 KiB frames).
  Streams share one TCP connection, so TCP head-of-line effects are inherent.
- **HTTP reconnect waiting**: briefly parks the request head and socket for a
  known tunnel whose client just dropped (default 8 s; 16 per name, 128 total).
  Unknown → 404; expired/full → 503 + `Retry-After: 2`; no application-level
  body accumulation/spooling/replay (normal bounded TCP buffering only);
  waiters follow the current owner.
- **Ownership modes**: `handoff` (newest wins) or `lease` (session-scoped
  reservation).
- **Optional native control TLS**: `CONTROL_TLS=true`; clients verify the
  certificate (system trust or `--ca-cert`).
- **Dashboard**: password login, in-memory HS256 JWT sessions (up to 31 days;
  restart/logout/password rotation invalidates), login throttle, lockdown on
  logout; served on the apex HTTPS listener (or a standalone loopback listener
  in HTTP-only mode).
- **SQLite**: bookkeeping and observability only; routing is in memory and is
  rebuilt on reconnect.
- **Limits**: `MAX_CLIENTS`, `MAX_TUNNELS_PER_CLIENT`, `MAX_STREAMS_PER_CLIENT`,
  `MAX_PENDING_HTTP_CONNECTIONS`, UDP peer caps/idle timeout, stream write
  timeout.

## Protocol at a glance

```
[Magic:2 "TN"] [Ver:1] [Type:1] [StreamID:4] [Length:4] [Payload]
```

- Stream 0: control (HELLO, PING, tunnel registration, errors)
- Stream 1+: one HTTP connection / TCP connection / UDP peer
- `STREAM_EOF` (0x0F): optional negotiated half-close (`stream_eof` capability
  advertised in `HELLO_OK`, echoed in `TUNNEL_OPEN_REQUEST`); without the
  capability, peers use abortive `STREAM_CLOSE`.
- `UDP_DATAGRAM` (0x0E): one complete datagram (including empty), max 65507
  bytes, no TCP flow-control credit.

See `../my_proxy_client/PROTOCOL.md` for the full specification.

## Testing

```bash
pytest ../tests -q
```

Covers tunnel modes and reconnect behaviour, dashboard authentication,
detached-client process management, and an end-to-end client path against a
mock server. Platform coverage is not claimed beyond what is actually run.

## Production checklist

- [ ] `SHARED_SECRET` and `WILDCARD_DOMAIN` set (placeholders rejected)
- [ ] `DASHBOARD_PASSWORD` and `JWT_SECRET` set
- [ ] DNS: apex and `*.<domain>` resolve to the server
- [ ] Ports 80, 443, 9000 and the chosen tunnel range open in the host and
      cloud firewall
- [ ] Docker port mapping 1:1 for every tunnel port, or host networking
- [ ] Certificate provisioned (or an explicit `HTTP_ONLY`/`EXTERNAL_SSL`/
      `ALLOW_HTTP_FALLBACK` decision)
- [ ] `/data` (database + certificates) and `/var/log/tunnel-proxy` mounted
- [ ] Restrict dashboard exposure; use HTTPS off localhost
- [ ] Monitor health, the authenticated dashboard and logs