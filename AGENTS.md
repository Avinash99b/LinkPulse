# AGENTS.md — LinkPulse

## Project overview

Self-hosted tunneling system with two standalone components. They share one
binary-framed, multiplexed wire protocol.

| Component | Path | Entry point | Language / deps |
|-----------|------|-------------|-----------------|
| Server | `tunnel-proxy/` | `proxy_server.py` | Python asyncio; stdlib only (`psutil` optional for dashboard CPU/RAM) |
| Client | `my_proxy_client/` | `my_proxy.py` (packaged as `linkpulse`) | Python asyncio; stdlib only |

Python **3.11** is recommended (the Docker image uses it). Local test runs use
Python 3.12.13; 3.9–3.10 are not verified, and hosted CI is configured but not
evidence in itself.

**Canonical protocol**: `tunnel-proxy/protocol.py`. `my_proxy_client/my_proxy.py`
contains a synchronized copy. Change both together.

---

## Developer commands

### Server

The server reads **environment variables only**; there is no config-file
parser, and `config.example.json` is a legacy reference file, not an input.

```bash
# Direct run (development; HTTP-only example)
cd tunnel-proxy
SHARED_SECRET="$(openssl rand -hex 32)" \
WILDCARD_DOMAIN="tunnel.example.com" \
DASHBOARD_PASSWORD="a-long-password" \
JWT_SECRET="$(openssl rand -hex 32)" \
HTTP_ONLY=true HTTP_PORT=8080 HTTPS_PORT=8443 DASHBOARD_PORT=8081 \
python3 proxy_server.py

# Docker (recommended for a server)
cp .env.example .env
docker build -t tunnel-proxy .
docker run -d --name tunnel-proxy --restart unless-stopped \
  --network host --cap-add NET_BIND_SERVICE --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy tunnel-proxy

# Optional interactive deploy helper (build/redeploy/health/rollback)
./startup.sh --action redeploy --mode 4 --range 20000-20100 --yes
```

Required env: `SHARED_SECRET`, `WILDCARD_DOMAIN`, `DASHBOARD_PASSWORD` (min 8
characters) and `JWT_SECRET` (min 32 characters); all are validated at startup.
Missing values or template placeholders fail startup. Without a certificate the server also
fails startup unless `HTTP_ONLY=true`, `EXTERNAL_SSL=true` or
`ALLOW_HTTP_FALLBACK=true` is set explicitly.

Docker health check hits `:80/health`; port 443 is the HTTPS/dashboard
listener and 9000 is the control channel. Raw tunnel ports default to
20000–20100 for both TCP and UDP and must be published 1:1.

### Client

```bash
python3 my_proxy.py http 8080 --token 'replace-with-secret' --server host:9000
python3 my_proxy.py tcp 22 --remote-port 20022
python3 my_proxy.py udp 5353
python3 my_proxy.py start tunnels.json

# env fallbacks
export MY_PROXY_SERVER=host:9000
export MY_PROXY_TOKEN='replace-with-secret'
python3 my_proxy.py http 8080
```

Precedence: explicit CLI > environment > config file > saved
`authtoken.json` > defaults. `linkpulse authtoken <secret>` and
`linkpulse server host:9000` save both values to
`~/.config/linkpulse/authtoken.json` (mode 0600).

---

## Architecture notes

- **Protocol**: 12-byte header (`TN` magic, version, type, stream id, length),
  HMAC-SHA256 HELLO (client id + timestamp + nonce, 60 s skew, nonce replay
  tracking), one multiplexed TCP control connection, per-stream credit flow
  control (256 KiB windows, 64 KiB frame payload cap).
- **Ownership modes** (`--lease`, per-tunnel `"mode"` in client JSON): a public
  name is a subdomain, TCP port or UDP port. `handoff` (default) gives a
  contested name to the newest claimant and revokes the previous owner with
  `TUNNEL_CLOSE reason="handoff"`. `lease` refuses other clients
  (`reason="leased"`) and refuses a lease over a name already in use
  (`reason="in_use"`). A reconnect of the same `(client_id, instance_id)`
  always reclaims its own registration. Leases last only for the owning
  session.
- **HTTP reconnect waiting**: when an HTTP tunnel's client drops unexpectedly,
  requests may wait up to `HTTP_RECONNECT_GRACE_SECONDS` (default 8) for the
  name to come back. The server parks the request head and client socket;
  there is no application-level accumulation, spooling, or replay of the
  request body (only normal bounded TCP receive buffering/backpressure).
  Bounds:
  `HTTP_RECONNECT_MAX_WAITERS_PER_NAME=16`,
  `HTTP_RECONNECT_MAX_WAITERS=128`. Unknown name → 404 immediately; known
  name with an expired wait or a full queue → 503 with `Retry-After: 2`;
  grace `0` disables waiting. Explicit close/handoff is not a wait or a lease
  extension; waiters follow the current owner.
- **No resume**: dropped control connections abort open streams (WebSocket,
  in-flight/partial bodies included). The client re-registers tunnels forever.
- **Control TLS** is opt-in: `CONTROL_TLS=true` (cert/key default to the public
  certificate). Clients use `--tls`/`MY_PROXY_TLS=true` with mandatory
  certificate verification (`--ca-cert`/`MY_PROXY_CA_CERT` or the system trust
  store). Plaintext remains supported for private networks only.
- **Server ports**: 80 HTTP, 443 HTTPS + dashboard, 9000 control, and one
  listener per raw TCP/UDP tunnel from the configured range.
- **Container lifecycle**: `entrypoint.sh` runs as root to create/chown
  volumes and provision the wildcard certificate with certbot (DNS challenge),
  installs a cron renewal entry, then `exec`s `proxy_server.py` as the
  unprivileged `tunnelproxy` user. There is no nginx, HAProxy or supervisord.
- **Dashboard**: password login plus HS256 JWT session; login throttled
  (5 attempts/60 s); tokens are valid up to 31 days but held in memory, so a
  restart, logout, or password rotation invalidates sessions. Binds loopback
  by default; the apex HTTPS listener serves it on 443.
- **Client identity**: machine-wide `client_id` in `~/.my_proxy/state.json`;
  managed/detached instances additionally record per-process state under
  `~/.config/linkpulse/clients/<managed-id>.json` (or
  `LINKPULSE_STATE_DIR`), with logs under `LINKPULSE_LOGS_DIR`. The managed ID
  is per process; a detached run with no explicit client id uses the same
  generated value for both, while the machine-wide `client_id` remains shared.
  `instance_id` is per process. Files
  LinkPulse creates are atomic mode 0600; a custom `--state-file` parent
  directory is not chmod-ed.
- **Process management** refuses to signal a PID unless the recorded process
  start time matches; on platforms where that cannot be verified it fails
  closed. Detached startup is validated before backgrounding and does not
  require the server to be online.

---

## Code conventions

- **Zero external dependencies** (stdlib only) for both components. `psutil`
  is optional server-side. Do not add runtime deps.
- Protocol duplication: `protocol.py` is canonical; keep `my_proxy.py` in sync.
- Asyncio throughout; no threads for request handling.
- SQLite is bookkeeping/observability only (`/data/tunnel_proxy.db`); live
  routing state lives in memory and is rebuilt on reconnect.
- Keep prose/docs free of unverified claims about throughput, latency, memory
  or platform coverage.
- Licensing: there is no `LICENSE` file. The owner permits unrestricted use and
  has deferred formalization. Do not add or imply a named license.

---

## Testing & verification

Tests live in `tests/` (pytest):

- `test_tunnel_modes.py` — handoff/lease/instance-id rules and indefinite
  reconnect behaviour.
- `test_end_to_end.py` — detached clients and process management.
- `test_dashboard_auth.py` — dashboard authentication regressions.
- `test_client_process_mgmt.py` — CLI and process/state handling.
- `test_reconnect_grace.py`, `test_data_plane_regressions.py`,
  `test_security_regressions.py`, `test_deployment_regressions.py`,
  `test_client_regressions.py` — focused regression coverage for HTTP
  reconnect waiting, stream/UDP data plane behaviour, security, deployment
  scripts, and client edge cases. `tests/_linkpulse_harness.py` is a shared
  helper, not a test module.
- `test_integration_contracts.py` — cross-component integration checks:
  canonical/embedded protocol AST parity, public half-close during a reconnect
  wait, dead-owner park, standalone dashboard connection bound/shutdown, live
  certificate reload, and in-progress backend-connect teardown.

```bash
pytest tests/ -q
```

Manual verification:

```bash
curl -i http://localhost/health              # always 200, redirect or not
curl -s http://127.0.0.1:8081/api/stats       # 401 without a session
python3 my_proxy.py http 8080 --token 'replace-with-secret' --server 127.0.0.1:9000
curl 'https://myapp.tunnel.example.com/'   # through the tunnel
```

For a local no-TLS run set `HTTP_ONLY=true` plus `HTTP_PORT`,
`CONTROL_PORT`, `DASHBOARD_PORT`, `DB_PATH`, `LOG_FILE`, and point the client
at `127.0.0.1:<CONTROL_PORT>`.

Do not claim Windows/macOS or hosted-CI results without actual evidence.

---

## Common gotchas

1. The client always connects to the **control port (default 9000)**, not 80/443.
2. Two public port families: 80/443 for HTTP(S)/dashboard, 9000 for control.
   Raw TCP/UDP tunnels each consume a dedicated published port.
3. Shared-secret mismatch → `Authentication failed: invalid signature`
   (the client exits; other failures are retried forever).
4. Wildcard DNS `*.<WILDCARD_DOMAIN>` and the apex must both point at the
   server, and port 443 must be reachable.
5. Bridge networking needs 1:1 port publishing for every tunnel port; host
   networking avoids per-port Docker proxy overhead but then the host firewall
   must allow the ports.
6. Same name, two clients: `handoff` gives it to the newest; `--lease` reserves
   it for the session. Same `client_id` with a different `instance_id` counts
   as a competitor, not a reconnect.
7. A lease is not permanent: an unreachable owner is dropped after
   `HEARTBEAT_TIMEOUT`, freeing the name.
8. The HTTP reconnect wait is not stream resumption: POST bodies are not
   buffered/replayed and WebSockets cannot be resumed.

---

## File map

```
tunnel-proxy/
├── proxy_server.py      # Server: control channel, HTTP/TCP/UDP listeners, routing
├── protocol.py          # Canonical wire protocol — SOURCE OF TRUTH
├── storage.py           # SQLite bookkeeping
├── dashboard.py         # Authenticated dashboard (HTML + JSON)
├── entrypoint.sh        # Root init: volumes, certbot, cron, then unprivileged server
├── startup.sh           # Optional deploy helper (build, health, rollback)
├── Dockerfile           # Direct-server single container
├── .env.example         # Environment template (all server config)
├── config.example.json  # Legacy shape reference only — NOT read by the server
├── examples/reference_client.py
└── DEPLOYMENT.md

my_proxy_client/
├── my_proxy.py          # Single-file client (includes protocol copy)
├── config.example.json  # Multi-tunnel config template
├── compile.sh           # PyInstaller build helper
└── PROTOCOL.md

tests/
├── test_tunnel_modes.py
├── test_end_to_end.py
├── test_dashboard_auth.py
├── test_client_process_mgmt.py
└── ...reconnect/data-plane/security/deployment/client regression tests
```

The root `linkpulse` and `my_proxy_client/linkpulse`, `my_proxy_client/my_proxy`
launchers are symlinks; keep them intact.