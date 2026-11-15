# LinkPulse

Self-hosted tunneling (an ngrok alternative): expose local HTTP, TCP and UDP
services through your own server, over one persistent authenticated connection.

- **Server** — `tunnel-proxy/proxy_server.py`, Python asyncio. Binds public
  HTTP/HTTPS/control ports and one listener per raw TCP/UDP tunnel, and stores
  bookkeeping (not routing state) in SQLite.
- **Client** — `my_proxy_client/my_proxy.py`, also stdlib-only asyncio. One
  process can expose one service or several tunnels from a JSON config.

Everything routes through a single binary-framed, multiplexed control
connection. There is no external service in the data path (SQLite plus local
files only).

```
local service :8080 ── client ── one authenticated, multiplexed TCP connection ── server ── internet
                                                                 https://app.example.com
                                                                 tcp://example.com:20022
```

## Requirements

- Python **3.11 recommended** (the version used by the Docker image). The test
  suite has been run locally on Python 3.12.13; Python 3.9–3.10 are not
  verified here, and hosted CI is configured but not claimed as proof in this
  document.
- A wildcard DNS record: `<domain>` and `*.<domain>` must resolve to the server.
- Docker (recommended for the server) or a direct Python run for development.
- No Python package dependencies. `psutil` is optional and only adds CPU/RAM
  figures to the server dashboard.

## Quick start (server)

The server reads **environment variables only**. It does not accept or parse a
JSON config file.

```bash
cd tunnel-proxy
cp .env.example .env          # fill in the required values
docker build -t tunnel-proxy .
docker run -d --name tunnel-proxy --restart unless-stopped \
  --network host \
  --cap-add NET_BIND_SERVICE \
  --env-file .env \
  -v /data:/data -v /var/log/tunnel-proxy:/var/log/tunnel-proxy \
  tunnel-proxy
```

`--network host` is recommended on a VPS: it binds 80/443/9000 and the tunnel
port range directly, with no per-port Docker NAT rules. Pass
`--cap-add NET_BIND_SERVICE` explicitly so the unprivileged server can bind
ports 80/443 on any Docker configuration. With bridge networking,
publish `-p 80:80 -p 443:443 -p 9000:9000` and a **small** range such as
`-p 20000-20100:20000-20100` (plus `/udp` if you need UDP tunnels). Port 80 is
still needed for `/health` and the HTTP listener.

Required values:

| Variable | Purpose |
|----------|---------|
| `SHARED_SECRET` | Shared secret every client authenticates with |
| `WILDCARD_DOMAIN` | Apex domain whose wildcard points at the server |
| `DASHBOARD_PASSWORD` | Server dashboard login password (min 8 characters) |
| `JWT_SECRET` | HS256 signing secret for dashboard sessions (min 32 characters) |

The server refuses to start when a required secret is missing or still a
template placeholder. For local HTTP-only testing set `HTTP_ONLY=true`; you
then do not need certificates.

Minimal direct run:

```bash
cd tunnel-proxy
SHARED_SECRET="$(openssl rand -hex 32)" \
WILDCARD_DOMAIN="tunnel.example.com" \
DASHBOARD_PASSWORD="a-long-password" \
JWT_SECRET="$(openssl rand -hex 32)" \
HTTP_PORT=8080 HTTPS_PORT=8443 DASHBOARD_PORT=8081 \
HTTP_ONLY=true \
python3 proxy_server.py
```

`startup.sh` is an optional interactive helper that inspects the machine and
can build, redeploy, wait for health, and roll back a failed container:

```bash
./startup.sh --action redeploy --mode 4 --range 20000-20100 --yes
```

## Quick start (client)

There is nothing to install; run the script (or the packaged `linkpulse`
binary).

```bash
cd my_proxy_client
export MY_PROXY_SERVER=proxy.example.com:9000
export MY_PROXY_TOKEN='replace-with-shared-secret'

python3 my_proxy.py http 8080
python3 my_proxy.py http 8080 -u myapp
python3 my_proxy.py tcp 22 --remote-port 20022
python3 my_proxy.py udp 5353
python3 my_proxy.py start tunnels.json
```

`linkpulse` and `my_proxy` in that directory are symlink launchers for the same
script; use whichever is on your PATH.

Keep a name to yourself with `--lease`; the default `handoff` mode gives a
contested subdomain/port to the newest claimant.

Detached mode and process management use the `linkpulse` entry point:

```bash
linkpulse http 8080 -d
linkpulse clients list
linkpulse clients info <client-id>
linkpulse clients delete <client-id>
linkpulse clients clear [-f]
```

`clients list` shows both the machine-wide `CLIENT ID` and the per-process
`MANAGED ID` (a detached run with no explicit client id uses the same generated
value for both). `info`/`delete` accept either value or an unambiguous prefix.

The local client dashboard runs at `http://127.0.0.1:4040` (read-only, no auth;
bind it to loopback unless you trust the network).

## Ports

| Port | Purpose |
|------|---------|
| 80 | HTTP `/health`, apex→HTTPS redirect, HTTP tunnels |
| 443 | HTTPS tunnels and the server dashboard (apex domain) |
| 9000 | Control channel (raw TCP by default; optional native TLS) |
| `TCP_PORT_MIN..MAX` | One public port per TCP tunnel (default pool 20000–20100) |
| `UDP_PORT_MIN..MAX` | One public port per UDP tunnel (default pool 20000–20100) |

HTTP tunnels consume no additional public HTTP port — they share 80/443 via the
`Host` header — but every tunnel still needs the raw control port 9000.
Set a small, explicitly published range (for example 20000–20100) for TCP/UDP.
The server only checks that an allocated port is bindable *inside* the
container, so the published range and `TCP_PORT_MIN/MAX` (and `UDP_*`) must
match 1:1.

## TLS

- **Public HTTPS** is terminated by the server with the wildcard certificate.
  In the container, `entrypoint.sh` (as root) fixes volume ownership and
  obtains/reuses the certificate via certbot's DNS challenge, then starts
  `proxy_server.py` as the unprivileged user. Renewal runs from a separate
  root-only cron wrapper that invokes the pinned `/opt/venv/bin/certbot`; it is
  not a background task of the server process.
- `EXTERNAL_SSL=true` skips certbot entirely (put your own TLS terminator in
  front); `HTTP_ONLY=true` runs without a 443 listener.
- If certificates cannot be provisioned the server fails at startup rather
  than silently downgrading. Set `ALLOW_HTTP_FALLBACK=true` only when you
  explicitly want an HTTP-only run without a certificate.
- **Control channel TLS** is optional: set `CONTROL_TLS=true`, with
  `CONTROL_CERT_PATH`/`CONTROL_KEY_PATH` (defaulting to the public
  certificate). Clients then use `--tls` (or `MY_PROXY_TLS=true`); certificate
  verification is mandatory, using the system trust store or `--ca-cert`
  (`MY_PROXY_CA_CERT`). Renewed certificates are reloaded in place for both the
  public HTTPS listener and control TLS; changing the configured certificate
  paths still requires a restart.

Without control TLS, HMAC authenticates the client but the control connection
— including HTTP headers and request/response bodies — is only as private as
the network path. Use a VPN/WireGuard/SSH tunnel or native control TLS on
untrusted networks. Public HTTPS protects the browser↔server leg only, not the
client↔server leg.

## HTTP reconnect waiting

HTTP requests are held only briefly when an HTTP tunnel's client has just
dropped unexpectedly:

- `HTTP_RECONNECT_GRACE_SECONDS=8` — how long a request may wait.
  `0` disables waiting (an unknown name is then an immediate 404).
- `HTTP_RECONNECT_MAX_WAITERS_PER_NAME=16` and
  `HTTP_RECONNECT_MAX_WAITERS=128` bound queued requests.
- The server parks the parsed request head and the client socket. It does not
  accumulate, spool, or replay the request body at the application level.
  A normal bounded TCP/asyncio receive buffer with backpressure may hold some
  bytes; there is no unbounded application-level body buffering or replay.
- Unknown subdomains get `404`. A known name whose wait expires gets
  `503` with `Retry-After: 2`.
- An explicit client close or a handoff does not create a wait/reservation.
  Waiting requests follow the current owner, including a new competitor.
- A lease lasts only as long as its session and is not extended by waiting.
- The grace period starts when the server detects the disconnect, which may be
  later than the physical link died (heartbeat/inactivity detection).

There is **no stream resumption**: a dropped control connection aborts open
streams, including WebSocket connections and partially uploaded bodies. The
client retries the control connection and re-registers its tunnels forever.

## Architecture

- Single-threaded asyncio; no threads for request handling.
- One TCP control connection per client process; streams are multiplexed with
  per-stream credit-based flow control (256 KiB initial window, 64 KiB maximum
  frame payload).
- HELLO authentication: HMAC-SHA256 over `client_id || timestamp || nonce`, with
  a 60-second timestamp window and single-use nonce tracking (replay
  protection). This is one-way authentication, not a challenge-response: there
  is no server challenge.
- Routing tables live in memory and are rebuilt on reconnect. SQLite records
  clients/tunnels for observability only.
- Client identity: `client_id` is persisted per machine and shared by processes
  on that machine; a per-process `instance_id` distinguishes a genuine
  reconnect from a second competing process.
- Tunnels can carry HTTP, TCP or UDP. UDP uses one `UDP_DATAGRAM` frame per
  complete datagram (empty datagrams allowed, maximum 65507 bytes) over one
  stream per public peer; it does not consume TCP flow-control credit.
- Optional per-stream half-close (`STREAM_EOF`, capability `stream_eof`) keeps
  the opposite direction open until both sides finish. Older peers fall back
  to full `STREAM_CLOSE` aborts.

See `my_proxy_client/PROTOCOL.md` for the wire format.

## Limits and accounting

Server defaults (environment-tunable): `MAX_CLIENTS=128`,
`MAX_TUNNELS_PER_CLIENT=32`, `MAX_STREAMS_PER_CLIENT=256`,
`MAX_PENDING_HTTP_CONNECTIONS=256`, `UDP_MAX_PEERS_PER_TUNNEL=128`,
`UDP_IDLE_TIMEOUT=60` seconds, `STREAM_WRITE_TIMEOUT=30` seconds.

Dashboard counters are connection/stream/byte counts; the server dashboard does
not report latency. The client dashboard's “average latency” is a
first-byte-since-stream-open figure, not network RTT. No throughput,
end-to-end latency or memory figures are promised here.

There is one shared TCP connection, so a large frame or a stalled stream can
still cause head-of-line delay. Per-stream queues are bounded, but the design
makes no claim of absolute independence from TCP behaviour.

## Dashboard

With HTTPS enabled, the server dashboard is served on the apex domain
(`/` and `/dashboard/`) and requires `DASHBOARD_PASSWORD`/`JWT_SECRET`.
With `HTTP_ONLY=true`, a standalone dashboard listener binds
`DASHBOARD_HOST:DASHBOARD_PORT` (loopback by default) instead; it admits at
most 128 concurrent connections and cancels its handlers on shutdown so a slow
unauthenticated client cannot queue unbounded work.

Dashboard login is throttled (5 attempts per 60 seconds per source address).
Sessions are signed HS256 JWTs valid for at most 31 days, but they are
in-memory: a server restart, logout, or dashboard-password rotation invalidates
them. `GET /health` remains unauthenticated.

## Testing

```bash
pytest tests/ -q
```

The suite covers tunnel ownership/reconnect behaviour, dashboard auth,
detached-client process management, and a client↔mock-server end-to-end path.
Results depend on the platform and Python version; this repository does not
claim CI coverage of every OS.

## Hosting platforms

HTTP tunnels require a host that can serve 80/443 **and** expose the raw TCP
control port (default 9000) to clients. The control channel cannot ride over
HTTP; a platform that only forwards HTTP needs another path to 9000 (for
example a VPN), otherwise the deployment is unsupported. Raw TCP/UDP tunnels
additionally need a **public raw TCP or UDP port** (or a contiguous range)
forwarded unchanged. Most HTTP PaaS platforms do not provide arbitrary raw
TCP/UDP ports, so do not assume their “TCP service” feature proxies one until
you have verified it. A VPS with a public IP is the recommended deployment.

## Limitations

- No per-tenant bandwidth/rate quota or per-tunnel ACL. Connection/resource
  caps do exist (`MAX_CLIENTS`, `MAX_TUNNELS_PER_CLIENT`,
  `MAX_STREAMS_PER_CLIENT`, pending-HTTP/UDP limits).
- No stream/body resumption across reconnects.
- Dashboard/listener tuning is environment-only; there is no config-file
  parser on the server.
- Only the shared-secret HMAC authentication method is provided.
- Server logs go to `LOG_FILE`/stdout with no built-in rotation; bound them with
  logrotate, the container log driver, or a size-limited journal.
- No cross-platform CI guarantee is claimed for the packaged binaries.

## License

There is no `LICENSE` file and no formally declared license yet. The owner
permits unrestricted use: *“its my own repository, dont bother about licensing
for now, just keep it fully opensource, anyone can use however the heck they
want”*. License formalization is deliberately deferred; do not treat this
project as MIT-licensed or as carrying any other named license until a
`LICENSE` file is added.