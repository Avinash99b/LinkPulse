# LinkPulse Client (`my_proxy`)

Expose local HTTP, TCP and UDP services through a LinkPulse server over one
persistent, authenticated, multiplexed connection. Single file, Python stdlib
only. Python 3.11 recommended (Docker image); local runs/tests use Python
3.12.13.

```
local :8080 ── my_proxy ── one multiplexed connection ── server ── https://app.example.com
```

## Install / run

Nothing to install; run the script (or the packaged `linkpulse` binary):

```bash
python3 my_proxy.py http 8080 --token 'replace-with-secret' --server proxy.example.com:9000
```

Or make it executable and use the launcher name:

```bash
chmod +x my_proxy
./my_proxy http 8080
```

## CLI

```
my_proxy http <port|host:port> [-u SUBDOMAIN] [options]
my_proxy tcp  <port|host:port> [--remote-port PORT] [options]
my_proxy udp  <port|host:port> [--remote-port PORT] [options]
my_proxy start <config.json> [options]
my_proxy authtoken <secret>
my_proxy server <host:port>
my_proxy clients list|info|delete|clear
```

Common options:

| Option | Env | Default | Meaning |
|--------|-----|---------|---------|
| `--server HOST:PORT` | `MY_PROXY_SERVER` | `127.0.0.1:9000` | Control-channel address |
| `--token SECRET` | `MY_PROXY_TOKEN` | — (required) | Shared secret |
| `--tls` | `MY_PROXY_TLS` | off | Use native TLS for the control channel |
| `--ca-cert PATH` | `MY_PROXY_CA_CERT` | system trust | CA bundle for control TLS |
| `--lease` | — | off | Lease the requested name (default: handoff) |
| `--retry-interval SECONDS` | `MY_PROXY_RETRY_INTERVAL` | `5` | Reconnect/registration retry delay |
| `--grace-time SECONDS` | — | `10` | When retry logs escalate from warnings to errors (never stops retrying) |
| `--dashboard HOST:PORT` | `MY_PROXY_DASHBOARD` | `127.0.0.1:4040` | Local read-only dashboard |
| `--no-dashboard` | — | off | Disable the dashboard |
| `--state-file PATH` | — | `~/.my_proxy/state.json` | Persistent client identity |
| `--log-level LEVEL` | — | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `-d, --detach` | — | off | Run in the background (via `linkpulse`) |

Value precedence: explicit CLI > environment > config file > saved
`authtoken.json` > defaults.

### TLS

TLS is optional; the server must have `CONTROL_TLS=true`. Certificate
verification is mandatory — there is no skip-verify mode:

```bash
my_proxy http 8080 --tls
my_proxy http 8080 --tls --ca-cert /path/to/private-ca.pem
```

Without TLS the control connection (including HTTP headers and bodies) is only
protected by the network path. Use a VPN/WireGuard/SSH tunnel or enable TLS on
untrusted networks. Public HTTPS covers the browser↔server leg only.

### Saving the token/server

```bash
linkpulse authtoken <secret>
linkpulse server proxy.example.com:9000
```

Both values are stored in `~/.config/linkpulse/authtoken.json` with mode 0600.

### Detached mode and management

```bash
linkpulse http 8080 -d
linkpulse tcp 22 --remote-port 20022 -d
linkpulse start config.json -d

linkpulse clients list
linkpulse clients info <client-id>
linkpulse clients delete <client-id>
linkpulse clients clear          # idle only
linkpulse clients clear -f       # stop and remove all
```

- The parent returns immediately after validating the invocation; logs go to
  `~/.config/linkpulse/logs/<managed-id>.log`
  (or `LINKPULSE_LOGS_DIR`).
- Per-process managed state is `~/.config/linkpulse/clients/<managed-id>.json`
  (or `LINKPULSE_STATE_DIR`).
- `linkpulse clients list` shows both the machine-wide `CLIENT ID` and the
  per-process `MANAGED ID`; `info`/`delete` accept either value or an
  unambiguous prefix. A foreground process gets its own managed ID; a detached
  run with no explicit client id uses the generated ID for both fields, but the
  state file is still keyed by the managed ID.
- Written files are created atomically with mode 0600. LinkPulse never changes
  the permissions of a parent directory you point `--state-file` at.
- Before signalling a PID, the manager verifies the recorded process start
  time. On platforms where that cannot be verified it fails closed and may
  refuse to manage the process.
- `delete` sends `SIGTERM`, waits up to 3 s, then `SIGKILL`.
- Aliases: `client`, `ls`, `show`/`status`, `stop`/`rm`/`kill`, `prune`.

## Multi-tunnel config

```json
{
  "server": "proxy.example.com:9000",
  "token": "shared-secret",
  "mode": "handoff",
  "tunnels": [
    { "type": "http", "local": "127.0.0.1:3000", "subdomain": "api", "mode": "lease" },
    { "type": "http", "local": "8080" },
    { "type": "tcp", "local": "localhost:22", "remote_port": 20022 },
    { "type": "udp", "local": "127.0.0.1:5353", "remote_port": 15353 }
  ]
}
```

Fields:

- `server`, `token` (optional defaults; CLI/env wins)
- `tls` (boolean) and `ca_cert` (path or null) for control-channel TLS; `ca_cert`
  implies TLS. CLI/env still wins.
- `mode` (top-level default: `"handoff"` or `"lease"`; `--lease` forces lease)
- `tunnels`: `type` (`http`/`tcp`/`udp`), `local` (port or `host:port`),
  optional `subdomain` (HTTP), `remote_port` (TCP/UDP), and per-tunnel `mode`.

## Tunnel behaviour

- Each HTTP request connection becomes a stream. Routing is by subdomain; a
  requested name is granted or the server assigns one. The granted subdomain is
  stored after `TUNNEL_OPEN_RESPONSE`, so an auto-assigned name survives
  reconnects.
- Each TCP connection becomes a stream; bytes are forwarded transparently.
- UDP uses one stream per public peer; one `UDP_DATAGRAM` frame per complete
  datagram (empty datagrams allowed, max 65507 bytes).
- Optional `STREAM_EOF` half-close lets one direction finish while the other
  keeps flowing, when both peers advertise the `stream_eof` capability. Older
  servers use abortive `STREAM_CLOSE`; the client falls back automatically.
- WebSocket upgrades and keep-alive work while the control connection lives,
  but they are **not resumed** after a reconnect.

### Ownership modes

| Mode | Behaviour |
|------|-----------|
| `handoff` (default) | Newest claimant wins; the previous owner is told `Tunnel 'x' was handed off to a new client` and stops serving it (exits if it has nothing left). |
| `lease` (`--lease`) | The name is reserved for this process/session; other clients are refused, and this client will not take over an in-use name. |

Two processes on one machine share `client_id` but have distinct
`instance_id`s, so they are competitors, not a reconnect (a lease refuses the
second one). A lease ends when its session ends; it is not permanent and is not
extended by HTTP reconnect waiting.

## Reliability

- **Retries forever**: a dropped/unreachable server is retried every
  `--retry-interval` seconds (default 5). `--grace-time` only changes log level.
- **Registrations retry too**: an in-use/leased name or exhausted port range is
  re-requested every interval until it succeeds.
- **Authentication failure exits** immediately (wrong secret cannot be fixed by
  retrying).
- **Local backend down**: per-request failure, not tunnel failure; the tunnel
  stays registered.
- **Graceful shutdown** (`SIGINT`/`SIGTERM`): closes tunnels, disconnects, exits.
- **Inactivity watchdog**: no server frame for roughly 3× heartbeat interval
  forces a reconnect.
- **Reconnect does not resume** WebSockets, in-flight requests, or partial
  uploads. HTTP requests waiting on the server see the current owner once the
  client is back; the server does not accumulate, spool, or replay a request
  body at the application level (normal bounded TCP buffering only).

## Dashboard

`http://127.0.0.1:4040` (or `--dashboard`) is a read-only local dashboard:
status, uptime, reconnect count, per-tunnel type/mode/public URL/local target,
connection and byte counters, first-byte-since-open “latency”, recent logs.
`/api/stats` returns the same JSON. It has no authentication, so keep it on
loopback (the default) or a trusted network.

Counters are accounting figures, not network RTT or throughput guarantees.

## Security

- Keep the shared secret private; rotate it if exposed.
- Prefer native control TLS (`--tls`, verified) or a private network.
- The client does not inspect, log, cache or replay request/response bodies.
- Credentials and state files are written atomically with mode 0600. A custom
  parent directory for `--state-file` is not chmod-ed by LinkPulse. Do not
  commit them.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `Connection refused` | Server running? Port 9000 open? |
| `Authentication failed: invalid signature` | `--token`/`MY_PROXY_TOKEN` matches `SHARED_SECRET` |
| TLS handshake failure | `CONTROL_TLS` enabled server-side; CA/hostname valid; `--ca-cert` correct |
| Local service unreachable | Backend listening on the configured host/port |
| Tunnel active but requests fail | Dashboard error text; local backend health |
| Dashboard missing | Not disabled; port 4040 free |
| Client exits at startup | Missing token, bad config, or auth failure; run `--log-level DEBUG` |
| HTTP request 503 after a reconnect | Server reconnect wait expired; retry |

## Protocol

See [PROTOCOL.md](PROTOCOL.md). The client embeds a synchronized copy of the
canonical `protocol.py`; keep them in sync when changing framing or frame
semantics.