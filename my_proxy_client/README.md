# my_proxy — Client for the self-hosted tunneling proxy

A production-quality client for the `proxy_server.py` tunneling proxy. Exposes local HTTP and TCP services on public URLs/ports via a single persistent, multiplexed connection. Handles reconnects with exponential backoff, graceful shutdown, and automatic recovery.

**1,098 lines, zero external dependencies** (uses only Python stdlib: asyncio, ssl, sqlite3, struct, json, etc.).

## Quick start

```bash
# Expose local HTTP service
my_proxy http 8080
my_proxy http localhost:3000
my_proxy http 5173 -u myapp

# Expose local TCP service
my_proxy tcp 22
my_proxy tcp 25565

# Expose multiple services at once
my_proxy start tunnels.json

# All commands require a shared secret:
my_proxy http 8080 --token <shared-secret>

# Or set environment variable:
export MY_PROXY_TOKEN=<shared-secret>
my_proxy http 8080
```

## Features

✅ **Single persistent connection** — All tunnels multiplexed over one authenticated TCP connection  
✅ **HTTP and TCP forwarding** — Host header–based routing for HTTP; random port allocation for TCP  
✅ **Automatic reconnect** — Exponential backoff (0.5s → 1s → 2s → 4s → 8s) with grace period (default 10s)  
✅ **Local dashboard** — Real-time tunnel status, bytes/connection counts, latency, logs (default `127.0.0.1:4040`)  
✅ **Flow control** — Per-stream credit-based backpressure (256 KiB windows), prevents stalling  
✅ **Graceful shutdown** — SIGINT/SIGTERM cleanly closes tunnels and disconnects  
✅ **Persistent identity** — Client ID saved across restarts for stable public URLs  
✅ **Zero external deps** — Only Python stdlib  

## Project structure

```
my_proxy                    Single-file client (1,098 lines)
README.md                   This file
config.example.json         Multi-tunnel config template
requirements.txt            Python dependencies (empty — stdlib only)
PROTOCOL.md                 Wire protocol spec (for client implementers)
```

---

## Installation

### Requirements

- Python 3.9+
- A running `proxy_server.py` instance
- The shared secret configured on the server

### Setup

```bash
# No installation needed; just run directly:
python3 my_proxy http 8080 --token <secret>

# Or make executable and add to PATH:
chmod +x my_proxy
./my_proxy http 8080 --token <secret>
```

---

## CLI reference

### Commands

#### `my_proxy http <target> [options]`

Expose a local HTTP service on a public HTTPS URL.

**Arguments:**
- `<target>` — local port (e.g., `8080`) or `host:port` (e.g., `localhost:5173`)

**Options:**
- `-u, --subdomain <subdomain>` — request a specific subdomain (e.g., `myapp` → `https://myapp.forwarding.example.com`)

**Example:**
```bash
my_proxy http 8080
my_proxy http localhost:5173 -u frontend
my_proxy http 127.0.0.1:3000 --token mysecret
```

#### `my_proxy tcp <target> [options]`

Expose a local TCP service on a random public port.

**Arguments:**
- `<target>` — local port (e.g., `22`) or `host:port` (e.g., `127.0.0.1:25565`)

**Options:**
- `--remote-port <port>` — request a specific public port

**Example:**
```bash
my_proxy tcp 22
my_proxy tcp 25565 --remote-port 20000
my_proxy tcp localhost:5432 --token mysecret
```

#### `my_proxy start <config>`

Open multiple tunnels at once from a JSON config file.

**Arguments:**
- `<config>` — path to JSON file (see `config.example.json`)

**Example:**
```bash
my_proxy start tunnels.json --token mysecret
```

#### Detached Mode (`-d` / `--detach`)

Run any port-forwarding command in background mode:

```bash
# Expose HTTP in background
linkpulse http 8080 -d --token <secret> --server proxy.example.com:9000

# Expose TCP in background
linkpulse tcp 22 --remote-port 20022 -d --token <secret> --server proxy.example.com:9000

# Expose multi-tunnel in background
linkpulse start config.json -d
```

When detached mode is requested:
- Spawns an independent background child process.
- The parent process returns to the shell immediately.
- Stdin/stdout/stderr are cleanly detached; child logs are written to `~/.config/linkpulse/logs/<client-id>.log`.

#### Client Management (`clients`)

Manage running and detached LinkPulse client instances:

```bash
# List all running and managed clients
linkpulse clients list

# View detailed information for a client (accepts full ID or prefix)
linkpulse clients info <client-id>

# Gracefully stop a client and remove its local state
linkpulse clients delete <client-id>

# Remove all idle (stopped) clients
linkpulse clients clear

# Stop and remove ALL clients (including connected ones)
linkpulse clients clear -f
```

Aliases supported: `client` for `clients`, `ls` for `list`, `show`/`status` for `info`, `stop`/`rm`/`kill` for `delete`, `prune` for `clear`.

### Global options

All commands support:

| Option | Env var | Default | Description |
|--------|---------|---------|-------------|
| `-d, --detach` | — | (off) | Run client in background (detached mode) |
| `--server <host:port>` | `MY_PROXY_SERVER` | `127.0.0.1:9000` | Proxy server address |
| `--token <secret>` | `MY_PROXY_TOKEN` | (required) | Shared authentication secret |
| `--grace-time <seconds>` | — | `10` | How long to retry if server unreachable before giving up |
| `--dashboard <host:port>` | `MY_PROXY_DASHBOARD` | `127.0.0.1:4040` | Local status dashboard |
| `--no-dashboard` | — | (off) | Disable the dashboard |
| `--state-file <path>` | — | `~/.my_proxy/state.json` (foreground) / `~/.config/linkpulse/clients/<id>.json` (detached) | Custom state file path |
| `--log-level <LEVEL>` | — | `INFO` | DEBUG, INFO, WARNING, ERROR |

### Examples

```bash
# Simple HTTP tunnel with default server/secret from env
export MY_PROXY_SERVER=proxy.example.com:9000
export MY_PROXY_TOKEN=my-shared-secret
my_proxy http 8080

# HTTP tunnel with custom subdomain
my_proxy http 3000 -u api --server proxy.example.com:9000 --token mysecret

# TCP tunnel for SSH with preferred port
my_proxy tcp 22 --remote-port 20022 --server proxy.example.com:9000 --token mysecret

# Multiple tunnels at once
my_proxy start config.json --server proxy.example.com:9000 --token mysecret

# Disable dashboard, custom grace period, debug logging
my_proxy http 5173 --no-dashboard --grace-time 30 --log-level DEBUG
```

---

## Configuration (multi-tunnel)

Create a JSON file to configure multiple tunnels:

```json
{
  "server": "proxy.example.com:9000",
  "token": "shared-secret-or-use-CLI-flag",
  "tunnels": [
    {
      "type": "http",
      "local": "127.0.0.1:3000",
      "subdomain": "api"
    },
    {
      "type": "http",
      "local": "8080"
    },
    {
      "type": "tcp",
      "local": "localhost:22",
      "remote_port": 20022
    },
    {
      "type": "tcp",
      "local": "5432"
    }
  ]
}
```

**Fields:**
- `server` (optional) — proxy server address (overridden by `--server` CLI flag)
- `token` (optional) — shared secret (overridden by `--token` CLI flag)
- `tunnels` (required) — array of tunnel specs:
  - `type` — `"http"` or `"tcp"`
  - `local` — port or `host:port` string
  - `subdomain` (http only, optional) — requested subdomain
  - `remote_port` (tcp only, optional) — requested public port

Run with:
```bash
my_proxy start config.json --token mysecret
```

---

## Dashboard

A lightweight read-only status page accessible at `http://127.0.0.1:4040` (or configured `--dashboard` address).

**Shows:**
- Connection status (connecting, connected, reconnecting, disconnected, stopped)
- Process uptime
- Server address and client ID
- Reconnect count
- Per-tunnel info:
  - Type (http/tcp), status (pending/active/error)
  - Public URL
  - Local destination (host:port)
  - Connection count
  - Bytes in/out
  - Average latency (if available)
- Recent log messages

**API:**
- `GET /` — HTML dashboard (auto-refreshes every 2 seconds)
- `GET /api/stats` — JSON stats payload

No authentication, no request inspection, no replay, no packet capture.

---

## Tunnel behavior

### HTTP tunnels

- Requests are routed to the local service based on the `Host` header / subdomain
- The first HTTP request on a connection determines which tunnel owns it; subsequent requests on the same TCP connection stay with that tunnel
- WebSocket upgrades and keep-alive both work transparently (the proxy doesn't parse individual HTTP requests after routing)
- Each `STREAM_OPEN` from the server gets its own local TCP connection to the backend

### TCP tunnels

- Each incoming public TCP connection becomes one stream
- All bytes are forwarded transparently (no parsing, no protocol awareness)
- Connection stays open until either side closes

### Subdomains

- Specify with `-u myapp` or the config file
- If not specified, a random subdomain is assigned
- Subdomains are first-come, first-served across all clients
- If you reconnect and request the same subdomain, you get it back (if no one else claimed it in the meantime)

### Public ports (TCP)

- Allocated randomly from the server's configured range (e.g., 20000–20100)
- Can request a preferred port with `--remote-port PORT`
- Ports are freed when the tunnel closes and reusable by other clients
- The server logs/dashboard show the assigned port after `TUNNEL_OPEN_RESPONSE`

---

## Reliability & error handling

### Reconnect behavior

If the server becomes unreachable:
1. Client detects the disconnect (read error or inactivity timeout)
2. Enters reconnecting mode, logs a warning
3. Retries with exponential backoff: 0.5s, 1s, 2s, 4s, 8s, ...
4. If server is unreachable for > `--grace-time` seconds (default 10s), gives up and exits
5. All reconnects attempt to re-register the same tunnels (same subdomain/port if possible)

### Local service failure

If the local backend is down (connection refused, timeout):
- The client logs a warning but **doesn't** tear down the tunnel
- The tunnel remains registered and active
- Per-request failures are handled normally (connection errors sent back to the public side)
- The tunnel is still available if the local service comes back up

### Authentication failure

- If the shared secret is wrong: client exits immediately (exit code 1) with a clear error
- Not retried (retrying won't help if the secret is wrong)
- Check `--token` and server configuration

### Graceful shutdown

- SIGINT (`Ctrl+C`) or SIGTERM triggers clean shutdown:
  1. Client sends `TUNNEL_CLOSE` frames for all active tunnels
  2. Gracefully disconnects from server
  3. Exits with code 0
- In-flight connections are closed; no data loss recovery (see protocol spec)

### Inactivity detection

- If no frames received from server for 3× heartbeat interval (default 60s), client reconnects
- Acts as a safety net for silently dropped connections

---

## Performance & limits

- **Flow control**: each stream has a 256 KiB send window; backpressure is applied automatically
- **Frame chunking**: payloads > 64 KiB are split into multiple frames
- **Multiplexing**: all streams share one TCP connection; latency of one stream doesn't affect others (independent flow windows)
- **Memory**: bounded by number of concurrent connections (each stream ≈ a few KB of state)

No request inspection, no traffic replay, no packet capture — the proxy is intentionally transparent to the application protocols.

---

## Security & privacy

**What the client does NOT do:**
- Inspect, log, or replay request/response bodies
- Capture or cache traffic
- Store credentials or sensitive data (except the shared secret, which is in memory only)

**What you SHOULD do:**
- Keep the shared secret **secure** and **unique** (treat it like a password)
- Rotate it periodically if you suspect compromise
- Run the client and server over a **private network** (LAN, WireGuard, VPN) if possible
  - Optionally enable TLS on the control channel (`control.tls: true` in server config)
  - The current version uses HMAC-SHA256 challenge-response, not full encryption
- Never commit the secret to version control (use env vars or `.env` files with `.gitignore`)

---

## Troubleshooting

### `Connection refused` to server

- Confirm server is running: `curl http://<server>:9000/` (or check port in config)
- Confirm firewall allows the control port (default 9000)
- Check server logs for crashes or binding errors

### `Authentication failed: invalid signature`

- Wrong `--token` / `MY_PROXY_TOKEN`
- Confirm token matches server's `shared_secret` in `config.json`

### `Local service <host>:<port> unreachable`

- Confirm your backend is listening on that address/port
- `netstat -ln | grep :8080` (if testing port 8080)
- Check firewall (localhost should be allowed)

### Tunnel is active but requests fail

- Check dashboard for per-tunnel status
- If status is "error", read the error message for details
- If status is "active" but requests hang, local service may be slow/unresponsive

### Dashboard not accessible

- Confirm it's enabled (no `--no-dashboard` flag)
- Confirm `--dashboard` address is correct
- Check if another process is using that port (`lsof -i :4040`)

### Client exits immediately after connecting

- Check log for error messages (usually authentication or server config issue)
- Run with `--log-level DEBUG` for verbose output

### High latency on tunneled requests

- Latency is measured from first byte sent to local backend to response received
- If consistently high, your local service may be slow
- Check dashboard for per-tunnel average latency
- Confirm no other clients are hogging the connection (multiple streams shouldn't interfere due to independent flow control)

---

## Advanced usage

### Debug logging

```bash
my_proxy http 8080 --log-level DEBUG
```

Prints frame-by-frame protocol details, useful for troubleshooting protocol issues.

### Custom state file

```bash
my_proxy http 8080 --state-file /tmp/my_proxy_state.json
```

By default, client ID is persisted in `~/.my_proxy/state.json`. Useful for testing or running multiple instances.

### Longer grace period

```bash
my_proxy http 8080 --grace-time 60
```

Wait up to 60 seconds for server to come back before giving up (default 10s).

### Custom dashboard port

```bash
my_proxy http 8080 --dashboard 0.0.0.0:8888
```

Bind dashboard to all interfaces on port 8888 (security: dashboard has no auth, only bind to trusted networks).

---

## Process Management & State Lifecycle

### Local State Storage

- Client state files are saved in `~/.config/linkpulse/clients/<client-id>.json` (or `$LINKPULSE_STATE_DIR`).
- Detached process logs are saved in `~/.config/linkpulse/logs/<client-id>.log` (or `$LINKPULSE_LOGS_DIR`).
- Auth token and saved server address are saved in `~/.config/linkpulse/authtoken.json` and `~/.config/linkpulse/server.json`.

### How Detached Processes Are Managed

- **Identification**: Each client is tracked with a unique `client_id` (UUID hex), PID, start timestamp, target mode, and server address.
- **Liveness & PID Safety**: When checking or stopping a client, LinkPulse verifies whether the process is alive, not in a zombie state, and that the command line matches Python/LinkPulse. This prevents PID reuse from signaling unrelated processes.
- **Graceful Termination**: `linkpulse clients delete <client-id>` sends `SIGTERM`, allows up to 3 seconds for graceful disconnection and tunnel closure, escalates to `SIGKILL` only if unresponsive, and removes the state file.
- **After Reboot**: If the machine reboots, state entries whose PIDs no longer exist are cleanly shown as `stopped` and removed when `clients delete` is called.
- **Multiple Clients**: Any number of independent client instances can run concurrently in detached mode without conflicting state files.

---

## Protocol compliance

This client implements the **canonical wire protocol** exactly as defined by `proxy_server.py`:

- Frame layout: 12-byte header (magic, version, type, stream_id, length) + variable payload
- HELLO authentication: HMAC-SHA256 challenge-response
- Multiplexing: independent streams over one connection
- Flow control: per-stream, credit-based, 256 KiB windows
- Reconnect semantics: client ID persists, tunnels re-registered by tunnel_id

See `PROTOCOL.md` for the full spec (or `protocol.py` in the server project for the reference implementation).

---

## License & credits

Built to interoperate exactly with `proxy_server.py` (also in this project). Both implement the same canonical protocol, ensuring client/server compatibility and making alternative implementations straightforward.

Clean, production-quality code with zero external dependencies — suitable for embedded use, CI runners, or self-hosting with minimal footprint.
