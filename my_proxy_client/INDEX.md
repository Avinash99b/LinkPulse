# LinkPulse Client — Project Index

`my_proxy.py` is a single-file, stdlib-only asyncio client for the LinkPulse
server. It exposes local HTTP/TCP/UDP services over one persistent,
authenticated, multiplexed connection, and retries forever when the server is
unreachable. Python 3.11 is recommended (Docker image); the local suite runs on
Python 3.12.13.

## Files

| File | Purpose |
|------|---------|
| `my_proxy.py` | Client (CLI, tunnel engine, protocol copy, dashboard, process management) |
| `my_proxy`, `linkpulse` | Symlink launchers; keep them intact |
| `config.example.json` | Multi-tunnel configuration template |
| `compile.sh` | PyInstaller one-file build helper |
| `requirements.txt` | Empty on purpose (stdlib only) |
| `README.md` | Full client guide (CLI, TLS, config, reliability, troubleshooting) |
| `QUICKSTART.md` | Short hands-on walkthrough |
| `PROTOCOL.md` | Wire protocol specification |

## Quick start

```bash
export MY_PROXY_SERVER=proxy.example.com:9000
export MY_PROXY_TOKEN='replace-with-shared-secret'

python3 my_proxy.py http 8080
python3 my_proxy.py http 8080 -u myapp
python3 my_proxy.py tcp 22 --remote-port 20022
python3 my_proxy.py udp 5353
python3 my_proxy.py start tunnels.json
```

Output looks like:

```
Connected to proxy.example.com:9000 (client_id=...)
HTTP tunnel ready: https://myapp.example.com -> 127.0.0.1:8080
Dashboard: http://127.0.0.1:4040
```

## Features

- HTTP, TCP and UDP tunnels; multiple tunnels from one JSON config.
- One persistent multiplexed connection with per-stream credit flow control.
- Reconnects and failed registrations retried every `--retry-interval`
  (default 5 s), indefinitely; `--grace-time` only affects log severity.
- Ownership modes: `handoff` (default) or `--lease` (session-scoped).
- Optional native control TLS with mandatory certificate verification
  (`--tls`, `--ca-cert` / `MY_PROXY_TLS`, `MY_PROXY_CA_CERT`).
- Optional per-stream half-close (`STREAM_EOF` / `stream_eof` capability), with
  automatic fallback to abortive `STREAM_CLOSE` for older servers.
- Detached mode plus `clients list|info|delete|clear`, with PID start-time
  verification that fails closed where it cannot verify.
- Local read-only dashboard at `127.0.0.1:4040`.

## Identity and state

| Data | Location |
|------|----------|
| Machine-wide `client_id` | `~/.my_proxy/state.json` (or `--state-file`) |
| Managed instance records | `~/.config/linkpulse/clients/<managed-id>.json` (`LINKPULSE_STATE_DIR`); the managed ID is per process (a detached run with no explicit client id uses the same generated value for both) |
| Detached logs | `~/.config/linkpulse/logs/<managed-id>.log` (`LINKPULSE_LOGS_DIR`) |
| Saved token + server | `~/.config/linkpulse/authtoken.json` (mode 0600) |

Files LinkPulse creates are written atomically with mode 0600; it does not
change permissions on a parent directory you supply for `--state-file`.

`client_id` is shared by client processes on the machine; `instance_id` is
per-process, so the server can distinguish a reconnect from a competing
second process.

## CLI at a glance

| Option | Env | Default |
|--------|-----|---------|
| `--server` | `MY_PROXY_SERVER` | `127.0.0.1:9000` |
| `--token` | `MY_PROXY_TOKEN` | required |
| `--tls` | `MY_PROXY_TLS` | off |
| `--ca-cert` | `MY_PROXY_CA_CERT` | system trust |
| `--lease` | — | off |
| `--retry-interval` | `MY_PROXY_RETRY_INTERVAL` | `5` |
| `--grace-time` | — | `10` |
| `--dashboard` | `MY_PROXY_DASHBOARD` | `127.0.0.1:4040` |
| `--no-dashboard` | — | off |
| `--state-file` | — | `~/.my_proxy/state.json` |
| `--log-level` | — | `INFO` |

Precedence: explicit CLI > environment > config file > saved token/server >
defaults.

## Testing

From the repository root:

```bash
pytest tests/ -q
```

The suite exercises tunnel ownership and reconnect behaviour, dashboard auth,
detached-client process management, and a client↔mock-server round trip.
Platform coverage is not claimed beyond what is actually run. Building the
standalone binary (`compile.sh` / the release workflow) is separate from the
Python script and is not verified on every platform here.

## Notes

- No request/response body inspection, caching or replay.
- Open streams (WebSockets, in-flight/partial bodies) are aborted on a control
  connection drop and are not resumed.
- The dashboard is unauthenticated; keep it on loopback.