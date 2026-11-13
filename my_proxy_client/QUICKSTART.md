# Quick Start — LinkPulse Client

## Prerequisites

- Python 3.11 recommended (Docker image). Local runs/tests use Python 3.12.13;
  3.9–3.10 are not verified.
- A running LinkPulse server with `SHARED_SECRET` and `WILDCARD_DOMAIN` set.
- The shared secret and the server's control address (`host:9000`).

## Expose a local HTTP service

```bash
python3 my_proxy.py http 8080 \
  --token 'replace-with-shared-secret' --server proxy.example.com:9000
```

Or with environment variables:

```bash
export MY_PROXY_SERVER=proxy.example.com:9000
export MY_PROXY_TOKEN='replace-with-shared-secret'
export MY_PROXY_DASHBOARD=127.0.0.1:4040

python3 my_proxy.py http 8080
```

Output includes the public URL:

```
HTTP tunnel ready: https://a1b2c3d4.example.com -> 127.0.0.1:8080
```

Request a name and keep it for the session:

```bash
python3 my_proxy.py http 3000 -u myapp --lease
```

Without `--lease`, a newer client claiming the same name takes it over
(handoff mode).

## Expose TCP or UDP

```bash
python3 my_proxy.py tcp 22 --remote-port 20022
python3 my_proxy.py udp 5353
```

TCP/UDP tunnels need the server to have those public ports published (the
server's default pool is 20000–20100).

## Multiple tunnels

`tunnels.json`:

```json
{
  "server": "proxy.example.com:9000",
  "token": "shared-secret",
  "mode": "handoff",
  "tunnels": [
    { "type": "http", "local": "3000", "subdomain": "api", "mode": "lease" },
    { "type": "http", "local": "8080" },
    { "type": "tcp", "local": "22", "remote_port": 20022 },
    { "type": "udp", "local": "5353", "remote_port": 15353 }
  ]
}
```

```bash
python3 my_proxy.py start tunnels.json --token shared-secret
```

## Control-channel TLS

If the server has `CONTROL_TLS=true`:

```bash
python3 my_proxy.py http 8080 --tls
python3 my_proxy.py http 8080 --tls --ca-cert ./private-ca.pem
```

Certificate verification is mandatory. Without TLS, run over a VPN or other
private path; public HTTPS does not protect the client↔server leg.

## Run in the background

```bash
linkpulse http 8080 -d --token 'replace-with-shared-secret' --server proxy.example.com:9000
linkpulse clients list
linkpulse clients info <client-id>
linkpulse clients delete <client-id>
```

Logs: `~/.config/linkpulse/logs/<managed-id>.log` (`clients list` shows both
the machine `CLIENT ID` and the per-process `MANAGED ID`).

## Dashboard

Open `http://127.0.0.1:4040` for connection status, tunnels, counters and
recent logs. Disable with `--no-dashboard`. The dashboard has no
authentication.

## Test locally against a server

Terminal 1 — server (HTTP-only, non-privileged ports):

```bash
cd tunnel-proxy
SHARED_SECRET=test-secret WILDCARD_DOMAIN=forwarding.local \
DASHBOARD_PASSWORD=test-password JWT_SECRET=test-jwt-secret-0123456789abcdef \
HTTP_ONLY=true HTTP_PORT=8080 HTTPS_PORT=8443 DASHBOARD_PORT=8081 \
DB_PATH=/tmp/lp.db LOG_FILE=/tmp/lp.log \
python3 proxy_server.py
```

Terminal 2 — a local backend:

```bash
python3 -m http.server 8001
```

Terminal 3 — the client:

```bash
python3 my_proxy.py http 8001 -u test \
  --token test-secret --server 127.0.0.1:9000
```

Terminal 4 — through the tunnel:

```bash
curl -H 'Host: test.forwarding.local' http://127.0.0.1:8080/
```

## Troubleshooting

- `Connection refused`: wrong server/port (control port is 9000 by default) or
  the server is down/firewalled.
- `Authentication failed: invalid signature`: token does not match
  `SHARED_SECRET`. The client exits rather than retrying a wrong secret.
- TLS errors: server control TLS not enabled, or the CA/hostname cannot be
  verified; pass the right `--ca-cert`.
- Dashboard not reachable: `--no-dashboard` set, or port 4040 is occupied.
- More detail: `--log-level DEBUG`, or see [README.md](README.md).