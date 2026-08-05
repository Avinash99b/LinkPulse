# Quick Start Guide

## Prerequisites

- Python 3.9+
- A running `proxy_server.py` instance (see the server project)
- The shared secret from the server config

## Installation

No installation needed. Just run:

```bash
python3 my_proxy http 8080 --token <shared-secret>
```

Or make it executable:

```bash
chmod +x my_proxy
./my_proxy http 8080 --token <shared-secret>
```

## Basic usage

### 1. Expose a local HTTP service

```bash
# Expose localhost:8080
my_proxy http 8080 --token mysecret

# Expose on a different host
my_proxy http localhost:5173 --token mysecret

# Request a specific subdomain
my_proxy http 3000 -u myapp --token mysecret
```

The client will print the public URL:
```
HTTP tunnel ready: https://myapp.forwarding.example.com -> localhost:3000
```

Test it:
```bash
curl https://myapp.forwarding.example.com/
```

### 2. Expose a local TCP service

```bash
# Expose localhost:22 (SSH)
my_proxy tcp 22 --token mysecret

# Request a specific port
my_proxy tcp 25565 --remote-port 20000 --token mysecret
```

The client will print the public address:
```
TCP tunnel ready: tcp://forwarding.example.com:20000 -> localhost:25565
```

Test it:
```bash
ssh -p 20000 user@forwarding.example.com
```

### 3. Expose multiple services at once

Create a config file `tunnels.json`:

```json
{
  "tunnels": [
    {"type": "http", "local": "3000", "subdomain": "api"},
    {"type": "http", "local": "8080", "subdomain": "frontend"},
    {"type": "tcp", "local": "22", "remote_port": 20022}
  ]
}
```

Run:
```bash
my_proxy start tunnels.json --token mysecret
```

## Environment variables

Instead of repeating `--token` and `--server`, set environment variables:

```bash
export MY_PROXY_SERVER=proxy.example.com:9000
export MY_PROXY_TOKEN=shared-secret
export MY_PROXY_DASHBOARD=127.0.0.1:4040

# Now just:
my_proxy http 8080
my_proxy tcp 22
```

## Dashboard

By default, a dashboard is available at `http://127.0.0.1:4040`:

- **Status indicators**: connection state, uptime, reconnect count
- **Per-tunnel view**: type, public URL, local destination, bytes transferred, latency
- **Logs**: recent messages from the client
- **Auto-refresh**: updates every 2 seconds

Disable with `--no-dashboard` if you don't want it.

## Testing locally

To test the client against `proxy_server.py` on the same machine:

**Terminal 1: Start the server**
```bash
cd /path/to/proxy_server
python3 proxy_server.py config.json
```

**Terminal 2: Start a local backend**
```bash
# A simple HTTP echo server on port 8001
python3 -c "
import asyncio
async def echo(reader, writer):
    req = await reader.readline()
    writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello!')
    await writer.drain()
    writer.close()
async def main():
    server = await asyncio.start_server(echo, '127.0.0.1', 8001)
    async with server:
        await server.serve_forever()
asyncio.run(main())
"
```

**Terminal 3: Start the client**
```bash
python3 my_proxy http 8001 -u test --token test-secret-please-change
```

**Terminal 4: Test it**
```bash
# Note: using self-signed cert, so -k flag
curl -sk https://test.forwarding.local:18443/
# Should print: Hello!
```

## Troubleshooting

### `Connection refused` to server

```bash
$ my_proxy http 8080 --token secret
ERROR Authentication failed: invalid signature
```

Solution: Check that `--server` points to the right address and port, and that `--token` matches the server's `shared_secret`.

### `Local service unreachable`

```
WARNING Local service localhost:8080 unreachable for tunnel ...: Connect call failed
```

Solution: Make sure your backend is actually listening on the configured port.

```bash
netstat -ln | grep 8080
# or
lsof -i :8080
```

### Dashboard not showing up

The dashboard runs by default on `127.0.0.1:4040`. If it's not accessible:
- Check the port is free: `lsof -i :4040`
- Bind it elsewhere: `my_proxy http 8080 --dashboard 0.0.0.0:8888`
- Disable it if not needed: `my_proxy http 8080 --no-dashboard`

### Enable debug logging

```bash
my_proxy http 8080 --token secret --log-level DEBUG
```

This will print detailed frame-by-frame protocol messages, useful for diagnosing protocol issues.

## Common scenarios

### Expose a web app running on localhost:3000

```bash
my_proxy http localhost:3000 -u frontend --token mysecret
# Public URL: https://frontend.forwarding.example.com
```

### Expose SSH for remote access

```bash
my_proxy tcp 22 --remote-port 20022 --token mysecret
# Access: ssh -p 20022 user@forwarding.example.com
```

### Expose multiple services with stable subdomains

```bash
# Create config.json with specific subdomains
cat > config.json <<EOF
{
  "tunnels": [
    {"type": "http", "local": "3000", "subdomain": "api"},
    {"type": "http", "local": "8080", "subdomain": "web"}
  ]
}
EOF

# Run it
my_proxy start config.json --token mysecret
```

Subdomains are persistent across restarts — as long as no other client has claimed them.

### Run the client in the background

```bash
nohup my_proxy http 8080 --token mysecret > /tmp/my_proxy.log 2>&1 &
# Check status:
tail -f /tmp/my_proxy.log
```

Or use systemd (see deployment docs if available).

## Next steps

- Read [README.md](README.md) for full CLI reference and configuration options
- Read [PROTOCOL.md](PROTOCOL.md) to understand the wire protocol (useful for debugging or building alternative clients/servers)
- Check [config.example.json](config.example.json) for multi-tunnel setup examples
