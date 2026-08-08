#!/bin/sh
# Entrypoint for tunnel-proxy container.
# Runs as root to fix ownership of mounted volumes, then starts supervisord
# which drops privileges per-program to the `tunnelproxy` user.
#
# TLS termination and wildcard SSL are handled externally (cloud LB,
# Cloudflare, or your own reverse proxy), so this image serves plain
# HTTP on a single public port (80) and needs no certbot.

set -e

# Ensure all writable dirs exist and belong to tunnelproxy.
mkdir -p /data \
    /var/log/tunnel-proxy \
    /var/log/nginx \
    /var/log/supervisor \
    /run/nginx \
    /run/supervisord

chown -R tunnelproxy:tunnelproxy \
    /data \
    /var/log/tunnel-proxy \
    /var/log/nginx \
    /var/log/supervisor \
    /run/nginx \
    /run/supervisord \
    /var/lib/nginx

# Hand off to supervisord
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf