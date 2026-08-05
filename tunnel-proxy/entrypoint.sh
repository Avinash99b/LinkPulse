#!/bin/sh
# Entrypoint for tunnel-proxy container.
# Runs as root so we can fix up ownership of mounted volumes (Render
# persistent disks mount as root), then hands off to supervisord which
# drops privileges per-program to the unprivileged `tunnelproxy` user.

set -e

# Ensure all writable dirs exist and belong to tunnelproxy.
# This is what makes /data (Render disk) usable after it is mounted.
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

# Hand off to supervisord (pidfile now lands in /run/supervisord/)
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
