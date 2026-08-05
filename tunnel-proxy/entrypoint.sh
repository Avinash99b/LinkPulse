#!/bin/sh
# Entrypoint script for nginx container
# HTTP only - Render handles HTTPS termination

set -e

# Determine upstream host (default to tunnel-proxy for docker-compose, localhost for standalone)
UPSTREAM_HOST="${NGINX_UPSTREAM_HOST:-tunnel-proxy}"
UPSTREAM_PORT="${NGINX_UPSTREAM_PORT:-8080}"

# Substitute environment variables in nginx config
sed -e "s|server tunnel-proxy:8080;|server ${UPSTREAM_HOST}:${UPSTREAM_PORT};|g" \
    /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Start nginx
exec nginx -g "daemon off;"