#!/bin/sh
# Entrypoint for tunnel-proxy container.
# Runs as root to:
#   - fix ownership of mounted volumes (Render persistent disks mount as root)
#   - provision/renew wildcard SSL certificates via certbot (DNS challenge)
#   - start supervisord which drops privileges per-program to `tunnelproxy` user.

set -e

WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@${WILDCARD_DOMAIN}}"
DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"  # cloudflare, route53, digitalocean, etc.

# Ensure all writable dirs exist and belong to tunnelproxy.
mkdir -p /data \
    /var/log/tunnel-proxy \
    /var/log/nginx \
    /var/log/supervisor \
    /run/nginx \
    /run/supervisord \
    /etc/letsencrypt \
    /var/lib/letsencrypt \
    /var/www/letsencrypt

chown -R tunnelproxy:tunnelproxy \
    /data \
    /var/log/tunnel-proxy \
    /var/log/nginx \
    /var/log/supervisor \
    /run/nginx \
    /run/supervisord \
    /var/lib/nginx \
    /var/www/letsencrypt

# SSL certificate provisioning (if WILDCARD_DOMAIN is set and not using external SSL)
if [ -n "$WILDCARD_DOMAIN" ] && [ "${EXTERNAL_SSL:-false}" != "true" ]; then
    echo "=== Provisioning wildcard SSL for *.$WILDCARD_DOMAIN ==="

    # Determine certbot DNS plugin
    case "$DNS_PROVIDER" in
        cloudflare)
            CERTBOT_PLUGIN="dns-cloudflare"
            CREDENTIALS_FILE="/etc/letsencrypt/cloudflare.ini"
            ;;
        route53)
            CERTBOT_PLUGIN="dns-route53"
            CREDENTIALS_FILE=""
            ;;
        digitalocean)
            CERTBOT_PLUGIN="dns-digitalocean"
            CREDENTIALS_FILE="/etc/letsencrypt/digitalocean.ini"
            ;;
        *)
            CERTBOT_PLUGIN="manual"
            CREDENTIALS_FILE=""
            ;;
    esac

    # Install certbot DNS plugin if needed
    if [ "$CERTBOT_PLUGIN" != "manual" ]; then
        pip install --quiet "certbot-$CERTBOT_PLUGIN" 2>/dev/null || true
    fi

    # Check if cert exists and is valid (>30 days)
    CERT_PATH="/etc/letsencrypt/live/$WILDCARD_DOMAIN/fullchain.pem"
    NEED_RENEWAL=false
    if [ -f "$CERT_PATH" ]; then
        if ! openssl x509 -checkend 2592000 -noout -in "$CERT_PATH" >/dev/null 2>&1; then
            echo "Certificate expires within 30 days, renewing..."
            NEED_RENEWAL=true
        else
            echo "Valid certificate found, skipping initial provision."
        fi
    else
        NEED_RENEWAL=true
    fi

    if [ "$NEED_RENEWAL" = "true" ]; then
        echo "Requesting/renewing certificate for *.$WILDCARD_DOMAIN..."

        CERTBOT_ARGS="certonly --non-interactive --agree-tos --email $CERTBOT_EMAIL \
            --preferred-challenges dns \
            -d *.$WILDCARD_DOMAIN \
            -d $WILDCARD_DOMAIN"

        if [ "$CERTBOT_PLUGIN" != "manual" ] && [ -n "$CREDENTIALS_FILE" ] && [ -f "$CREDENTIALS_FILE" ]; then
            CERTBOT_ARGS="$CERTBOT_ARGS --$CERTBOT_PLUGIN --$CERTBOT_PLUGIN-credentials $CREDENTIALS_FILE"
        elif [ "$CERTBOT_PLUGIN" = "dns-route53" ]; then
            # Route53 uses AWS credentials from env/instance profile
            CERTBOT_ARGS="$CERTBOT_ARGS --dns-route53"
        else
            # Manual DNS challenge - requires hook scripts or manual intervention
            CERTBOT_ARGS="$CERTBOT_ARGS --manual --manual-auth-hook /usr/local/bin/dns-auth-hook.sh --manual-cleanup-hook /usr/local/bin/dns-cleanup-hook.sh"
        fi

        certbot $CERTBOT_ARGS 2>&1 | tee /var/log/certbot-init.log || {
            echo "WARNING: Certificate provisioning failed. Check DNS credentials and logs."
            echo "Continuing without SSL - external termination (Render/Cloudflare) expected."
        }
    fi

    # Set up auto-renewal cron (runs daily at 03:17)
    cat > /etc/cron.d/certbot-renew <<'EOF'
# Auto-renew Let's Encrypt certificates daily at 03:17
17 3 * * * root certbot renew --quiet --post-hook "nginx -s reload" >> /var/log/certbot-renew.log 2>&1
EOF
    chmod 644 /etc/cron.d/certbot-renew
    cron
fi

# Generate nginx SSL config - always generate at least self-signed so nginx can start
# If we have Let's Encrypt certs, use those; otherwise self-signed.
if [ -f "/etc/letsencrypt/live/$WILDCARD_DOMAIN/fullchain.pem" ]; then
    cat > /etc/nginx/ssl.conf <<EOF
# Auto-generated SSL config for $WILDCARD_DOMAIN (Let's Encrypt)
ssl_certificate /etc/letsencrypt/live/$WILDCARD_DOMAIN/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$WILDCARD_DOMAIN/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
EOF
    echo "SSL config generated at /etc/nginx/ssl.conf (Let's Encrypt)"
elif [ -n "$WILDCARD_DOMAIN" ]; then
    # Generate self-signed cert as fallback so nginx can start
    echo "Generating self-signed certificate for $WILDCARD_DOMAIN..."
    mkdir -p /etc/ssl/selfsigned
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/ssl/selfsigned/privkey.pem \
        -out /etc/ssl/selfsigned/fullchain.pem \
        -subj "/CN=*.$WILDCARD_DOMAIN" \
        -addext "subjectAltName=DNS:*.$WILDCARD_DOMAIN,DNS:$WILDCARD_DOMAIN" \
        2>/dev/null
    chown -R tunnelproxy:tunnelproxy /etc/ssl/selfsigned
    cat > /etc/nginx/ssl.conf <<EOF
# Self-signed SSL config for $WILDCARD_DOMAIN
ssl_certificate /etc/ssl/selfsigned/fullchain.pem;
ssl_certificate_key /etc/ssl/selfsigned/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
EOF
    echo "Self-signed SSL config generated at /etc/nginx/ssl.conf"
else
    # No domain set - generate minimal dummy ssl.conf so nginx doesn't fail
    cat > /etc/nginx/ssl.conf <<'EOF'
# Dummy SSL config - no WILDCARD_DOMAIN set
ssl_certificate /etc/ssl/selfsigned/fullchain.pem;
ssl_certificate_key /etc/ssl/selfsigned/privkey.pem;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
EOF
    # Also generate a dummy self-signed cert for the dummy config
    mkdir -p /etc/ssl/selfsigned
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/ssl/selfsigned/privkey.pem \
        -out /etc/ssl/selfsigned/fullchain.pem \
        -subj "/CN=localhost" \
        2>/dev/null
    chown -R tunnelproxy:tunnelproxy /etc/ssl/selfsigned
    echo "Dummy SSL config generated at /etc/nginx/ssl.conf"
fi

# Hand off to supervisord (pidfile now lands in /run/supervisord/)
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf