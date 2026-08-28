#!/bin/sh
# Entrypoint for tunnel-proxy container (direct server, no nginx/haproxy).
# Runs as root to:
#   - fix ownership of mounted volumes
#   - provision/renew wildcard SSL certificates via certbot (DNS challenge)
#   - start cron for automatic renewal
#   - run proxy_server.py directly (binds 80/443/9000/tunnel ports itself)

set -e

WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@${WILDCARD_DOMAIN}}"
DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"
CF_API_TOKEN="${CF_API_TOKEN:-}"

# Ensure all writable dirs exist and belong to tunnelproxy.
mkdir -p /data \
    /var/log/tunnel-proxy \
    /etc/letsencrypt \
    /var/lib/letsencrypt \
    /var/www/letsencrypt

chown -R tunnelproxy:tunnelproxy \
    /data \
    /var/log/tunnel-proxy \
    /var/lib/letsencrypt \
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

    # Create Cloudflare credentials file from CF_API_TOKEN
    if [ "$DNS_PROVIDER" = "cloudflare" ] && [ -n "$CF_API_TOKEN" ]; then
        cat > /etc/letsencrypt/cloudflare.ini <<EOF
dns_cloudflare_api_token = $CF_API_TOKEN
EOF
        chmod 600 /etc/letsencrypt/cloudflare.ini
        echo "Created Cloudflare credentials at /etc/letsencrypt/cloudflare.ini"
    fi

    # Install certbot DNS plugin if needed
    case "$CERTBOT_PLUGIN" in
        dns-cloudflare|dns-digitalocean|dns-route53)
            pip install --quiet "certbot-$CERTBOT_PLUGIN" 2>/dev/null || true
            ;;
    esac

    # Check if cert exists and is valid (>30 days)
    CERT_PATH="/etc/letsencrypt/live/$WILDCARD_DOMAIN/fullchain.pem"
    NEED_RENEWAL=false
    if [ -f "$CERT_PATH" ]; then
        # Ensure existing certs are readable by tunnelproxy
        chmod 755 /etc/letsencrypt 2>/dev/null || true
        chmod 755 /etc/letsencrypt/archive 2>/dev/null || true
        chmod 755 /etc/letsencrypt/live 2>/dev/null || true
        chmod -R 755 /etc/letsencrypt/live/$WILDCARD_DOMAIN 2>/dev/null || true
        chmod -R 755 /etc/letsencrypt/archive/$WILDCARD_DOMAIN 2>/dev/null || true

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
        echo "Requesting/renewing certificate for *.$WILDCARD_DOMAIN and $WILDCARD_DOMAIN..."

        CERTBOT_ARGS="certonly --non-interactive --agree-tos --email $CERTBOT_EMAIL \
            --preferred-challenges dns \
            -d *.$WILDCARD_DOMAIN \
            -d $WILDCARD_DOMAIN"

        if [ "$CERTBOT_PLUGIN" != "manual" ] && [ -n "$CREDENTIALS_FILE" ] && [ -f "$CREDENTIALS_FILE" ]; then
            CERTBOT_ARGS="$CERTBOT_ARGS --$CERTBOT_PLUGIN --$CERTBOT_PLUGIN-credentials $CREDENTIALS_FILE"
        elif [ "$CERTBOT_PLUGIN" = "dns-route53" ]; then
            CERTBOT_ARGS="$CERTBOT_ARGS --dns-route53"
        else
            echo "WARNING: No valid DNS plugin/credentials. Falling back to manual (will fail without hooks)."
            CERTBOT_ARGS="$CERTBOT_ARGS --manual --manual-auth-hook /usr/local/bin/dns-auth-hook.sh --manual-cleanup-hook /usr/local/bin/dns-cleanup-hook.sh"
        fi

        certbot $CERTBOT_ARGS 2>&1 | tee /var/log/certbot-init.log || {
            echo "WARNING: Certificate provisioning failed. Check DNS credentials and logs."
            echo "proxy_server.py will fall back to HTTP-only mode."
        }

        # Make Let's Encrypt certs readable by tunnelproxy user
        if [ -d "/etc/letsencrypt/live/$WILDCARD_DOMAIN" ]; then
            chmod -R 755 /etc/letsencrypt/live/$WILDCARD_DOMAIN 2>/dev/null || true
            chmod -R 755 /etc/letsencrypt/archive/$WILDCARD_DOMAIN 2>/dev/null || true
            chmod 755 /etc/letsencrypt 2>/dev/null || true
            chmod 755 /etc/letsencrypt/archive 2>/dev/null || true
            chmod 755 /etc/letsencrypt/live 2>/dev/null || true
            echo "Made Let's Encrypt certs readable for tunnelproxy user"
        fi
    fi

    # Set up auto-renewal cron (runs daily at 03:17)
    cat > /etc/cron.d/certbot-renew <<EOF
# Auto-renew Let's Encrypt certificates daily at 03:17
17 3 * * * root certbot renew --quiet >> /var/log/certbot-renew.log 2>&1
EOF
    chmod 644 /etc/cron.d/certbot-renew
fi

# Start cron daemon (for certbot auto-renewal) in the background
crond 2>/dev/null || true

echo "=== Starting tunnel-proxy server (WILDCARD_DOMAIN=$WILDCARD_DOMAIN) ==="

# Run the server directly. It binds 80 (HTTP), 443 (HTTPS w/ certbot certs),
# 9000 (control channel) and allocates TCP/UDP tunnel ports from its range.
exec python3 /app/proxy_server.py