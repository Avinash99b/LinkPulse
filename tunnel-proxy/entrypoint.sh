#!/usr/bin/env bash
# LinkPulse tunnel server container entrypoint.
#
# Runs as root, but only for privileged initialisation:
#   1. validate configuration up front (ALL required values, via the server's
#      own validator, before any volume/certbot side effect)
#   2. prepare the persistent certificate store
#      (/etc/letsencrypt -> /data/letsencrypt, without destructive deletes)
#   3. issue/renew the wildcard certificate with the pinned /opt/venv/bin/certbot
#      (only when using the managed Let's Encrypt store)
#   4. install a root-only renewal credential file + /etc/cron.d job
#   5. start cron as a SEPARATE root daemon (it is not part of the python process)
#   6. drop privileges with setpriv and exec proxy_server.py as `tunnelproxy`
#
# It never runs `pip install` (certbot + DNS plugins are baked into the image)
# and it never prints secret values.
#
# Environment (all optional unless noted):
#   SHARED_SECRET        required
#   WILDCARD_DOMAIN      required
#   DASHBOARD_PASSWORD   required
#   JWT_SECRET           required (>=32 chars for production)
#   DNS_PROVIDER         cloudflare | digitalocean | route53   (default cloudflare)
#   CF_API_TOKEN / DO_API_TOKEN / AWS_*   provider credentials
#   CERTBOT_EMAIL        defaults to admin@$WILDCARD_DOMAIN
#   HTTP_ONLY            true -> skip certbot, serve plain HTTP
#   EXTERNAL_SSL         true -> skip certbot, TLS is terminated upstream
#   ALLOW_HTTP_FALLBACK  true -> start even if TLS is unavailable
#   CONTROL_TLS          true -> control channel TLS (defaults to the public cert)
#   CERT_PATH / KEY_PATH external TLS material (not managed/provisioned here)
#
# NOTE: when CERT_PATH/KEY_PATH are provided they are treated as user-owned
# external files. The container does NOT chgrp/chmod them and does NOT run
# certbot; it only verifies the runtime user can read them.

set -euo pipefail

APP_DIR=/app
VENV=/opt/venv
CERTBOT_BIN="$VENV/bin/certbot"
PYTHON_BIN="$VENV/bin/python"
SERVER_USER=tunnelproxy
SERVER_GROUP=tunnelproxy
LE_DIR=/etc/letsencrypt
DATA_LE_DIR=/data/letsencrypt
LOG_DIR=/var/log/tunnel-proxy
PERMS_HOOK=/usr/local/bin/linkpulse-cert-perms
RENEW_WRAPPER=/usr/local/bin/linkpulse-certbot-renew
RENEW_ENV=/etc/letsencrypt/renewal.env

log()  { printf '[entrypoint] %s\n' "$*" >&2; }
warn() { printf '[entrypoint] WARNING: %s\n' "$*" >&2; }
die()  { printf '[entrypoint] ERROR: %s\n' "$*" >&2; exit 1; }

is_true() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

# A value is a placeholder if it is empty or still looks like the shipped
# examples. Used to refuse starting with default/example secrets.
is_placeholder() {
    case "${1:-}" in
        ""|*your-*|*YOUR-*|*replace-with*|*REPLACE-WITH*|*placehold*|*PLACEHOLD*|*change_me*|*CHANGE_ME*|*changeme*|*example.com*)
            return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------- secrets ---
SHARED_SECRET="${SHARED_SECRET:-}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
DNS_PROVIDER="${DNS_PROVIDER:-cloudflare}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
HTTP_ONLY="${HTTP_ONLY:-false}"
EXTERNAL_SSL="${EXTERNAL_SSL:-false}"
ALLOW_HTTP_FALLBACK="${ALLOW_HTTP_FALLBACK:-false}"
CONTROL_TLS="${CONTROL_TLS:-false}"

# ------------------------------------------------------- validate NOW ---
# Nothing below this point (chown, certbot, cron) may run with invalid config.
# Shell-side domain preflight first (fast, catches whitespace/quotes/scheme);
# then the server's own load_config()+validate_config() is authoritative.

if [ -z "$WILDCARD_DOMAIN" ]; then
    die "WILDCARD_DOMAIN is required (e.g. tunnel.example.com)"
fi
_dns_label='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
if [ "${#WILDCARD_DOMAIN}" -gt 253 ] || ! [[ "$WILDCARD_DOMAIN" =~ ^($_dns_label\.)+[A-Za-z]{2,63}$ ]]; then
    die "WILDCARD_DOMAIN '$WILDCARD_DOMAIN' is not a valid DNS name (labels of a-z/0-9/-, separated by dots; no scheme, slash, space, tab or quote)"
fi

preflight_rc=0
"$PYTHON_BIN" - <<'PY' || preflight_rc=$?
import sys
sys.path.insert(0, "/app")
try:
    import proxy_server as srv
    cfg = srv.load_config()
    srv.validate_config(cfg)
    if len(str(cfg.get("jwt_secret") or "")) < 32:
        raise RuntimeError("JWT_SECRET must be at least 32 characters long for production use.")
except Exception as exc:
    print(f"configuration error: {exc}", file=sys.stderr)
    sys.exit(1)
PY
[ "$preflight_rc" -eq 0 ] || die "configuration rejected (see above); not starting, and no certbot/DNS side effects were attempted"

# ------------------------------------------------------- TLS selection ---
# The server reads CERT_PATH/KEY_PATH itself. Mirror that decision here so the
# low-port probe and the readiness check use the SAME files the server will use.
EXTERNAL_CERT="${CERT_PATH:-}"
EXTERNAL_KEY="${KEY_PATH:-}"
TLS_MANAGED=true
if [ -n "$EXTERNAL_CERT" ] || [ -n "$EXTERNAL_KEY" ]; then
    TLS_MANAGED=false
    if [ -z "$EXTERNAL_CERT" ] || [ -z "$EXTERNAL_KEY" ]; then
        die "CERT_PATH and KEY_PATH must be set together"
    fi
    CERT_FILE="$EXTERNAL_CERT"
    KEY_FILE="$EXTERNAL_KEY"
else
    CERT_FILE="$LE_DIR/live/$WILDCARD_DOMAIN/fullchain.pem"
    KEY_FILE="$LE_DIR/live/$WILDCARD_DOMAIN/privkey.pem"
fi

WANT_TLS=true
if is_true "$HTTP_ONLY"; then
    WANT_TLS=false
fi

PROVISION=false
if [ "$WANT_TLS" = true ] && [ "$TLS_MANAGED" = true ] && ! is_true "$EXTERNAL_SSL"; then
    PROVISION=true
fi

if is_true "$HTTP_ONLY"; then
    log "HTTP_ONLY=true -> certificate provisioning skipped (plain HTTP)"
elif is_true "$EXTERNAL_SSL"; then
    log "EXTERNAL_SSL=true -> certificate provisioning skipped (TLS terminated upstream)"
elif [ "$TLS_MANAGED" = false ]; then
    log "CERT_PATH/KEY_PATH provided -> using external TLS material (not provisioned)"
fi

# ------------------------------------------------------------ directories ---
install -d -o "$SERVER_USER" -g "$SERVER_GROUP" -m 0750 /data "$LOG_DIR"
install -d -o root -g "$SERVER_GROUP" -m 0750 "$DATA_LE_DIR"
install -d -o root -g root -m 0700 /var/lib/letsencrypt

# Ensure runtime user can write to existing application logs and databases
# if they were created by root or under a different UID in an earlier run.
if [ -d "$LOG_DIR" ]; then
    chown "$SERVER_USER:$SERVER_GROUP" "$LOG_DIR" 2>/dev/null || true
    find "$LOG_DIR" -maxdepth 1 -type f -exec chown "$SERVER_USER:$SERVER_GROUP" {} + 2>/dev/null || true
    find "$LOG_DIR" -maxdepth 1 -type f -exec chmod u+rw {} + 2>/dev/null || true
fi
if [ -d /data ]; then
    chown "$SERVER_USER:$SERVER_GROUP" /data 2>/dev/null || true
    find /data -maxdepth 1 -name 'tunnel_proxy.db*' -exec chown "$SERVER_USER:$SERVER_GROUP" {} + 2>/dev/null || true
    find /data -maxdepth 1 -name 'tunnel_proxy.db*' -exec chmod u+rw {} + 2>/dev/null || true
fi

# --------------------------------------------------- cert store relocation ---
# Keep the certbot store on the persistent volume. This function never deletes
# data: a pre-existing image directory is migrated (and moved aside, not
# removed) and a real mount point is refused rather than wiped.
ensure_cert_store() {
    if [ -L "$LE_DIR" ]; then
        local target
        target="$(readlink -f "$LE_DIR" 2>/dev/null || true)"
        if [ "$target" = "$DATA_LE_DIR" ]; then
            log "cert store: $LE_DIR -> $DATA_LE_DIR (existing symlink)"
        else
            warn "$LE_DIR is a symlink to '${target:-?}' (expected $DATA_LE_DIR); leaving it untouched"
        fi
        return 0
    fi

    if [ -d "$LE_DIR" ]; then
        if mountpoint -q "$LE_DIR" 2>/dev/null; then
            warn "$LE_DIR is a real mount point; refusing to replace it -- certificates will live there"
            return 0
        fi
        if [ -n "$(ls -A "$LE_DIR" 2>/dev/null || true)" ]; then
            cp -a "$LE_DIR/." "$DATA_LE_DIR/" 2>/dev/null || warn "could not copy existing $LE_DIR contents"
            local keep="${LE_DIR}.pre-migrate.$(date +%s)"
            mv "$LE_DIR" "$keep"
            warn "migrated $LE_DIR into $DATA_LE_DIR (previous directory kept at $keep)"
        else
            rmdir "$LE_DIR"
        fi
    fi

    ln -s "$DATA_LE_DIR" "$LE_DIR"
    log "cert store: $LE_DIR -> $DATA_LE_DIR (symlink created)"
}
ensure_cert_store

# ------------------------------------------------ external TLS material ---
# Only when the user supplied CERT_PATH/KEY_PATH (or a control cert). We verify
# readability as the runtime user but never change ownership/mode of files we
# do not manage.
require_readable() { # require_readable <path> <label>
    local p=$1 label=$2
    [ -e "$p" ] || die "$label is set but '$p' does not exist"
    if ! setpriv --reuid="$SERVER_USER" --regid="$SERVER_GROUP" --init-groups -- test -r "$p"; then
        die "$label '$p' is not readable by the '$SERVER_USER' user.
  External TLS material is not modified by this container; make it readable to
  the '$SERVER_GROUP' group (e.g. chgrp $SERVER_GROUP && chmod 0640) and restart."
    fi
}

if [ "$WANT_TLS" = true ] && [ "$TLS_MANAGED" = false ]; then
    require_readable "$CERT_FILE" "CERT_PATH"
    require_readable "$KEY_FILE" "KEY_PATH"
    log "external TLS material is readable: $CERT_FILE"
fi

# --------------------------------------------------------------- certbot ---
write_root_only() { # write_root_only <path>   (content on stdin)
    local path=$1
    umask 077
    cat > "$path"
    chmod 0600 "$path"
    chown root:root "$path"
}

# Credentials are captured on EVERY start, independent of whether a new
# certificate is issued, so a rotated token / changed AWS region is picked up by
# the renewal cron immediately. route53 values are written with bash %q quoting
# (never evaluated as shell code) into a root-only file; secrets are never
# logged. When no AWS_* variables are present the file is CLEARED so stale
# static credentials cannot mask an instance/task IAM role.
capture_credentials() {
    case "$DNS_PROVIDER" in
        cloudflare)
            if is_placeholder "${CF_API_TOKEN:-}"; then
                warn "CF_API_TOKEN is unset or a placeholder"
                return 1
            fi
            printf 'dns_cloudflare_api_token = %s\n' "$CF_API_TOKEN" | write_root_only "$LE_DIR/cloudflare.ini"
            ;;
        digitalocean)
            if is_placeholder "${DO_API_TOKEN:-}"; then
                warn "DO_API_TOKEN is unset or a placeholder"
                return 1
            fi
            printf 'dns_digitalocean_token = %s\n' "$DO_API_TOKEN" | write_root_only "$LE_DIR/digitalocean.ini"
            ;;
        route53)
            local lines=() k v line
            for k in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION AWS_REGION; do
                v="${!k:-}"
                [ -n "$v" ] || continue
                printf -v line '%s=%q' "$k" "$v"
                lines+=("$line")
            done
            if [ "${#lines[@]}" -gt 0 ]; then
                printf '%s\n' "${lines[@]}" | write_root_only "$RENEW_ENV"
                set -a
                # shellcheck disable=SC1090
                . "$RENEW_ENV"
                set +a
            else
                : | write_root_only "$RENEW_ENV"
                log "no AWS_* variables set; cleared renewal.env and assuming an instance/task IAM role for route53"
            fi
            ;;
    esac
    return 0
}

run_certbot() {
    local plugin="" creds=""
    local args=(
        certonly
        --non-interactive
        --agree-tos
        --email "$CERTBOT_EMAIL"
        --cert-name "$WILDCARD_DOMAIN"
        --preferred-challenges dns
        --config-dir "$LE_DIR"
        --work-dir /var/lib/letsencrypt
        --logs-dir "$LOG_DIR/letsencrypt"
        -d "*.$WILDCARD_DOMAIN"
        -d "$WILDCARD_DOMAIN"
    )

    case "$DNS_PROVIDER" in
        cloudflare)    plugin=dns-cloudflare;    creds="$LE_DIR/cloudflare.ini" ;;
        digitalocean)  plugin=dns-digitalocean;  creds="$LE_DIR/digitalocean.ini" ;;
        route53)       plugin=dns-route53 ;;
    esac

    case "$plugin" in
        dns-cloudflare|dns-digitalocean)
            [ -s "$creds" ] || { warn "credentials file $creds is missing or empty"; return 1; }
            args+=(--"$plugin" --"$plugin"-credentials "$creds")
            ;;
        dns-route53)
            args+=(--dns-route53)
            ;;
    esac

    log "requesting certificate for $WILDCARD_DOMAIN and *.$WILDCARD_DOMAIN (plugin: $plugin)"
    "$CERTBOT_BIN" "${args[@]}"
}

if [ "$PROVISION" = true ]; then
    case "$DNS_PROVIDER" in
        cloudflare|digitalocean|route53) ;;
        *) die "DNS_PROVIDER '$DNS_PROVIDER' is not supported (use cloudflare, digitalocean or route53)" ;;
    esac
    [ -n "$CERTBOT_EMAIL" ] || CERTBOT_EMAIL="admin@$WILDCARD_DOMAIN"

    creds_ok=1
    capture_credentials || creds_ok=0

    need_issue=1
    if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
        if openssl x509 -checkend 2592000 -noout -in "$CERT_FILE" >/dev/null 2>&1; then
            log "existing certificate is valid for more than 30 days; skipping issuance"
            need_issue=0
        else
            log "existing certificate expires within 30 days; attempting renewal"
        fi
    fi

    if [ "$need_issue" = 1 ]; then
        if [ "$creds_ok" = 0 ]; then
            if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
                warn "DNS credentials are unavailable; keeping the existing certificate"
            elif is_true "$ALLOW_HTTP_FALLBACK"; then
                warn "DNS credentials are unavailable and ALLOW_HTTP_FALLBACK=true -> starting without TLS"
            else
                die "DNS credentials are unavailable and no certificate exists.
  Set the provider credentials (CF_API_TOKEN / DO_API_TOKEN / AWS_*),
  or start in HTTP-only mode with HTTP_ONLY=true,
  or set ALLOW_HTTP_FALLBACK=true to accept missing TLS."
            fi
        elif run_certbot; then
            log "certificate issued/renewed successfully"
        elif [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
            warn "certificate renewal failed; continuing with the existing certificate"
        elif is_true "$ALLOW_HTTP_FALLBACK"; then
            warn "certificate issuance failed and ALLOW_HTTP_FALLBACK=true -> starting without TLS"
        else
            die "certificate issuance failed and no usable certificate exists.
  Fix DNS/credentials, or start in HTTP-only mode with HTTP_ONLY=true,
  or set ALLOW_HTTP_FALLBACK=true to accept missing TLS."
        fi
    fi

    # Enforce group-readable (never world-readable) certificate permissions.
    # TLS is in use here (managed, not HTTP_ONLY/EXTERNAL_SSL), so a hook failure
    # is fatal: never start with unreadable or over-exposed TLS material.
    if [ -s "$CERT_FILE" ]; then
        if ! RENEWED_LINEAGE="$LE_DIR/live/$WILDCARD_DOMAIN" "$PERMS_HOOK"; then
            die "certificate permission hook failed; refusing to start with inaccessible or over-exposed TLS material"
        fi
        not_after="$(openssl x509 -noout -enddate -in "$CERT_FILE" 2>/dev/null | cut -d= -f2- || true)"
        log "certificate ready: $CERT_FILE (not after: ${not_after:-unknown})"
    fi

    # Daily renewal job: exact venv certbot path via the root-only wrapper.
    install -m 0644 -o root -g root /dev/stdin /etc/cron.d/linkpulse-certbot-renew <<CRON
SHELL=/bin/bash
PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 3 * * * root $RENEW_WRAPPER >> $LOG_DIR/certbot-renew.log 2>&1
CRON
    rm -f /etc/cron.d/certbot-renew
    log "configured daily certificate renewal (03:17) via $CERTBOT_BIN"
fi

# ------------------------------------------------------------------ cron ---
# cron is a separate root daemon, started BEFORE we drop privileges.
if [ -x /usr/sbin/cron ]; then
    /usr/sbin/cron
    if command -v pgrep >/dev/null 2>&1 && pgrep -x cron >/dev/null 2>&1; then
        log "cron started (separate root daemon) for certificate renewal"
    else
        log "cron launched (separate root daemon)"
    fi
else
    warn "/usr/sbin/cron not found; automatic certificate renewal is disabled"
fi

# ------------------------------------------------------ low-port binding ---
# NEVER write /proc/sys/net/ipv4/ip_unprivileged_port_start: with --network host
# the container shares the HOST network namespace, so doing so would change a
# host-wide sysctl. In bridge mode Docker already sets it to 0 (startup.sh also
# passes --sysctl). If the non-root user still cannot bind a needed port we grant
# ONLY CAP_NET_BIND_SERVICE as an ambient capability via setpriv, and only when
# the container actually has that capability.
SERVER_CAPS=()

# Probe only the listeners the server will actually open.
need_ports=""
for port in "${HTTP_PORT:-80}" "${CONTROL_PORT:-9000}"; do
    case "$port" in ''|*[!0-9]*) continue ;; esac
    [ "$((10#$port))" -lt 1024 ] && need_ports="$need_ports $port"
done
# HTTPS is only bound when TLS is active (the same files the server uses).
if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ] && ! is_true "$HTTP_ONLY"; then
    https_port="${HTTPS_PORT:-443}"
    case "$https_port" in ''|*[!0-9]*) ;; *) [ "$((10#$https_port))" -lt 1024 ] && need_ports="$need_ports $https_port" ;; esac
fi

probe_port() { # probe_port <port>
    setpriv "${SERVER_CAPS[@]}" --reuid="$SERVER_USER" --regid="$SERVER_GROUP" --init-groups -- \
        "$PYTHON_BIN" -c 'import socket,sys; s=socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.close()' "$1"
}

if [ -n "$need_ports" ]; then
    caps_ok=1
    for port in $need_ports; do
        probe_port "$port" 2>/dev/null || { caps_ok=0; break; }
    done
    if [ "$caps_ok" = 0 ]; then
        server_caps_mask="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)"
        # CAP_NET_BIND_SERVICE is bit 10 -> 0x400.
        if [ -z "$server_caps_mask" ] || [ "$(( 0x${server_caps_mask} & 0x400 ))" -eq 0 ]; then
            die "the unprivileged user '$SERVER_USER' cannot bind port(s):$need_ports and the container lacks CAP_NET_BIND_SERVICE.
  Bridge networking already allows unprivileged low ports; for --network host add
      --cap-add NET_BIND_SERVICE
  or use ports >= 1024 (HTTP_PORT/HTTPS_PORT/CONTROL_PORT) behind an upstream proxy."
        fi
        SERVER_CAPS=(--inh-caps=+net_bind_service --ambient-caps=+net_bind_service)
        caps_ok=1
        for port in $need_ports; do
            probe_port "$port" 2>/dev/null || { caps_ok=0; break; }
        done
        if [ "$caps_ok" = 0 ]; then
            die "the unprivileged user '$SERVER_USER' still cannot bind port(s):$need_ports after granting CAP_NET_BIND_SERVICE.
  Use ports >= 1024, or terminate the low ports outside the container."
        fi
    fi
    log "non-root low-port binding OK for:$need_ports${SERVER_CAPS:+ (CAP_NET_BIND_SERVICE ambient)}"
fi

# ------------------------------------------------------------- control TLS ---
if is_true "$CONTROL_TLS"; then
    CONTROL_CERT_PATH="${CONTROL_CERT_PATH:-$CERT_FILE}"
    CONTROL_KEY_PATH="${CONTROL_KEY_PATH:-$KEY_FILE}"
    require_readable "$CONTROL_CERT_PATH" "CONTROL_CERT_PATH"
    require_readable "$CONTROL_KEY_PATH" "CONTROL_KEY_PATH"
    export CONTROL_CERT_PATH CONTROL_KEY_PATH
    log "control-channel TLS enabled (cert: $CONTROL_CERT_PATH)"
fi

# ---------------------------------------------------------------- startup ---
log "starting proxy_server.py as '$SERVER_USER' (HTTP_ONLY=$HTTP_ONLY, EXTERNAL_SSL=$EXTERNAL_SSL)"
exec setpriv "${SERVER_CAPS[@]}" --reuid="$SERVER_USER" --regid="$SERVER_GROUP" --init-groups -- \
    "$PYTHON_BIN" "$APP_DIR/proxy_server.py"