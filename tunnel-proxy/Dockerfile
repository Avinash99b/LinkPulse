# syntax=docker/dockerfile:1
#
# LinkPulse tunnel server image.
# proxy_server.py is stdlib-only and terminates HTTPS itself; there is no
# nginx / haproxy / supervisord in this image.
#
# Conventions enforced here:
#   * Interpreter pinned to CPython 3.11.13 on Debian bookworm. Both stages use
#     the SAME pinned base (tag + digest) so the copied /opt/venv keeps a valid
#     interpreter. Digest verified against Docker Hub for python:3.11.13-slim-bookworm.
#   * certbot and the DNS plugins are installed at BUILD time, pinned, into
#     /opt/venv. The container NEVER runs `pip install` at runtime, so a bad
#     network / bad index at start-up can no longer silently break TLS.
#   * certbot is always invoked by absolute path (/opt/venv/bin/certbot) from
#     entrypoint.sh and from the root cron wrapper.
#   * entrypoint.sh starts as root only to prepare volumes/certs/cron, then
#     drops to the unprivileged `tunnelproxy` user via setpriv.
#   * The exposed tunnel-port range is narrow and explicit (20000-20100). The
#     old 10000-65535 allocation created tens of thousands of DNAT rules and
#     thrashed small instances.

FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build-only toolchain (stays out of the runtime image). Wheels exist for every
# pinned package on bookworm/amd64, so this is only a safety net for sdists.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Pin the packaging toolchain instead of a floating `pip install --upgrade`.
# Versions verified to exist on PyPI for CPython 3.11.
RUN pip install \
        "pip==24.0" \
        "setuptools==70.0.0" \
        "wheel==0.43.0"

COPY requirements.txt .

# Server deps first (stdlib-only + optional psutil; pinned to psutil==6.1.1 in
# requirements.txt by the CI dependency owner -- this image installs that file
# verbatim so there is a single source of truth).
#
# Then the certbot toolchain. certbot 3.3.0 is the last 3.x release, supports
# CPython 3.11 and is installed with matching plugin versions (plugin versions
# track the certbot version and must stay in lockstep).
#
# PyOpenSSL is pinned <26 on purpose: certbot 3.3.0 requires josepy<2, and
# josepy 1.x still uses OpenSSL.crypto.X509Req, which PyOpenSSL 26 removed.
# Without this pin pip resolves PyOpenSSL 26.x and certbot crashes at runtime.
RUN pip install -r requirements.txt \
    && pip install \
        "certbot==3.3.0" \
        "certbot-dns-cloudflare==3.3.0" \
        "certbot-dns-digitalocean==3.3.0" \
        "certbot-dns-route53==3.3.0" \
        "PyOpenSSL==25.3.0"

# Build-time self-test: fail here (not at server start-up) if certbot or its
# plugins cannot import with the resolved dependency set.
RUN certbot --version && certbot plugins --text >/dev/null

# ---------------------------------------------------------------------------
FROM python:3.11.13-slim-bookworm@sha256:86adf8dbadc3d6e82ee5dd2c74bec2e1c2467cdad47886280501df722372d2e1 AS runtime

# Runtime packages:
#   bash        entrypoint / deploy hook / renewal wrapper
#   cron        automatic certificate renewal (Debian binary /usr/sbin/cron)
#   openssl     certificate inspection in entrypoint.sh
#   curl        bounded healthcheck probe
#   util-linux  setpriv (privilege drop) + mountpoint (mount detection)
#   ca-certificates, tzdata  TLS trust store + correct cron timestamps
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        cron \
        curl \
        openssl \
        util-linux \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system tunnelproxy \
    && useradd --system --gid tunnelproxy --home-dir /app --shell /usr/sbin/nologin tunnelproxy

# Writable locations and their intended ownership/mode:
#   /data                  tunnelproxy:tunnelproxy 0750  (database)
#   /data/letsencrypt      root:tunnelproxy        0750  (certbot writes as root, server reads via group)
#   /var/log/tunnel-proxy  tunnelproxy:tunnelproxy 0750  (logs; mount THIS, never the whole host /var/log)
#   /var/lib/letsencrypt   root:root               0700  (certbot work dir)
RUN install -d -o tunnelproxy -g tunnelproxy -m 0750 /data /var/log/tunnel-proxy \
    && install -d -o root -g tunnelproxy -m 0750 /data/letsencrypt \
    && install -d -o root -g root -m 0700 /var/lib/letsencrypt

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1

WORKDIR /app
COPY proxy_server.py protocol.py storage.py dashboard.py requirements.txt ./
COPY examples/ ./examples/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

# --- helper scripts -------------------------------------------------------
# Generated here so the image is self-contained and entrypoint.sh stays small.

RUN cat > /usr/local/bin/linkpulse-cert-perms <<'SCRIPT'
#!/bin/bash
# certbot deploy hook (runs as root): make renewed certificates readable by the
# `tunnelproxy` group WITHOUT world-readable private keys.
# certbot exports RENEWED_LINEAGE (= .../live/<domain>) to hooks.
#
# FAILS CLOSED: missing file, chgrp/chmod error, a world-readable private key, an
# unreadable file, or a target that resolves OUTSIDE the cert store all exit
# non-zero. Containment: the logical config dir is resolved (e.g.
# /etc/letsencrypt -> /data/letsencrypt) and every resolved cert/key MUST stay
# inside that store; ancestors are only made traversable down to that store,
# never up to '/'. A symlink pointing outside is refused, not chmod'd.
set -euo pipefail
lineage="${RENEWED_LINEAGE:-}"
if [ -z "$lineage" ]; then
    echo "linkpulse-cert-perms: RENEWED_LINEAGE is not set" >&2
    exit 1
fi
group="tunnelproxy"
[ -d "$lineage" ] || { echo "linkpulse-cert-perms: missing directory $lineage" >&2; exit 1; }

logical_config="$(dirname "$(dirname "$lineage")")"
config_real="$(readlink -f "$logical_config" 2>/dev/null || true)"
if [ -z "$config_real" ] || [ ! -d "$config_real" ]; then
    echo "linkpulse-cert-perms: cert store '$logical_config' is missing" >&2
    exit 1
fi
lineage_real="$(readlink -f "$lineage" 2>/dev/null || true)"
case "$lineage_real" in
    "$config_real"/*) ;;
    *) echo "linkpulse-cert-perms: lineage resolves outside $config_real ($lineage_real); refusing" >&2; exit 1 ;;
esac

# Make directories group-traversable, but only within the resolved cert store.
make_traversable() {
    local d
    d="$(dirname "$1")"
    while [ -n "$d" ] && [ "$d" != "/" ]; do
        case "$d" in
            "$config_real"|"$config_real"/*) ;;
            *) break ;;
        esac
        chgrp "$group" "$d"
        chmod 0750 "$d"
        [ "$d" = "$config_real" ] && break
        d="$(dirname "$d")"
    done
}

for f in "$lineage/fullchain.pem" "$lineage/privkey.pem"; do
    [ -e "$f" ] || { echo "linkpulse-cert-perms: missing $f" >&2; exit 1; }
    real="$(readlink -f "$f" 2>/dev/null || true)"
    case "$real" in
        "$config_real"/*) ;;
        *) echo "linkpulse-cert-perms: $f resolves outside $config_real ($real); refusing to change permissions" >&2; exit 1 ;;
    esac
    [ -f "$real" ] || { echo "linkpulse-cert-perms: missing target $real" >&2; exit 1; }
    chgrp "$group" "$real"
    chmod 0640 "$real"
    make_traversable "$real"
done

make_traversable "$lineage_real"
chgrp "$group" "$lineage_real"
chmod 0750 "$lineage_real"

# Normalise the rest of a certbot archive if present (also contained).
archive_candidate="$(dirname "$lineage_real")/../archive/$(basename "$lineage_real")"
if [ -d "$archive_candidate" ]; then
    archive_real="$(readlink -f "$archive_candidate" 2>/dev/null || true)"
    case "$archive_real" in
        "$config_real"/*) ;;
        *) echo "linkpulse-cert-perms: archive resolves outside $config_real ($archive_real); refusing" >&2; exit 1 ;;
    esac
    chgrp -R "$group" "$archive_real"
    find "$archive_real" -type d -exec chmod 0750 {} +
    find "$archive_real" -type f -name '*.pem' -exec chmod 0640 {} +
fi

# The resolved private key must never be world-readable.
perm="$(stat -L -c '%a' "$lineage/privkey.pem")"
case "$perm" in
    *[4-7]) echo "linkpulse-cert-perms: private key is world-readable ($perm): $lineage/privkey.pem" >&2; exit 1 ;;
esac

# Verify the runtime user can actually read the leaf certificate and key.
for f in "$lineage/fullchain.pem" "$lineage/privkey.pem"; do
    if ! setpriv --reuid="$group" --regid="$group" --init-groups -- test -r "$f"; then
        echo "linkpulse-cert-perms: user '$group' cannot read $f" >&2
        exit 1
    fi
done
exit 0
SCRIPT
RUN chmod 0755 /usr/local/bin/linkpulse-cert-perms

RUN cat > /usr/local/bin/linkpulse-certbot-renew <<'SCRIPT'
#!/bin/bash
# Root-only cron wrapper for `certbot renew`.
# Sources the root-only credential env file written by entrypoint.sh so
# route53-style providers get their AWS_* variables under cron (which starts
# with a minimal environment). Values are never echoed; `set -x` is never used.
set -euo pipefail
umask 077
env_file="/etc/letsencrypt/renewal.env"
if [ -r "$env_file" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
fi
# route53/boto3 needs a region even when using an instance role. Under cron there
# is no interactive fallback, so default it (global DNS service) instead of
# performing a network/IMDS lookup that could hang the renewal job.
: "${AWS_DEFAULT_REGION:=us-east-1}"
: "${AWS_REGION:=$AWS_DEFAULT_REGION}"
export AWS_DEFAULT_REGION AWS_REGION
exec /opt/venv/bin/certbot renew \
    --quiet \
    --config-dir /etc/letsencrypt \
    --work-dir /var/lib/letsencrypt \
    --logs-dir /var/log/tunnel-proxy/letsencrypt \
    --deploy-hook /usr/local/bin/linkpulse-cert-perms
SCRIPT
RUN chmod 0755 /usr/local/bin/linkpulse-certbot-renew

RUN cat > /usr/local/bin/linkpulse-healthcheck <<'SCRIPT'
#!/bin/sh
# Bounded health probe for the HTTP listener. Honors HTTP_PORT and
# HEALTHCHECK_HOST so a non-default HTTP port still reports healthy.
set -eu
host="${HEALTHCHECK_HOST:-127.0.0.1}"
port="${HTTP_PORT:-80}"
url="http://${host}:${port}/health"
if command -v curl >/dev/null 2>&1; then
    exec curl -fsS --max-time 5 --connect-timeout 3 "$url"
fi
exec python3 -c 'import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=5).read()' "$url"
SCRIPT
RUN chmod 0755 /usr/local/bin/linkpulse-healthcheck

# Default tunnel-port allocation. Keep in sync with:
#   * the EXPOSE lines below
#   * startup.sh DEFAULT_RANGE
#   * proxy_server.py DEFAULT_CONFIG (manager: align 10000-65535 -> 20000-20100)
ENV TCP_PORT_MIN=20000 \
    TCP_PORT_MAX=20100 \
    UDP_PORT_MIN=20000 \
    UDP_PORT_MAX=20100 \
    CONTROL_TLS=false

# Public listeners + the narrow tunnel range (TCP and UDP).
EXPOSE 80/tcp 443/tcp 9000/tcp
EXPOSE 20000-20100/tcp 20000-20100/udp

HEALTHCHECK --interval=30s --timeout=8s --start-period=25s --retries=3 \
    CMD ["/usr/local/bin/linkpulse-healthcheck"]

ENTRYPOINT ["/entrypoint.sh"]
