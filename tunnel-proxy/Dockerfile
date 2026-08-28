# Dockerfile for tunnel-proxy - direct server, no nginx/haproxy/supervisord.
# The Python server terminates HTTPS itself and allocates tunnel ports directly.

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Final runtime image
FROM python:3.11-slim AS runtime

# Runtime deps: certbot (SSL issuance/renewal), cron (auto-renew), curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    certbot \
    cron \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN groupadd -r tunnelproxy && useradd -r -g tunnelproxy -d /app -s /bin/bash tunnelproxy

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY proxy_server.py .
COPY protocol.py .
COPY storage.py .
COPY dashboard.py .
COPY requirements.txt .
COPY examples/ ./examples/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /data /var/log/tunnel-proxy /etc/letsencrypt /var/lib/letsencrypt /var/www/letsencrypt \
    && chown -R tunnelproxy:tunnelproxy /data /var/log/tunnel-proxy /var/lib/letsencrypt /var/www/letsencrypt /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1 \
    PYTHONMALLOC=malloc \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

# Exposed ports:
#   :80    - HTTP (redirects apex -> HTTPS, serves /health)
#   :443   - HTTPS (tunnels + dashboard on apex domain)
#   :9000  - Control channel (raw TCP)
# Tunnel ports (TCP/UDP) are allocated from TCP_PORT_MIN..TCP_PORT_MAX
# (default 10000-65535); expose the range so host firewalls can permit them.
EXPOSE 80
EXPOSE 443
EXPOSE 9000
EXPOSE 10000-65535

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:80/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]