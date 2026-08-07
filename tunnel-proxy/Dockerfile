# Dockerfile for tunnel-proxy with nginx reverse proxy (single container)
# Optimized for low resource environments (512MB RAM, 0.1-0.5 vCPU)
# Multi-stage build for smaller final image

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Final runtime image
FROM python:3.11-slim AS runtime

# Install runtime dependencies: nginx + haproxy + supervisord + SSL libs + certbot + cron
# libnginx-mod-stream provides the stream module (dynamic .so) used for
# proxying the control channel; plain `nginx` only installs nginx-core.
# haproxy is the HTTP front door.
# certbot handles automatic wildcard SSL via Let's Encrypt (DNS challenge).
# cron runs certbot auto-renewal.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    libnginx-mod-stream \
    haproxy \
    supervisor \
    certbot \
    cron \
    libssl3 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r tunnelproxy && useradd -r -g tunnelproxy -d /app -s /bin/bash tunnelproxy

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY proxy_server.py .
COPY protocol.py .
COPY storage.py .
COPY dashboard.py .
COPY requirements.txt .
COPY examples/ ./examples/

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy haproxy config (protocol-sniffing front door)
COPY haproxy.cfg /etc/haproxy/haproxy.cfg

# Copy supervisord config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy entrypoint (runs as root, chowns mounted volumes, then starts supervisord)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create directories for data, logs, and nginx
RUN mkdir -p /data /var/log/tunnel-proxy /var/log/nginx /var/lib/nginx/body /run/nginx /var/log/supervisor /run/supervisord && \
    chown -R tunnelproxy:tunnelproxy /data /var/log/tunnel-proxy /var/log/nginx /var/lib/nginx /run/nginx /var/log/supervisor /run/supervisord /app

# Environment variables with defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1 \
    # Memory optimization
    PYTHONMALLOC=malloc \
    # Reduce thread count for low CPU
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

# Expose ports externally:
#   :80    - haproxy (HTTP -> HTTPS redirect, health checks)
#   :443   - nginx (HTTPS termination for tunnels + dashboard)
#   :9000  - nginx stream (control channel) -> internal :9001
EXPOSE 80
EXPOSE 443
EXPOSE 9000

# Health check - hits the Python server directly (port 8080) so it fails if proxy_server.py dies
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

# Run entrypoint as root (to chown mounted volumes), supervisord drops per-program privileges
ENTRYPOINT ["/entrypoint.sh"]