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

# Install runtime dependencies: nginx + haproxy + supervisord + SSL libs
# haproxy is the single HTTP front door on port 80.
# nginx routes /dashboard/ and /api/ to the dashboard and everything else
# (HTTP tunnels + the /ws WebSocket control plane) to proxy_server.
# TLS termination is handled externally (cloud LB/Cloudflare/own reverse
# proxy), so certbot/cron and the old stream control channel are NOT needed
# in the container.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    haproxy \
    supervisor \
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

# Copy haproxy config (single HTTP front door)
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

# Expose a single external port:
#   :80 - haproxy HTTP front door -> nginx -> proxy_server (HTTP tunnels,
#         /ws WebSocket control plane, dashboard)
EXPOSE 80

# Health check - hits the Python server directly (port 8080) so it fails if proxy_server.py dies
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

# Run entrypoint as root (to chown mounted volumes), supervisord drops per-program privileges
ENTRYPOINT ["/entrypoint.sh"]