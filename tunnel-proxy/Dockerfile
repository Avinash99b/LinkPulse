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

# Install runtime dependencies: nginx + supervisord + SSL libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    supervisor \
    libssl3 \
    ca-certificates \
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

# Copy nginx config (modified for single container - use localhost)
COPY nginx.conf /etc/nginx/nginx.conf

# Copy supervisord config
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create directories for data, logs, and nginx
RUN mkdir -p /data /var/log/tunnel-proxy /var/log/nginx /var/lib/nginx/body /run/nginx /var/log/supervisor && \
    chown -R tunnelproxy:tunnelproxy /data /var/log/tunnel-proxy /var/log/nginx /var/lib/nginx /run/nginx /var/log/supervisor /app

# Switch to non-root user
USER tunnelproxy

# Environment variables with defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1 \
    # Memory optimization
    PYTHONMALLOC=malloc \
    # Reduce thread count for low CPU
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

# Expose only port 80 externally (nginx entry point)
EXPOSE 80

# Health check - checks nginx health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Run supervisord to manage both processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]