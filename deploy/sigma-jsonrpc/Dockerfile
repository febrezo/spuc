FROM python:3.12-slim

LABEL maintainer="SPUC" \
      description="sigma-jsonrpc: JSON-RPC 2.0 service for Sigma rule conversion"

WORKDIR /srv/sigma-jsonrpc

# System packages needed by some pySigma backends
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install service dependencies first (good cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install sigma-cli and all backends (failures are tolerated per-package)
COPY scripts/install_plugins.sh /tmp/install_plugins.sh
RUN chmod +x /tmp/install_plugins.sh && /tmp/install_plugins.sh

# Copy application code
COPY app/ ./app/

EXPOSE 8080

ENV PORT=8080 \
    LOG_LEVEL=INFO

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
