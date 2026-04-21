# =============================================================================
# Project Swarm — Sandboxer Image
# Base: python:3.11-slim
# Runtime isolation: gVisor (runsc) for sandboxed exploit execution
# =============================================================================

FROM python:3.11-slim

# -----------------------------------------------------------------------------
# Build arguments
# -----------------------------------------------------------------------------
ARG GVISOR_URL=https://storage.googleapis.com/gvisor/releases/release/latest/x86_64
ARG GVISOR_RUNSC_URL=${GVISOR_URL}/runsc
ARG GVISOR_RUNSC_SHA_URL=${GVISOR_URL}/runsc.sha512

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/bin:${PATH}"

# -----------------------------------------------------------------------------
# System dependencies
# -----------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        build-essential && \
    rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# gVisor — install runsc and verify checksum
# -----------------------------------------------------------------------------
RUN set -eux; \
    curl -fsSL "${GVISOR_RUNSC_URL}"     -o /usr/local/bin/runsc && \
    curl -fsSL "${GVISOR_RUNSC_SHA_URL}" -o /tmp/runsc.sha512 && \
    sed -i "s|runsc|/usr/local/bin/runsc|" /tmp/runsc.sha512 && \
    sha512sum -c /tmp/runsc.sha512 && \
    chmod +x /usr/local/bin/runsc && \
    rm /tmp/runsc.sha512

# -----------------------------------------------------------------------------
# Working directory
# -----------------------------------------------------------------------------
WORKDIR /app

# -----------------------------------------------------------------------------
# Python dependencies
# -----------------------------------------------------------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Application source
# -----------------------------------------------------------------------------
COPY src/ ./src/
COPY scripts/ ./scripts/

# -----------------------------------------------------------------------------
# Non-root user
# -----------------------------------------------------------------------------
RUN groupadd --gid 1001 swarm && \
    useradd  --uid 1001 --gid swarm --no-create-home --shell /sbin/nologin swarm && \
    chown -R swarm:swarm /app

USER swarm

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
ENTRYPOINT ["python", "scripts/run_scan.py"]
