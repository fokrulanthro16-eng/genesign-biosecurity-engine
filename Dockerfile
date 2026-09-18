# ------------------------------------------------------------------------------
# GeneSign Enterprise Level 2 - Production Multi-Stage Dockerfile
# Python 3.11 Hardened Biosecurity Firewall & DNA Watermarking Engine
# ------------------------------------------------------------------------------

# ----------------- Build Stage -----------------
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies in virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml .
RUN pip install --upgrade pip setuptools wheel
RUN pip install fastapi uvicorn[standard] jinja2 cryptography python-multipart pydantic pytest httpx

# ----------------- Final Production Stage -----------------
FROM python:3.11-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8095 \
    HOST=0.0.0.0 \
    KMS_ROOT=/app/keys \
    LEDGER_PATH=/app/storage/ledger.db \
    MAX_BATCH_RECORDS=500 \
    WORKER_CONCURRENCY=4

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create unprivileged system user for biosecurity process isolation
RUN groupadd -g 1001 genesign && \
    useradd -u 1001 -g genesign -s /bin/bash -m genesign

# Copy application modules and assets
COPY --chown=genesign:genesign engine /app/engine
COPY --chown=genesign:genesign scanner /app/scanner
COPY --chown=genesign:genesign security /app/security
COPY --chown=genesign:genesign storage /app/storage
COPY --chown=genesign:genesign web /app/web
COPY --chown=genesign:genesign samples /app/samples
COPY --chown=genesign:genesign keys /app/keys
COPY --chown=genesign:genesign cli.py /app/cli.py
COPY --chown=genesign:genesign pyproject.toml /app/pyproject.toml
COPY --chown=genesign:genesign README.md /app/README.md

# Ensure persistent mount directories exist with proper ownership
RUN mkdir -p /app/storage /app/keys && \
    chown -R genesign:genesign /app/storage /app/keys

USER genesign

EXPOSE 8095

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8095/healthz || exit 1

ENTRYPOINT ["python", "-m", "uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8095"]
