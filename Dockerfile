# Multi-stage production build for Dataset Poisoning Detector API
#
# Build: docker build -t poison-detector:latest .
# Run:   docker run -p 8000:8000 poison-detector:latest
#
# Security: runs as non-root user, no dev dependencies in final image,
# minimal attack surface with slim base.

# ─── Stage 1: Build ────────────────────────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy only dependency specification first (layer caching)
COPY pyproject.toml .
COPY src/ src/

# Build wheel
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -e ".[realtime]"

# ─── Stage 2: Production ──────────────────────────────────────────────────────
FROM python:3.14-slim AS production

# Security: create non-root user
RUN groupadd -r detector && useradd -r -g detector -d /app -s /sbin/nologin detector

WORKDIR /app

# Install runtime dependencies from wheels (no compilation needed)
COPY --from=builder /build/wheels /tmp/wheels
COPY --from=builder /build/pyproject.toml .
COPY --from=builder /build/src/ src/

RUN pip install --no-cache-dir --find-links /tmp/wheels -e ".[realtime]" \
    && rm -rf /tmp/wheels

# Copy configuration
COPY config/ config/

# Switch to non-root user
USER detector

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run with uvicorn -- production settings
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["poison_detector.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--access-log"]
