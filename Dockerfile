# Multi-stage runtime image for the authenticated dataset-poisoning API.
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --no-cache-dir --upgrade pip wheel \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels ".[realtime]"

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system detector \
    && useradd --system --gid detector --create-home --home-dir /home/detector detector

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links /wheels \
      "dataset-poisoning-detector[realtime]" \
    && rm -rf /wheels

WORKDIR /app
COPY config ./config

USER detector
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()" || exit 1

# Detector and rate-limit state are process-local. Run one worker per container.
# Horizontal replicas require an external/shared rate limiter and deliberate
# detector-state distribution strategy.
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["poison_detector.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
