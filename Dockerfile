# Dataset Poisoning Detector - Production Dockerfile
FROM python:3.12-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Production stage
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# Copy poison_detector source
COPY src/poison_detector ./poison_detector
COPY pyproject.toml .
COPY README.md .

RUN pip install --no-cache-dir -e .

# Non-root user
RUN groupadd -r mlsec && useradd -r -g mlsec mlsec
RUN chown -R mlsec:mlsec /app
USER mlsec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "poison_detector.api:app", "--host", "0.0.0.0", "--port", "8000"]