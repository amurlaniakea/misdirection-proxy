# Misdirection Proxy — Production Dockerfile

FROM python:3.12-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# App directory
WORKDIR /app

# Install Python dependencies first (layer caching)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

# Copy source code
COPY src/ src/
COPY tests/ tests/

# Expose gateway port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run gateway
CMD ["uvicorn", "src.misdirection.proxy.gateway:app", \
     "--host", "0.0.0.0", \
     "--port", "8000"]
