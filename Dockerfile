FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git && \
    rm -rf /var/lib/apt/lists/*

# Copy environment package files
COPY pyproject.toml ./
COPY openenv.yaml ./
COPY models.py ./
COPY client.py ./
COPY __init__.py ./
COPY server/ ./server/

# Set PYTHONPATH so imports work
ENV PYTHONPATH="/app:$PYTHONPATH"

# Install Python dependencies via pip (no uv needed)
RUN pip install --no-cache-dir \
    "openenv-core[core]>=0.2.2" \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:7860/health || exit 1

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
