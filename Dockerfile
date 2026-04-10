## NetPwn OpenEnv — root-level Dockerfile for HF Spaces
ARG BASE_IMAGE=ghcr.io/meta-pytorch/openenv-base:latest
FROM ${BASE_IMAGE} AS builder

WORKDIR /app/env

# Install git (needed for VCS deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml ./
COPY openenv.yaml ./
COPY models.py ./
COPY client.py ./
COPY __init__.py ./
COPY server/ ./server/

# Ensure uv is available
RUN if ! command -v uv >/dev/null 2>&1; then \
        curl -LsSf https://astral.sh/uv/install.sh | sh && \
        mv /root/.local/bin/uv /usr/local/bin/uv && \
        mv /root/.local/bin/uvx /usr/local/bin/uvx; \
    fi

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project --no-editable || pip install openenv-core fastapi uvicorn pydantic

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-editable || true

# ── Final runtime stage ───────────────────────────────────────────────────────
FROM ${BASE_IMAGE}

WORKDIR /app/env

COPY --from=builder /app/env /app/env
COPY --from=builder /app/env/.venv /app/.venv 2>/dev/null || true

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/env:$PYTHONPATH"

# Install deps via pip as fallback if .venv missing
RUN pip install --no-cache-dir openenv-core fastapi uvicorn pydantic || true

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["sh", "-c", "cd /app/env && uvicorn server.app:app --host 0.0.0.0 --port 7860"]
