# Ariadne — blockchain money-flow tracer. Pure-Python, no system dependencies.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Ariadne" \
      org.opencontainers.image.description="Blockchain money-flow tracer for lawful financial-crime investigation" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first (better layer caching), then the package.
COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY ariadne ./ariadne
RUN pip install --upgrade pip && pip install -e ".[pdf]"

# Runtime data (cache / knowledge / reports) and the Ed25519 signing key are created
# on first use under /app. Mount a volume there to persist them across containers.
EXPOSE 8000

# Default: launch the web console, bound to all interfaces INSIDE the container.
# The API is unauthenticated by default — pass --auth-token / put it behind a proxy
# for anything beyond a local demo. Recommended first run: `ariadne update-intel`.
ENTRYPOINT ["ariadne"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
