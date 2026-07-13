# Ariadne — blockchain money-flow tracer. Pure-Python, no system dependencies.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Ariadne" \
      org.opencontainers.image.description="Blockchain money-flow tracer for lawful financial-crime investigation" \
      org.opencontainers.image.source="https://github.com/Theasus-ops/Project_Ariadne" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first (better layer caching), then the package itself.
# [pdf] = court-ready PDF reports; [serve] = waitress production WSGI server.
COPY pyproject.toml README.md LICENSE ./
COPY ariadne ./ariadne
RUN pip install --upgrade pip && pip install ".[pdf,serve]"

# Run as a non-root user (defence-in-depth). /app is writable so the runtime
# cache / knowledge / reports and the Ed25519 signing key are created on first
# use; mount a volume at /app/knowledge and /app/cache to persist them.
RUN useradd --create-home --uid 10001 ariadne \
    && mkdir -p /app/cache /app/knowledge /app/reports /app/keys \
    && chown -R ariadne:ariadne /app
USER ariadne

EXPOSE 8000

# Liveness probe for orchestrators (Docker / Kubernetes) — hits the web health
# endpoint using only the stdlib, so no extra packages (curl/wget) are needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"

# Default: launch the web console, bound to all interfaces INSIDE the container.
# The API is unauthenticated by default — pass --auth-token / put it behind a
# proxy for anything beyond a local demo. Recommended first run: ariadne update-intel.
ENTRYPOINT ["ariadne"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
