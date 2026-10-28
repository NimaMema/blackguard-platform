ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}
WORKDIR /app
# Only runtime code is copied; data, tests and secrets are excluded via .dockerignore.
COPY guard ./guard
COPY web ./web
COPY agents ./agents
COPY start.py app.py ./
RUN groupadd --system blackguard && useradd --system --gid blackguard --home-dir /app blackguard \
    && mkdir -p /app/data && chown -R blackguard:blackguard /app/data
USER blackguard
# Inside the container we bind all interfaces; compose publishes the port on host loopback only.
ENV BLACKGUARD_HOST=0.0.0.0 BLACKGUARD_PORT=8000 BLACKGUARD_DATA_DIR=/app/data \
    BLACKGUARD_ALLOW_REMOTE_WITHOUT_TLS=1 BLACKGUARD_LOG_FILE= PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['BLACKGUARD_PORT']+'/healthz',timeout=4)"
# docker stop sends SIGTERM: the server drains requests and records a clean shutdown.
STOPSIGNAL SIGTERM
CMD ["python3", "start.py"]
