# ===== Stage 1: base (build deps + system libs) =====
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_PREFER_BINARY=1

# ⚙️ Ajout de curl (utile pour les healthchecks) + chaînes TLS + outils réseau
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl ca-certificates netcat-openbsd \
    libmagic1 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip && \
    bash -lc '\
      set -e; \
      for i in 1 2 3; do \
        echo "[pip] tentative $i/3"; \
        pip install --no-cache-dir --prefer-binary -r /app/requirements.txt && break || \
        (echo "[pip] échec tentative $i, on attend..."; sleep 10); \
      done \
    '

# ===== Stage 2: runtime =====
FROM python:3.11-slim AS runtime

# ✅ IMPORTANT : installer curl aussi dans l'image runtime (utilisé par le healthcheck Docker)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates netcat-openbsd \
    libmagic1 \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m appuser
WORKDIR /app
USER appuser

COPY --from=base /usr/local /usr/local
COPY --chown=appuser:appuser . /app

RUN mkdir -p /app/uploads /app/logs /app/instance /app/keys

ENV FLASK_APP=app:create_app \
    APP_CONFIG=production \
    PORT=8000 \
    HOST=0.0.0.0

COPY --chown=appuser:appuser entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
CMD ["/app/entrypoint.sh"]
