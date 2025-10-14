#!/bin/sh
set -eu

echo "[entry] Waiting for Postgres to be ready..."
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

i=0
while [ "$i" -lt 60 ]; do
  if command -v nc >/dev/null 2>&1; then
    if nc -z "$POSTGRES_HOST" "$POSTGRES_PORT"; then
      echo "[entry] Postgres is ready."
      break
    fi
  else
    if sh -c "exec 3<>/dev/tcp/${POSTGRES_HOST}/${POSTGRES_PORT}" 2>/dev/null; then
      exec 3>&-
      echo "[entry] Postgres is ready (tcp)."
      break
    fi
  fi
  i=$((i+1))
  echo "[entry] Postgres not ready yet... ($i)"
  sleep 2
done

echo "[entry] Env: FLASK_APP=${FLASK_APP:-unset} | APP_CONFIG=${APP_CONFIG:-unset} | USE_SSL=${USE_SSL:-unset}"
echo "[entry] DATABASE_URL=${DATABASE_URL:+(set)}"

: "${MIGRATION_TIMEOUT_SECS:=120}"    # limite max pour 'flask db upgrade'
: "${SKIP_DB_MIGRATIONS:=false}"      # true = ne lance pas Alembic (diagnostic)
: "${GUNICORN_WORKERS:=2}"
: "${GUNICORN_TIMEOUT:=120}"

if [ "$SKIP_DB_MIGRATIONS" = "true" ]; then
  echo "[entry] SKIP_DB_MIGRATIONS=true -> skip migrations."
else
  echo "[entry] Running Alembic migrations (timeout=${MIGRATION_TIMEOUT_SECS}s)..."
  if command -v timeout >/dev/null 2>&1; then
    set +e
    timeout "${MIGRATION_TIMEOUT_SECS}"s flask db upgrade
    rc=$?
    set -e
    if [ $rc -eq 124 ]; then
      echo "[entry][WARN] Alembic timed out (${MIGRATION_TIMEOUT_SECS}s). Continuing to start app."
    elif [ $rc -ne 0 ]; then
      echo "[entry][WARN] Alembic failed (rc=$rc). Continuing to start app."
    else
      echo "[entry] Alembic upgrade done."
    fi
  else
    echo "[entry][WARN] 'timeout' not found. Running 'flask db upgrade' without timebox..."
    set +e
    flask db upgrade
    rc=$?
    set -e
    if [ $rc -ne 0 ]; then
      echo "[entry][WARN] Alembic failed (rc=$rc). Continuing anyway."
    else
      echo "[entry] Alembic upgrade done."
    fi
  fi
fi

echo "[entry] Starting gunicorn on :8000 ..."
exec gunicorn "app:create_app()" \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS}" \
  --timeout "${GUNICORN_TIMEOUT}" \
  --access-logfile "-" \
  --error-logfile "-"
