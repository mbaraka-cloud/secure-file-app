#!/usr/bin/env bash
set -e
TS=$(date +"%Y%m%d_%H%M%S")
DEST="./backups"
mkdir -p "$DEST"

# Exporte depuis le container postgres
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-secureuser}" "${POSTGRES_DB:-secureapp}" \
  | gzip > "${DEST}/pg_${TS}.sql.gz"

echo "DB backup -> ${DEST}/pg_${TS}.sql.gz"
