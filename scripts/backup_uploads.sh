#!/usr/bin/env bash
set -e
TS=$(date +"%Y%m%d_%H%M%S")
DEST="./backups"
mkdir -p "$DEST"

tar -czf "${DEST}/uploads_${TS}.tar.gz" uploads keys
echo "Files backup -> ${DEST}/uploads_${TS}.tar.gz"
