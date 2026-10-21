#!/usr/bin/env bash
# Nightly backup of the database, uploads and .env. Keeps 14 days.
set -euo pipefail
D=/opt/peltdev; OUT=/var/backups/peltdev; mkdir -p "$OUT"; chmod 700 "$OUT"
STAMP=$(date +%F)
# consistent copy of SQLite even while the app is running
sqlite3 "$D/backend/peltdev.db" ".backup '$OUT/peltdev-$STAMP.db'"
tar -czf "$OUT/files-$STAMP.tar.gz" -C "$D" .env frontend/static/uploads 2>/dev/null || true
chmod 600 "$OUT"/*
find "$OUT" -type f -mtime +14 -delete
