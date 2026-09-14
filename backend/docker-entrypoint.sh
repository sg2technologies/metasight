#!/bin/sh
# Entrypoint shared by the backend (API) and celery-worker services in
# ../docker-compose.yml — same image, different CMD.
#
# Only the API container runs migrations (RUN_MIGRATIONS=true, set in
# docker-compose.yml on the `backend` service only) — running
# `alembic upgrade head` from two containers racing on the same fresh
# database on first `docker compose up` is avoidable by just picking one
# owner, rather than relying on Alembic's locking behavior across engines.
set -e

if [ "$RUN_MIGRATIONS" = "true" ]; then
  echo "[docker-entrypoint] running alembic upgrade head..."
  alembic upgrade head
fi

exec "$@"
