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

# Fail loudly, before touching the database, if .env was copied from
# .env.example but never actually edited. docker-compose.yml's
# ${VAR:?msg} guards only catch a var being *unset* — they don't catch it
# still being the literal placeholder, so `cp .env.example .env` with no
# edits sails straight past them. Without this check the failure mode was
# either a raw Python ValidationError traceback (ENCRYPTION_KEY happens to
# have a length check) or, worse, for every other secret here: nothing at
# all — a fully "working" stack with the literal password CHANGE_ME.
placeholder_vars=""
for var in POSTGRES_PASSWORD SETUP_SECRET JWT_SECRET_KEY SUPER_ADMIN_PASSWORD ENCRYPTION_KEY; do
  eval "val=\$$var"
  if [ "$val" = "CHANGE_ME" ]; then
    placeholder_vars="$placeholder_vars $var"
  fi
done
if [ -n "$placeholder_vars" ]; then
  echo "[docker-entrypoint] ERROR: .env still has placeholder value(s) — edit .env (not .env.example) and set real values for:$placeholder_vars" >&2
  echo "[docker-entrypoint] See the generation note near the top of .env.example (openssl rand -hex 32, or docker run --rm python:3.11-slim ...)." >&2
  exit 1
fi

if [ "$RUN_MIGRATIONS" = "true" ]; then
  echo "[docker-entrypoint] running alembic upgrade head..."
  alembic upgrade head
fi

exec "$@"
