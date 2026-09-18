#!/bin/sh
# Generates a self-signed TLS cert on first start if none is present —
# TLS is mandatory (the gateway refuses any client that doesn't send
# SSLRequest before StartupMessage), and this image has no way to know a
# real cert for local `docker compose up`. Production deployments should
# mount a real cert/key instead (see ../../DEPLOYMENT.md) — this dev cert
# is neither CA-signed nor meant to be trusted by anything but a local
# `sslmode=require` client.
set -e

CERT="${GATEWAY_TLS_CERT:-/app/certs/gateway.crt}"
KEY="${GATEWAY_TLS_KEY:-/app/certs/gateway.key}"

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "[docker-entrypoint] no TLS cert found at $CERT — generating a self-signed dev cert..."
  mkdir -p "$(dirname "$CERT")"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CERT" -days 365 \
    -subj "/CN=metasight-gateway.local" >/dev/null 2>&1
fi

export GATEWAY_TLS_CERT="$CERT"
export GATEWAY_TLS_KEY="$KEY"

exec "$@"
