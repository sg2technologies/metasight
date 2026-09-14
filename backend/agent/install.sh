#!/usr/bin/env bash
# MetaSight Agent — one-line Linux installer
#
# Usage (Oracle):
#   curl -sSL http://YOUR-SERVER:8000/downloads/install-agent.sh | \
#     MS_SERVER=http://YOUR-SERVER:8000 \
#     MS_API_KEY=your-key \
#     MS_DB_TYPE=oracle \
#     MS_DB_HOST=oracle-host \
#     MS_DB_PORT=1521 \
#     MS_DB_NAME=ORCL \
#     MS_DB_USER=metasight_monitor \
#     MS_DB_PASSWORD=yourpassword \
#     MS_AUTHORIZED_USERS=metasight_monitor,apps \
#     MS_AUTHORIZED_IPS=10.0.0.0/8 \
#     bash
#
# Usage (Postgres):
#   curl -sSL http://YOUR-SERVER:8000/downloads/install-agent.sh | \
#     MS_SERVER=http://YOUR-SERVER:8000 \
#     MS_API_KEY=your-key \
#     MS_DB_TYPE=postgres \
#     MS_DB_HOST=localhost \
#     MS_DB_USER=metasight_gateway \
#     MS_DB_PASSWORD=yourpassword \
#     MS_DB_NAME=yourdb \
#     bash
#
# Supported DB types: oracle, oracledb, postgres, mysql, mssql, mongodb
# Oracle notes:
#   - No Oracle Instant Client needed — uses pure-Go driver (go-ora)
#   - Grant required: GRANT SELECT ON V_$SESSION TO metasight_monitor;
#                     GRANT SELECT ON V_$SQL     TO metasight_monitor;
#   - MS_DB_NAME should be the Oracle service name or SID (e.g. ORCL, XEPDB1)

set -euo pipefail

AGENT_VERSION="1.1.0"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="metasight-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_FILE="/etc/metasight/agent.env"
LOG_DIR="/var/log/metasight-agent"

# ── Detect arch ───────────────────────────────────────────────────────────────

ARCH=$(uname -m)
case $ARCH in
  x86_64)  ARCH_SLUG="amd64" ;;
  aarch64) ARCH_SLUG="arm64" ;;
  *) echo "ERROR: Unsupported architecture: $ARCH (expected x86_64 or aarch64)"; exit 1 ;;
esac

# ── Config from environment ───────────────────────────────────────────────────

MS_SERVER="${MS_SERVER:-http://localhost:8000}"
MS_API_KEY="${MS_API_KEY:-}"
MS_DB_TYPE="${MS_DB_TYPE:-postgres}"
MS_DB_HOST="${MS_DB_HOST:-localhost}"
MS_DB_PORT="${MS_DB_PORT:-}"
MS_DB_NAME="${MS_DB_NAME:-}"
MS_DB_USER="${MS_DB_USER:-metasight_monitor}"
MS_DB_PASSWORD="${MS_DB_PASSWORD:-}"
MS_AUTHORIZED_USERS="${MS_AUTHORIZED_USERS:-${MS_DB_USER}}"
MS_AUTHORIZED_IPS="${MS_AUTHORIZED_IPS:-}"
MS_BLOCKED_OPS="${MS_BLOCKED_OPS:-DROP,TRUNCATE,GRANT,REVOKE}"
MS_AGENT_NAME="${MS_AGENT_NAME:-$(hostname)}"
MS_SOURCE_ID="${MS_SOURCE_ID:-}"
MS_INTERVAL="${MS_INTERVAL:-30s}"

if [[ -z "$MS_API_KEY" ]]; then
  echo "ERROR: MS_API_KEY is required. Get it from MetaSight → Settings → Agents."
  exit 1
fi

# Set Oracle default port if not specified
if [[ "$MS_DB_TYPE" == "oracle" || "$MS_DB_TYPE" == "oracledb" ]] && [[ -z "$MS_DB_PORT" ]]; then
  MS_DB_PORT="1521"
fi

# ── Download binary ───────────────────────────────────────────────────────────

DOWNLOAD_URL="${MS_SERVER}/downloads/metasight-agent-linux-${ARCH_SLUG}"

echo "==> Downloading MetaSight Agent v${AGENT_VERSION} (linux-${ARCH_SLUG}) from ${MS_SERVER}..."
if ! curl -fsSL --connect-timeout 15 --retry 3 -o /tmp/metasight-agent "${DOWNLOAD_URL}"; then
  echo ""
  echo "ERROR: Download failed from ${DOWNLOAD_URL}"
  echo ""
  echo "Make sure the MetaSight server is reachable and the Linux binary has been built:"
  echo "  cd backend/agent && make linux"
  echo ""
  echo "Or build manually on this machine:"
  echo "  git clone https://github.com/metasight/metasight && cd metasight/backend/agent"
  echo "  CGO_ENABLED=0 go build -o /usr/local/bin/metasight-agent ./cmd/agent"
  exit 1
fi

chmod +x /tmp/metasight-agent
mv /tmp/metasight-agent "${INSTALL_DIR}/metasight-agent"
echo "    Binary installed to ${INSTALL_DIR}/metasight-agent"

# ── Write env file ────────────────────────────────────────────────────────────

echo "==> Writing environment file to ${ENV_FILE}..."
mkdir -p /etc/metasight
cat > "${ENV_FILE}" <<EOF
MS_SERVER=${MS_SERVER}
MS_API_KEY=${MS_API_KEY}
MS_DB_TYPE=${MS_DB_TYPE}
MS_DB_HOST=${MS_DB_HOST}
MS_DB_PORT=${MS_DB_PORT}
MS_DB_NAME=${MS_DB_NAME}
MS_DB_USER=${MS_DB_USER}
MS_DB_PASSWORD=${MS_DB_PASSWORD}
MS_AUTHORIZED_USERS=${MS_AUTHORIZED_USERS}
MS_AUTHORIZED_IPS=${MS_AUTHORIZED_IPS}
MS_BLOCKED_OPS=${MS_BLOCKED_OPS}
MS_AGENT_NAME=${MS_AGENT_NAME}
MS_SOURCE_ID=${MS_SOURCE_ID}
EOF
chmod 600 "${ENV_FILE}"
echo "    Credentials written (mode 600)"

# ── Build ExecStart args ──────────────────────────────────────────────────────

EXEC_ARGS="--mode db"
EXEC_ARGS+=" --server \${MS_SERVER}"
EXEC_ARGS+=" --api-key \${MS_API_KEY}"
EXEC_ARGS+=" --db-type \${MS_DB_TYPE}"
EXEC_ARGS+=" --db-host \${MS_DB_HOST}"
EXEC_ARGS+=" --db-user \${MS_DB_USER}"
EXEC_ARGS+=" --db-password \${MS_DB_PASSWORD}"
EXEC_ARGS+=" --interval ${MS_INTERVAL}"

[[ -n "$MS_DB_PORT" ]]           && EXEC_ARGS+=" --db-port \${MS_DB_PORT}"
[[ -n "$MS_DB_NAME" ]]           && EXEC_ARGS+=" --db-name \${MS_DB_NAME}"
[[ -n "$MS_AUTHORIZED_USERS" ]]  && EXEC_ARGS+=" --authorized-users \${MS_AUTHORIZED_USERS}"
[[ -n "$MS_AUTHORIZED_IPS" ]]    && EXEC_ARGS+=" --authorized-ips \${MS_AUTHORIZED_IPS}"
[[ -n "$MS_BLOCKED_OPS" ]]       && EXEC_ARGS+=" --blocked-ops \${MS_BLOCKED_OPS}"
[[ -n "$MS_AGENT_NAME" ]]        && EXEC_ARGS+=" --name \${MS_AGENT_NAME}"
[[ -n "$MS_SOURCE_ID" ]]         && EXEC_ARGS+=" --source-id \${MS_SOURCE_ID}"

# ── Create systemd service ────────────────────────────────────────────────────

echo "==> Creating systemd service ${SERVICE_NAME}..."
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=MetaSight DB Activity Agent (${MS_DB_TYPE})
After=network.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/metasight-agent ${EXEC_ARGS}
Restart=on-failure
RestartSec=15s
# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

mkdir -p "${LOG_DIR}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  MetaSight Agent installed and running                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  DB type : ${MS_DB_TYPE}"
echo "  DB host : ${MS_DB_HOST}:${MS_DB_PORT:-default}"
echo "  Service : systemctl status ${SERVICE_NAME}"
echo "  Logs    : journalctl -u ${SERVICE_NAME} -f"
echo "  Config  : ${ENV_FILE}"
echo ""

if [[ "$MS_DB_TYPE" == "oracle" || "$MS_DB_TYPE" == "oracledb" ]]; then
  echo "Oracle prerequisites — grant on the Oracle server:"
  echo "  GRANT SELECT ON V_\$SESSION TO ${MS_DB_USER};"
  echo "  GRANT SELECT ON V_\$SQL     TO ${MS_DB_USER};"
  echo "  GRANT ALTER  SYSTEM TO ${MS_DB_USER};  -- only needed if block-mode is enabled"
  echo ""
fi
