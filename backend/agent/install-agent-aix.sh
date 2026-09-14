#!/bin/sh
# MetaSight Agent — AIX installer (PowerPC / ppc64)
#
# For Oracle E-Business Suite database tiers running on AIX. Uses the pure-Go
# Oracle driver (go-ora) — no Oracle Instant Client, no thick-mode libraries,
# nothing to install on the DB tier beyond this one static binary.
#
# AIX has no systemd, so this registers the agent as an /etc/inittab
# "respawn" entry instead — init restarts it if it ever exits, the same way
# systemd's Restart=on-failure does on Linux. Written in POSIX sh (not bash)
# since AIX's /bin/sh and default ksh don't support bash-isms.
#
# Usage (Oracle EBS):
#   curl -sSL http://YOUR-SERVER:8000/downloads/install-agent-aix.sh | \
#     MS_SERVER=http://YOUR-SERVER:8000 \
#     MS_API_KEY=your-key \
#     MS_DB_TYPE=oracle \
#     MS_DB_HOST=localhost \
#     MS_DB_PORT=1521 \
#     MS_DB_NAME=PROD \
#     MS_DB_USER=metasight_monitor \
#     MS_DB_PASSWORD=yourpassword \
#     MS_AUTHORIZED_USERS=metasight_monitor,apps \
#     MS_AUTHORIZED_IPS=10.0.0.0/8 \
#     sh
#
# Oracle notes:
#   - MS_DB_NAME should be the EBS instance's SID or service name (EBS's
#     listener almost always auto-registers the SID as a matching service
#     name too, so the SID usually works directly). If you get ORA-12514,
#     run `lsnrctl status` on the DB tier to confirm the exact name to use.
#   - Grant required (run as a DBA):
#       GRANT SELECT ON V_$SESSION TO metasight_monitor;
#       GRANT SELECT ON V_$SQL     TO metasight_monitor;
#   - Do NOT enable --block against a production EBS database until you've
#     watched it in alert-only mode first: terminating the wrong session on
#     an EBS DB tier can kill a concurrent-manager or apps-tier connection,
#     not just an ad hoc client. Scope MS_AUTHORIZED_USERS/IPS tightly.

set -e

AGENT_VERSION="1.1.0"
INSTALL_DIR="/usr/local/bin"
ENV_FILE="/etc/metasight/agent.env"
RUN_SCRIPT="/usr/local/bin/metasight-agent-run.sh"
LOG_DIR="/var/log/metasight-agent"
INITTAB_ID="metasight"

# ── Must run as root (writes /etc, /usr/local/bin, inittab) ─────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this installer must be run as root."
  exit 1
fi

# ── Sanity check: this is AIX ────────────────────────────────────────────────
OS_NAME=$(uname -s)
if [ "$OS_NAME" != "AIX" ]; then
  echo "ERROR: this installer is for AIX only (detected: $OS_NAME)."
  echo "Linux hosts: use install-agent.sh instead."
  exit 1
fi

# ── Config from environment ───────────────────────────────────────────────────
MS_SERVER="${MS_SERVER:-http://localhost:8000}"
MS_API_KEY="${MS_API_KEY:-}"
MS_DB_TYPE="${MS_DB_TYPE:-oracle}"
MS_DB_HOST="${MS_DB_HOST:-localhost}"
MS_DB_PORT="${MS_DB_PORT:-}"
MS_DB_NAME="${MS_DB_NAME:-}"
MS_DB_USER="${MS_DB_USER:-metasight_monitor}"
MS_DB_PASSWORD="${MS_DB_PASSWORD:-}"
MS_AUTHORIZED_USERS="${MS_AUTHORIZED_USERS:-$MS_DB_USER}"
MS_AUTHORIZED_IPS="${MS_AUTHORIZED_IPS:-}"
MS_BLOCKED_OPS="${MS_BLOCKED_OPS:-DROP,TRUNCATE,GRANT,REVOKE}"
MS_AGENT_NAME="${MS_AGENT_NAME:-$(hostname)}"
MS_SOURCE_ID="${MS_SOURCE_ID:-}"
MS_INTERVAL="${MS_INTERVAL:-30s}"
MS_DB_SSLMODE="${MS_DB_SSLMODE:-disable}"

if [ -z "$MS_API_KEY" ]; then
  echo "ERROR: MS_API_KEY is required. Get it from MetaSight -> Settings -> Agents."
  exit 1
fi

if [ "$MS_DB_TYPE" = "oracle" ] || [ "$MS_DB_TYPE" = "oracledb" ]; then
  if [ -z "$MS_DB_PORT" ]; then
    MS_DB_PORT="1521"
  fi
fi

# ── Download binary ───────────────────────────────────────────────────────────
DOWNLOAD_URL="${MS_SERVER}/downloads/metasight-agent-aix-ppc64"

echo "==> Downloading MetaSight Agent v${AGENT_VERSION} (aix-ppc64) from ${MS_SERVER}..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL --connect-timeout 15 --retry 3 -o /tmp/metasight-agent "${DOWNLOAD_URL}"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O /tmp/metasight-agent "${DOWNLOAD_URL}"
else
  echo "ERROR: neither curl nor wget is available on this host."
  echo "Install one (often under /opt/freeware/bin via the AIX Toolbox for"
  echo "Linux Applications), or download the binary manually from:"
  echo "  ${DOWNLOAD_URL}"
  echo "and place it at ${INSTALL_DIR}/metasight-agent (chmod 755) before re-running."
  exit 1
fi

if [ ! -s /tmp/metasight-agent ]; then
  echo "ERROR: download failed or produced an empty file from ${DOWNLOAD_URL}"
  echo "Make sure the MetaSight server is reachable and the AIX binary has been built:"
  echo "  cd backend/agent && make build-aix"
  exit 1
fi

chmod 755 /tmp/metasight-agent
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
MS_INTERVAL=${MS_INTERVAL}
MS_DB_SSLMODE=${MS_DB_SSLMODE}
EOF
chmod 600 "${ENV_FILE}"
echo "    Credentials written (mode 600)"

mkdir -p "${LOG_DIR}"

# ── Write the run wrapper (inittab commands are one-liners; keep the ─────────
#    optional-argument logic in a real script instead of jamming it all
#    into /etc/inittab) ────────────────────────────────────────────────────
echo "==> Writing run wrapper to ${RUN_SCRIPT}..."
cat > "${RUN_SCRIPT}" <<'EOF'
#!/bin/sh
# Auto-generated by install-agent-aix.sh — do not edit by hand.
. /etc/metasight/agent.env

set -- --mode db \
  --server "$MS_SERVER" \
  --api-key "$MS_API_KEY" \
  --db-type "$MS_DB_TYPE" \
  --db-host "$MS_DB_HOST" \
  --db-user "$MS_DB_USER" \
  --db-password "$MS_DB_PASSWORD" \
  --interval "${MS_INTERVAL:-30s}"

[ -n "$MS_DB_PORT" ]           && set -- "$@" --db-port "$MS_DB_PORT"
[ -n "$MS_DB_NAME" ]           && set -- "$@" --db-name "$MS_DB_NAME"
[ -n "$MS_DB_SSLMODE" ]        && set -- "$@" --db-sslmode "$MS_DB_SSLMODE"
[ -n "$MS_AUTHORIZED_USERS" ]  && set -- "$@" --authorized-users "$MS_AUTHORIZED_USERS"
[ -n "$MS_AUTHORIZED_IPS" ]    && set -- "$@" --authorized-ips "$MS_AUTHORIZED_IPS"
[ -n "$MS_BLOCKED_OPS" ]       && set -- "$@" --blocked-ops "$MS_BLOCKED_OPS"
[ -n "$MS_AGENT_NAME" ]        && set -- "$@" --name "$MS_AGENT_NAME"
[ -n "$MS_SOURCE_ID" ]         && set -- "$@" --source-id "$MS_SOURCE_ID"

exec /usr/local/bin/metasight-agent "$@"
EOF
chmod 755 "${RUN_SCRIPT}"

# ── Register with /etc/inittab (respawn = init restarts it if it exits) ──────
echo "==> Registering inittab entry '${INITTAB_ID}'..."
INITTAB_CMD="${RUN_SCRIPT} >>${LOG_DIR}/agent.log 2>&1"
if lsitab "${INITTAB_ID}" >/dev/null 2>&1; then
  chitab "${INITTAB_ID}:2:respawn:${INITTAB_CMD}"
  echo "    Updated existing inittab entry"
else
  mkitab "${INITTAB_ID}:2:respawn:${INITTAB_CMD}"
  echo "    Created inittab entry"
fi

# Pick up the new/changed entry now, without a reboot
telinit q

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  MetaSight Agent installed and running (AIX / inittab respawn)"
echo "================================================================"
echo ""
echo "  DB type : ${MS_DB_TYPE}"
echo "  DB host : ${MS_DB_HOST}:${MS_DB_PORT:-default}"
echo "  Status  : ps -ef | grep metasight-agent"
echo "  Logs    : tail -f ${LOG_DIR}/agent.log"
echo "  Config  : ${ENV_FILE}"
echo "  Stop    : rmitab ${INITTAB_ID} ; then kill the running process"
echo ""

if [ "$MS_DB_TYPE" = "oracle" ] || [ "$MS_DB_TYPE" = "oracledb" ]; then
  echo "Oracle prerequisites -- grant on the Oracle server:"
  echo "  GRANT SELECT ON V_\$SESSION TO ${MS_DB_USER};"
  echo "  GRANT SELECT ON V_\$SQL     TO ${MS_DB_USER};"
  echo "  GRANT ALTER  SYSTEM TO ${MS_DB_USER};  -- only needed if block-mode is enabled"
  echo ""
fi
