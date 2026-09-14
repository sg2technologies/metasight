#!/usr/bin/env bash
# MetaSight — Linux/macOS dev startup
# Logs appear LIVE in the terminal with color-coded prefixes AND are saved to
# backend/logs/*.log so you can also run: tail -f logs/metasight.log
# Usage: bash start.sh
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$BACKEND_DIR/venv"
PYTHON_EXE="$VENV_DIR/bin/python"
UVICORN_EXE="$VENV_DIR/bin/uvicorn"
CELERY_EXE="$VENV_DIR/bin/celery"
FRONTEND_DIR="$BACKEND_DIR/../frontend"
LOG_DIR="$BACKEND_DIR/logs"
mkdir -p "$LOG_DIR"

cd "$BACKEND_DIR"

# ── Terminal colours ──────────────────────────────────────────────────────────
# Detect colour support (disable on non-TTY piped output)
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_RST="\033[0m"
    C_BOLD="\033[1m"
    C_DIM="\033[2m"
    C_RED="\033[31m"
    C_GRN="\033[32m"
    C_YLW="\033[33m"
    C_BLU="\033[34m"
    C_MAG="\033[35m"
    C_CYN="\033[36m"
    C_WHT="\033[37m"
    # Per-process prefix colours
    COL_API="\033[36m"   # cyan   — FastAPI
    COL_WRK="\033[35m"   # magenta — Celery worker
    COL_BEA="\033[33m"   # yellow  — Celery beat
    COL_WEB="\033[32m"   # green   — Vite frontend
else
    C_RST=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""
    C_YLW=""; C_BLU=""; C_MAG=""; C_CYN=""; C_WHT=""
    COL_API=""; COL_WRK=""; COL_BEA=""; COL_WEB=""
fi

info()    { printf "${C_GRN}[INFO ]${C_RST} %s\n" "$*"; }
warn()    { printf "${C_YLW}[WARN ]${C_RST} %s\n" "$*"; }
err()     { printf "${C_RED}[ERROR]${C_RST} %s\n" "$*"; }
step()    { printf "\n${C_BOLD}${C_CYN}══ %s${C_RST}\n" "$*"; }
ok()      { printf "${C_GRN}  ✓${C_RST} %s\n" "$*"; }

# ── Banner ────────────────────────────────────────────────────────────────────
printf "\n"
printf "${C_BOLD}${C_BLU}╔══════════════════════════════════════════════════╗${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${C_BOLD}MetaSight${C_RST} — Enterprise Data Governance Platform  ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}╚══════════════════════════════════════════════════╝${C_RST}\n"
printf "\n"

# ── 1. Python venv ────────────────────────────────────────────────────────────
step "Python virtual environment"
if [ ! -f "$PYTHON_EXE" ]; then
    info "Creating virtual environment …"
    PY_CMD=""
    for v in python3.11 python3.12 python3.10 python3 python; do
        if command -v "$v" &>/dev/null; then
            PY_CMD="$v"
            break
        fi
    done
    if [ -z "$PY_CMD" ]; then
        err "Python 3.10+ not found. Install via your package manager."
        exit 1
    fi
    info "Using: $PY_CMD ($($PY_CMD --version))"
    "$PY_CMD" -m venv "$VENV_DIR"
fi
ok "Virtual environment ready: $VENV_DIR"

# ── 2. Install / verify dependencies ─────────────────────────────────────────
step "Python dependencies"
if ! "$PYTHON_EXE" -c "import uvicorn, celery, fastapi, sqlalchemy, pydantic_settings" &>/dev/null; then
    info "Installing core dependencies (this takes ~30s first time) …"
    "$PYTHON_EXE" -m pip install --upgrade pip --quiet
    "$PYTHON_EXE" -m pip install \
        fastapi "uvicorn[standard]" "sqlalchemy>=2.0" alembic psycopg2-binary \
        "python-jose[cryptography]" "passlib[argon2]" argon2-cffi python-dotenv \
        pydantic-settings "celery[redis]" redis cryptography python-multipart \
        slowapi sqlglot email-validator pymysql httpx minio apscheduler \
        hvac setuptools --quiet

    info "Installing optional DB drivers (failures are non-fatal) …"
    "$PYTHON_EXE" -m pip install \
        pymssql oracledb snowflake-sqlalchemy sqlalchemy-bigquery duckdb-engine \
        clickhouse-connect trino pyathena vertica-python pydruid pinotdb \
        pymongo cassandra-driver elasticsearch opensearch-py \
        boto3 azure-storage-blob google-cloud-storage databricks-sql-connector \
        --quiet 2>/dev/null || true
fi
ok "Dependencies ready"

# ── 3. Redis check ────────────────────────────────────────────────────────────
step "Redis connectivity check"
if "$PYTHON_EXE" -c "
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(('127.0.0.1', 6379))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
    ok "Redis is up on localhost:6379"
    REDIS_OK=1
else
    warn "Redis NOT found on localhost:6379"
    printf "\n"
    printf "  Celery (background tasks & DAM polling) requires Redis.\n"
    printf "  Start it with one of:\n"
    printf "    ${C_CYN}sudo systemctl start redis${C_RST}\n"
    printf "    ${C_CYN}redis-server --daemonize yes${C_RST}\n"
    printf "    ${C_CYN}docker run -d -p 6379:6379 redis:alpine${C_RST}\n"
    printf "\n"
    printf "  FastAPI will still start. Scans will run synchronously (no background tasks).\n"
    printf "  Press ${C_BOLD}Enter${C_RST} to continue, or ${C_BOLD}Ctrl+C${C_RST} to abort: "
    read -r
    REDIS_OK=0
fi

# ── 4. Kill any existing instances ────────────────────────────────────────────
step "Stopping any previous MetaSight processes"
pkill -f "uvicorn app.main:app"           2>/dev/null && info "Stopped previous FastAPI"    || true
pkill -f "celery.*celery_app.*worker"     2>/dev/null && info "Stopped previous Celery worker" || true
pkill -f "celery.*celery_app.*beat"       2>/dev/null && info "Stopped previous Celery beat"   || true
sleep 1

# ── Helper: prefix each line from a process with a coloured service tag ───────
#   Usage: some_cmd 2>&1 | _prefix "TAG" "\033[36m" "$LOG_DIR/file.log" &
_prefix() {
    local tag="$1"
    local color="$2"
    local logfile="$3"
    # awk prepends "COLOR[TAG] RESET " to every line, then tee saves it
    awk -v tag="$tag" -v col="$color" -v rst="${C_RST}" \
        '{ print col "[" tag "] " rst $0; fflush() }' \
    | tee -a "$logfile"
}

# ── 5. FastAPI backend ────────────────────────────────────────────────────────
step "Starting FastAPI backend"
{
    "$UVICORN_EXE" app.main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --reload \
        --log-level info \
        2>&1
} | _prefix "API " "$COL_API" "$LOG_DIR/fastapi.log" &
FASTAPI_PID=$!
ok "FastAPI launched (PID $FASTAPI_PID) → http://localhost:8000"

# Wait briefly for FastAPI to bind
sleep 2
if "$PYTHON_EXE" -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://localhost:8000/health', timeout=3)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
    ok "FastAPI health check passed ✓"
else
    warn "FastAPI didn't respond yet — check log output above"
fi

# ── 6. Celery worker + beat ───────────────────────────────────────────────────
if [ "$REDIS_OK" = "1" ]; then
    step "Starting Celery worker"
    {
        "$CELERY_EXE" -A app.workers.celery_app.celery_app worker \
            --loglevel=info \
            --concurrency=2 \
            2>&1
    } | _prefix "WRK " "$COL_WRK" "$LOG_DIR/celery_worker.log" &
    WORKER_PID=$!
    ok "Celery worker launched (PID $WORKER_PID)"

    step "Starting Celery beat scheduler"
    {
        "$CELERY_EXE" -A app.workers.celery_app.celery_app beat \
            --loglevel=info \
            2>&1
    } | _prefix "BEAT" "$COL_BEA" "$LOG_DIR/celery_beat.log" &
    BEAT_PID=$!
    ok "Celery beat launched (PID $BEAT_PID)"
else
    warn "Celery worker and beat skipped (Redis unavailable)"
    warn "Scans will run synchronously via POST /scans/{id}/scan/sync"
    WORKER_PID=""
    BEAT_PID=""
fi

# ── 7. Frontend (Vite) ────────────────────────────────────────────────────────
if [ -f "$FRONTEND_DIR/package.json" ]; then
    step "Starting Vite frontend"
    if [ ! -d "$FRONTEND_DIR/node_modules" ]; then
        info "Installing frontend npm packages …"
        npm install --prefix "$FRONTEND_DIR" --silent
    fi
    cd "$FRONTEND_DIR"
    {
        npm run dev 2>&1
    } | _prefix "WEB " "$COL_WEB" "$LOG_DIR/frontend.log" &
    FRONTEND_PID=$!
    cd "$BACKEND_DIR"
    ok "Frontend launched (PID $FRONTEND_PID) → http://localhost:5173"
else
    FRONTEND_PID=""
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf "\n"
printf "${C_BOLD}${C_BLU}╔══════════════════════════════════════════════════════════╗${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${C_BOLD}MetaSight is running${C_RST}                                    ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}╠══════════════════════════════════════════════════════════╣${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${COL_API}[API ]${C_RST}  Backend  →  ${C_BOLD}http://localhost:8000${C_RST}           ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${COL_API}[API ]${C_RST}  API Docs →  ${C_BOLD}http://localhost:8000/docs${C_RST}      ${C_BOLD}${C_BLU}║${C_RST}\n"
if [ -n "$FRONTEND_PID" ]; then
printf "${C_BOLD}${C_BLU}║${C_RST}  ${COL_WEB}[WEB ]${C_RST}  Frontend →  ${C_BOLD}http://localhost:5173${C_RST}           ${C_BOLD}${C_BLU}║${C_RST}\n"
fi
if [ "$REDIS_OK" = "1" ]; then
printf "${C_BOLD}${C_BLU}║${C_RST}  ${COL_WRK}[WRK ]${C_RST}  Celery   →  worker (concurrency=2) + beat     ${C_BOLD}${C_BLU}║${C_RST}\n"
else
printf "${C_BOLD}${C_BLU}║${C_RST}  ${C_YLW}[WRK ]${C_RST}  Celery   →  ${C_YLW}NOT started (Redis unavailable)${C_RST}  ${C_BOLD}${C_BLU}║${C_RST}\n"
fi
printf "${C_BOLD}${C_BLU}╠══════════════════════════════════════════════════════════╣${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  Logs  →  %s                     ${C_BOLD}${C_BLU}║${C_RST}\n" "$LOG_DIR"
printf "${C_BOLD}${C_BLU}║${C_RST}    ${C_DIM}fastapi.log  celery_worker.log  celery_beat.log${C_RST}  ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}    ${C_DIM}metasight.log  (rotating, all services combined)${C_RST}  ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}╠══════════════════════════════════════════════════════════╣${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${C_DIM}Log prefixes:  ${COL_API}[API ]${C_RST}${C_DIM} FastAPI   ${COL_WRK}[WRK ]${C_RST}${C_DIM} Celery worker ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}║${C_RST}  ${C_DIM}               ${COL_BEA}[BEAT]${C_RST}${C_DIM} Scheduler ${COL_WEB}[WEB ]${C_RST}${C_DIM} Vite frontend ${C_BOLD}${C_BLU}║${C_RST}\n"
printf "${C_BOLD}${C_BLU}╚══════════════════════════════════════════════════════════╝${C_RST}\n"
printf "\n"
printf "  ${C_DIM}Press${C_RST} ${C_BOLD}Ctrl+C${C_RST} ${C_DIM}to stop all services${C_RST}\n\n"

# ── Wait and handle Ctrl+C cleanly ───────────────────────────────────────────
_cleanup() {
    printf "\n\n${C_YLW}Stopping all MetaSight services …${C_RST}\n"
    kill "$FASTAPI_PID" ${WORKER_PID:-} ${BEAT_PID:-} ${FRONTEND_PID:-} 2>/dev/null || true
    # Kill any stray child processes from the prefix pipelines
    pkill -P $$ 2>/dev/null || true
    printf "${C_GRN}All services stopped. Goodbye.${C_RST}\n\n"
    exit 0
}
trap _cleanup INT TERM

wait "$FASTAPI_PID"
