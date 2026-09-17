# MetaSight — Bare-Metal / VM Deployment Guide

MetaSight is a Database Activity Monitoring (DAM) + Privileged Access Management (PAM) platform:
a FastAPI backend, a Celery worker + beat scheduler, a React frontend, a Postgres database, Redis,
and a Go agent that runs on (or near) each monitored database.

**Community vs Enterprise**: this repo (`backend/`, `frontend/`) is the Community edition —
catalog, PII discovery, masking/tokenization/RLS, the policy engine, and native/agentless DAM
polling. Full PAM (access requests/JIT, session recording, endpoint screen/clipboard/USB
monitoring, correlation, evidence, risk analytics, compliance reporting) lives in the separate
`enterprise/` directory and is optional — a Community-only install simply never registers the
`/pam/*` routes or the PAM nav section, no flag to flip. See `enterprise/README.md`. This guide
covers Community; where a step differs for Enterprise it says so explicitly.

This guide deploys the whole stack on a single Linux host under systemd — no Docker required for
the application tier (matches the target chosen for this deployment). Before following it, read
[`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) — several critical fixes described there are already
applied in this codebase, and a few items are deliberately left as an operational/organizational
checklist rather than a code change (e.g. PAM screen/clipboard capture consent).

## Architecture

```
                    ┌────────────┐
   Internet ──TLS──▶│   nginx    │── static files ──▶ frontend/dist (React SPA)
                    │ (reverse   │
                    │  proxy)    │── /auth,/pam,... ──▶ 127.0.0.1:8000
                    └────────────┘                           │
                                                      ┌───────┴────────┐
                                                      │  metasight-api │ (gunicorn + uvicorn workers)
                                                      └───────┬────────┘
                                          ┌────────────────────┼────────────────────┐
                                          ▼                    ▼                    ▼
                                   ┌─────────────┐     ┌──────────────┐     ┌───────────────┐
                                   │  PostgreSQL │     │    Redis     │     │ metasight-     │
                                   │ (app state) │     │ (Celery      │     │ worker/beat    │
                                   │             │     │  broker +    │     │ (scan ingest,  │
                                   │             │     │  rate-limit) │     │ PAM auto-      │
                                   └─────────────┘     └──────────────┘     │ revoke, DAM    │
                                                                            │ polling)       │
                                                                            └───────┬────────┘
                                                                                    │
                                                                     ┌──────────────┴──────────────┐
                                                                     ▼                              ▼
                                                          Monitored DB #1                 Monitored DB #2, ...
                                                       (Go agent via install.sh,
                                                        systemd, on/near the DB host)
```

## 1. Prerequisites

On the target host (Ubuntu/Debian shown; adjust package manager for RHEL/Amazon Linux):

```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv postgresql redis-server nginx git \
    build-essential libpq-dev nodejs npm certbot python3-certbot-nginx
```

Also needed once, on whichever machine builds the Go agent (can be the same host, or your CI):
a Go 1.22+ toolchain — see step 7.

## 2. Create the service user and directory layout

```bash
sudo useradd --system --create-home --home-dir /opt/metasight --shell /usr/sbin/nologin metasight
sudo mkdir -p /opt/metasight/backend/logs /opt/metasight/backend/data/screenshots /etc/metasight
sudo chown -R metasight:metasight /opt/metasight
```

## 3. Deploy the code

```bash
sudo -u metasight git clone <your-repo-url> /opt/metasight/src   # or rsync a release tarball
sudo -u metasight cp -r /opt/metasight/src/backend  /opt/metasight/backend-new
sudo -u metasight cp -r /opt/metasight/src/frontend /opt/metasight/frontend-new
# atomically swap into place (skip on first install)
```

For a first install, simplest is to place `backend/` at `/opt/metasight/backend` and build the
frontend into `/opt/metasight/frontend/dist` directly (steps below).

## 4. Backend: virtualenv + dependencies

```bash
cd /opt/metasight/backend
sudo -u metasight python3.11 -m venv venv
sudo -u metasight venv/bin/pip install --upgrade pip
sudo -u metasight venv/bin/pip install -r requirements.txt
```

`requirements.txt` is version-pinned (captured via `pip freeze` from a known-working environment)
for reproducible installs — don't relax the pins without deliberately re-testing.

## 5. Configure environment

```bash
sudo cp backend/.env.production.example /etc/metasight/backend.env
sudo chown metasight:metasight /etc/metasight/backend.env
sudo chmod 600 /etc/metasight/backend.env
sudo -u metasight nano /etc/metasight/backend.env   # fill in every CHANGE_ME
```

Generate secrets:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # JWT_SECRET_KEY, SETUP_SECRET
python3 -c "import secrets; print(secrets.token_hex(16))"   # ENCRYPTION_KEY
```

Never reuse a developer's local `backend/.env` values in production — generate fresh secrets for
every environment.

## 6. PostgreSQL

```bash
sudo -u postgres psql -c "CREATE USER metasight WITH PASSWORD 'the-password-you-put-in-env';"
sudo -u postgres psql -c "CREATE DATABASE metasight OWNER metasight;"
```

Run migrations (schema is exclusively Alembic's responsibility now — the app no longer calls
`Base.metadata.create_all()` at startup):

```bash
cd /opt/metasight/backend
sudo -u metasight venv/bin/alembic upgrade head
```

**Adding Enterprise to an existing Community install?** Community enforces exactly one tenant per
deployment with a DB-level guard (a unique index that makes a second `tenants` row impossible,
`community_single_tenant_guard` migration) — this is intentional, not a bug, and matches Community
having no tenant-management UI/API at all (that capability is Enterprise-only,
`metasight_enterprise.superadmin_tenants`). Once `enterprise/` is checked out alongside this repo,
its migration chain includes a merge migration that drops that guard automatically — but you must
run `alembic upgrade heads` (**plural**), not `alembic upgrade head`, since Enterprise's migrations
add a second branch:

```bash
sudo -u metasight venv/bin/alembic upgrade heads
```

Skipping this (or running plain `alembic upgrade head`, which only advances one arbitrary branch)
will leave the single-tenant guard in place, and `POST /superadmin/tenants` will fail with a DB
integrity error the moment you try to create a second tenant.

## 7. Redis

Either use the system package (`redis-server`, already installed above and running by default),
or the provided `docker-compose.yml` at the repo root if you prefer containerized infra:

```bash
docker compose up -d redis
```

Either way, make sure `REDIS_BROKER_URL` in `/etc/metasight/backend.env` points at it.

## 8. Install systemd units

```bash
sudo cp deploy/systemd/metasight-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now metasight-api metasight-worker metasight-beat
sudo systemctl status metasight-api metasight-worker metasight-beat
```

**Run exactly one `metasight-beat` instance cluster-wide.** It's the sole scheduler for PAM JIT
auto-revoke (expired `SUPERUSER`/`DBA`-level grants get revoked here — see
`app/workers/tasks.py:revoke_expired_pam_privileges`) and for native DAM polling. A second
concurrently-running beat instance double-schedules every periodic task; Celery beat itself isn't
active-active safe.

Tail logs while verifying:

```bash
journalctl -u metasight-api -f
journalctl -u metasight-beat -f
tail -f /opt/metasight/backend/logs/*.log
```

## 9. One-time bootstrap (create the first tenant + admin)

```bash
curl -X POST https://metasight.example.com/auth/setup \
  -H "X-Setup-Secret: <the SETUP_SECRET you put in the env file>" \
  -H "Content-Type: application/json" \
  -d '{"tenant_name": "Acme Corp", "admin_email": "admin@acme.example", "admin_password": "..."}'
```

This endpoint is permanently disabled the moment any user exists in the database — safe to leave
reachable, but you can also firewall it off after first use if you prefer belt-and-suspenders.

## 10. Frontend build

```bash
cd frontend
npm ci
VITE_API_URL=https://metasight.example.com npm run build
sudo mkdir -p /opt/metasight/frontend/dist
sudo cp -r dist/* /opt/metasight/frontend/dist/
sudo chown -R www-data:www-data /opt/metasight/frontend/dist
```

`VITE_API_URL` is baked into the built JS bundle at build time — if you omit it, the bundle
silently falls back to `http://localhost:8000`, which will not work in production. Rebuild and
redeploy the frontend any time this needs to change.

**Deploying Enterprise instead?** Run `enterprise/frontend/build.sh` instead of the `npm` commands
above — it overlays the PAM pages/nav onto this same Community source before building, then apply
`VITE_API_URL` and the rest of these steps to its `enterprise/frontend/.build/dist` output rather
than `frontend/dist`. See `enterprise/frontend/README.md`.

## 11. nginx + TLS

```bash
sudo cp deploy/nginx/metasight.conf /etc/nginx/sites-available/metasight
# edit server_name and TLS cert paths for your domain
sudo ln -s /etc/nginx/sites-available/metasight /etc/nginx/sites-enabled/
sudo nginx -t
sudo certbot --nginx -d metasight.example.com    # obtains + wires up TLS certs
sudo systemctl reload nginx
```

## 12. Go agent — build and roll out to monitored databases

This is the **DB-mode agent** (`--mode db`) — Community edition, watches sessions on/near a
monitored database. The **PAM endpoint agent** (screen/clipboard/USB monitoring on a user's own
workstation) is a separate binary built from `enterprise/agent/` (Enterprise-only) — see
`enterprise/agent/Makefile` and `enterprise/README.md`. The two no longer share a binary or even a
Go module; building one has no effect on the other.

Build once (needs a Go 1.22+ toolchain):

```bash
cd backend/agent
make linux      # produces dist/metasight-agent-linux-amd64 and -arm64
make build-aix  # produces dist/metasight-agent-aix-ppc64 — Oracle EBS/AIX DB tiers etc.
```

> Deploying to an **Oracle E-Business Suite database tier on AIX**? See the dedicated,
> step-by-step [`DEPLOYMENT-ORACLE-EBS-AIX.md`](DEPLOYMENT-ORACLE-EBS-AIX.md) — AIX has no
> systemd, no Oracle Instant Client requirement (the agent's pure-Go driver is thin-mode-only
> already), and the frontend's Install Agent wizard has an AIX tab that generates the right
> commands for it.

The built binaries are served by the API at `GET /downloads/metasight-agent-linux-{amd64,arm64}`
and `GET /downloads/metasight-agent-aix-ppc64`.
On each host that needs to monitor a database directly (i.e. outside MetaSight's own query
gateway), register an agent in MetaSight → Settings → Agents to get an API key, then run:

```bash
curl -sSL https://metasight.example.com/downloads/install-agent.sh | \
  MS_SERVER=https://metasight.example.com \
  MS_API_KEY=<key-from-agents-page> \
  MS_DB_TYPE=postgres \
  MS_DB_HOST=localhost \
  MS_DB_USER=metasight_monitor \
  MS_DB_PASSWORD=... \
  MS_DB_NAME=yourdb \
  bash
```

Set `MS_SERVER` to `https://...` — see the **Production hardening checklist** below for why this
matters. This installs a systemd unit (`metasight-agent`) on that host.

For direct-DB-access enforcement to actually mean something, grant the monitoring account
**only** the read privileges it needs (`SELECT` on `pg_stat_activity` / `v$session` / etc.), not
broad DBA rights — `isBlockedOp`'s keyword matching is a best-effort tripwire, not a security
boundary (see `SECURITY_AUDIT.md`).

## 13. MetaSight SDK (Enterprise)

This is the inline-enforcement counterpart to section 12's Go agent, using a different mechanism
than a network proxy: instead of monitoring direct-DB-access sessions after the fact, an
application imports the `metasight_sdk` Python package and wraps its own DB connection/cursor with
it. Every query is guarded/rewritten by the same `app/rewriters/sql_rewriter.py` /
`app/services/policy_engine.py` pipeline that already protects `/query/execute`, but executes with
the *application's own real driver* (psycopg2, oracledb, pymysql, pymssql, pymongo, ...) —
no wire protocol is reimplemented, so this works for engines a network proxy realistically
cannot (Oracle's TNS/Net8 protocol is proprietary; the SDK approach sidesteps that entirely since
the driver, not MetaSight, speaks it). Requires `metasight_enterprise` (see
`enterprise/metasight_enterprise/api/sdk.py`) and the separate `enterprise/sdk/` package.

**Current scope — read before deploying:**

- **Python only.** Java/Node/Go equivalents aren't built yet.
- **SQL (any DBAPI2-compliant driver) + MongoDB.** The SQL wrapper is generic — it works with
  whatever `.execute()`/`.fetchall()`/`.description` cursor the app already has (Postgres, Oracle,
  MySQL, MSSQL, ...); only Postgres has been exercised end-to-end so far.
- **Masking, not tokenization, for tokenize-marked columns** — same deliberate MVP tradeoff as the
  rest of this product's masking pipeline; there is no client-side-safe tokenization path yet.
- **Policy decisions require a live MetaSight API call per query** (`POST /sdk/prepare`) — the SDK
  fails closed on a MetaSight outage (raises `MetaSightGatewayError`), it never silently falls back
  to executing the original, unrewritten query.
- `.aggregate()` on a Mongo collection gets the policy decision (deny/mask) but does not rewrite
  the pipeline itself — only `.find()` gets row-filter injection.

**1. Publish/distribute `enterprise/sdk/`** to wherever your applications install Python packages
from (this is Enterprise, so the same private-distribution model as the Go agent binaries applies
— see `enterprise/README.md`):

```bash
cd enterprise/sdk
python -m build   # or: pip install -e . for local development against a real app
```

**2. Generate an API key for each application**, via `POST /sdk/credentials` (admin-only; see
`enterprise/metasight_enterprise/api/sdk.py`). The response's `api_key` field is shown exactly
once — store it in the application's own secret store, the same as any other credential. This key
is **not** scoped to one `DataSource` — an application can query several sources with one key;
per-table/per-source authorization is handled by the existing `PolicyEngine` department/table
checks, the same as it would for a JWT-authenticated human user.

**3. In the application**, wrap the existing DB connection/cursor:

```python
import psycopg2
from metasight_sdk import MetaSightClient

client = MetaSightClient(api_key="msdk_...", base_url="https://metasight.example.com")
conn = psycopg2.connect(...)                          # the app's own connection, own credentials
cursor = client.wrap_cursor(conn.cursor(), source_id=42)
cursor.execute("SELECT id, ssn FROM employees")        # guarded + rewritten server-side
rows = cursor.fetchall()                                 # masked locally, never touches the server
```

For MongoDB: `client.wrap_mongo_collection(real_collection, source_id=...)`, then use `.find()`/
`.aggregate()` as normal.

Revoke or rotate a key any time via `POST /sdk/credentials/{id}/revoke` or `/rotate-secret` — takes
effect on the application's next query (a `MetaSightPolicyDenied`/401 is raised, not a silent
bypass to the unwrapped connection).

## 14. Log rotation

```
# /etc/logrotate.d/metasight
/opt/metasight/backend/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## 15. Backups

- **Database**: `pg_dump` on a schedule, stored off-host/off-site. This is the system of record
  for everything — policies, audit logs, PAM access requests/privileges.
- **Secrets**: back up `/etc/metasight/backend.env` encrypted (e.g. via your secrets manager),
  separately from the DB dump.
- **Screenshots/evidence**: back up `SCREENSHOT_STORAGE_DIR` per your evidence-retention policy.

## 16. Upgrading

```bash
cd /opt/metasight/backend
sudo -u metasight git pull   # or deploy new code
sudo -u metasight venv/bin/pip install -r requirements.txt
sudo -u metasight venv/bin/alembic upgrade head
sudo systemctl restart metasight-worker metasight-beat metasight-api
cd ../frontend && npm ci && VITE_API_URL=https://metasight.example.com npm run build
sudo cp -r dist/* /opt/metasight/frontend/dist/
```

## 17. Production hardening checklist

Go through this before exposing the deployment to real users/data — it maps to the findings in
[`SECURITY_AUDIT.md`](SECURITY_AUDIT.md):

- [ ] Every secret in `/etc/metasight/backend.env` is freshly generated, not copied from a dev `.env`.
- [ ] `CORS_ORIGINS` is your actual frontend origin(s), not `["*"]` (check the API's startup log
      for the warning if unsure).
- [ ] `ENV=production` is set (disables `/docs`, `/redoc`, `/openapi.json`).
- [ ] `MS_SERVER` for every deployed Go agent is `https://...`, not `http://...` — the agent logs
      a warning at startup if it isn't, but nothing blocks it from running over plaintext.
- [ ] `--db-sslmode`/`MS_DB_SSLMODE` is set to `require` or `verify-full` for every agent
      wherever the target database supports TLS (default is `disable`, kept for backward
      compatibility with databases that don't have TLS configured).
- [ ] The DB accounts agents/gateway connect with hold the minimum privilege needed — the
      Oracle/Postgres session-kill enforcement path requires `ALTER SYSTEM` /
      `pg_signal_backend` respectively; don't grant more than that.
- [ ] Vault is either left unconfigured (uses the built-in AES-256-GCM `encrypted_config`
      storage) or is a real, non-dev-mode Vault cluster — the `docker-compose.yml` Vault service
      is dev-mode (in-memory, root token) and must never back production credentials.
- [ ] **Before enabling PAM screen/clipboard capture** (`--record-screen`/`--record-clipboard`,
      on by default in PAM agent mode): confirm legal/compliance sign-off and that affected users
      are notified through an out-of-band mechanism (login banner, employee agreement, etc.).
      The agent logs a one-line notice at startup, but that is not a consent mechanism — no code
      change can substitute for the organizational controls this requires, and requirements vary
      significantly by jurisdiction.
- [ ] `DEFAULT_UNCLASSIFIED_POLICY=deny` (the default) unless you have a specific, time-boxed
      reason to run permissively while backfilling scans/policies.
- [ ] Firewall Postgres/Redis to loopback + the app hosts only; nginx is the only thing that
      should be internet-facing.
- [ ] If distributing the MetaSight SDK (section 13): each application's API key is stored in that
      application's own secret store, not committed to source control. Confirmed the target
      application's DB driver actually returns the fields your policies expect from
      `cursor.description` (column names) — the SDK masks by name, matching what
      `/sdk/prepare` returned.
