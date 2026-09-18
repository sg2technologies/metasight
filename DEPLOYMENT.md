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

## 13. MetaSight Gateway (Enterprise) — primary enforcement path

This is the **mandatory** inline-enforcement path: a real PostgreSQL wire-protocol proxy
applications, users, and BI/ETL tools connect through with their normal Postgres driver or `psql`
— **no application code change required**, unlike section 14's SDK. Every query is guarded/
rewritten by the same `app/rewriters/sql_rewriter.py` / `app/services/policy_engine.py` pipeline
that protects `/query/execute` and the SDK, via `POST /gateway/prepare`
(`metasight_enterprise/services/prepare.py` — the one shared implementation both the gateway and
the SDK call, so policy logic never lives twice). Requires `metasight_enterprise` and the separate
`enterprise/gateway/` Go module.

For this to actually be the enforcement boundary, **the target database must not be reachable
directly** — firewall it so only the gateway host can connect (see the network topology note
below). A gateway that clients can simply route around isn't an enforcement point, just a slower
optional path.

**Current scope — read before deploying:**

- **PostgreSQL only.** MySQL/MSSQL/MongoDB adapters follow the same pattern (protocol-specific
  listener + the same shared `prepare()`/masking approach) but aren't built yet. **Oracle is an
  explicitly separate, unscoped research item** — its wire protocol (TNS/Net8) has no open
  server-side reference implementation anywhere, and reverse-engineering it raises real licensing
  questions this document can't resolve; don't treat it as "coming soon."
- **Simple Query protocol only.** Covers `psql`, most BI/reporting tools, and drivers in their
  default client-side-parameter-binding mode. **Extended Query (prepared statements) is rejected
  cleanly** — the client gets a normal Postgres error and the connection stays usable, but many
  ORMs and drivers that use Extended Query unconditionally (e.g. `asyncpg`) will not work through
  the gateway yet.
- **Masking, not tokenization**, for tokenize-marked columns — same deliberate tradeoff as the SDK;
  no async-safe tokenization path in the streaming hot path yet.
- No Cancel Request support, no HA/load-balancing/multi-instance policy caching this pass — a
  single gateway instance is a single point of failure for every connection routed through it;
  plan accordingly (see "Network topology" below) or wait for that fast-follow.
- `application_name` and client IP are captured from the wire protocol and available to
  `/gateway/prepare`/`/gateway/audit`, but are not yet `PolicyEngine` decision inputs, and are not
  yet persisted as their own `AuditLog` columns (a Community core-schema change, out of scope here)
  — they're logged, not silently dropped, but not queryable from the audit UI yet.

**1. Build the gateway binary** (Go 1.22+ toolchain):

```bash
cd enterprise/gateway
go build -o dist/metasight-gateway ./cmd/gateway
```

**2. Generate a credential for each application/user/tool that should connect through the
gateway**, via `POST /gateway/credentials` (admin-only; see
`enterprise/metasight_enterprise/api/gateway.py`). The response's `secret` field is shown exactly
once. Unlike the SDK's credential, this one is scoped to exactly one `DataSource` — a wire listener
naturally maps one username to one target database.

**3. TLS is mandatory** — same as the Go agent's own TLS posture, the gateway refuses any client
that doesn't send `SSLRequest` before `StartupMessage`. For a dev/staging cert:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout gateway.crt -out gateway.key -days 365 \
  -subj "/CN=metasight-gateway.example.com"
```

**4. Configure and start the service:**

```bash
# /etc/metasight/gateway.env
GATEWAY_HOST=0.0.0.0
GATEWAY_PORT=6543
GATEWAY_TLS_CERT=/etc/metasight/gateway.crt
GATEWAY_TLS_KEY=/etc/metasight/gateway.key
GATEWAY_API_BASE_URL=http://127.0.0.1:8000
GATEWAY_INTERNAL_API_KEY=<a freshly generated secret — also set as GATEWAY_INTERNAL_API_KEY in
                            /etc/metasight/backend.env so metasight-api.service can verify it>
```

```bash
sudo cp deploy/systemd/metasight-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now metasight-gateway
journalctl -u metasight-gateway -f
```

**5. Network topology — the part that makes this an actual enforcement boundary.** The gateway
calls two backend surfaces with very different trust levels: `/gateway/prepare`/`/gateway/audit`
(routine, one per query) and `GET /gateway/backend-credentials` (returns the **real, plaintext**
target-database password — must be reachable *only* from the gateway host, never from anywhere
else). And the target database itself must be firewalled so *only* the gateway's own host/IP can
reach it — otherwise a client can simply bypass the gateway and connect directly, and none of this
is actually an enforcement point:

```
Applications / users / BI tools ──(Postgres protocol, TLS)──▶ MetaSight Gateway
                                                                       │
                                          (X-Internal-Key, internal-only) │ (real DB creds)
                                                                       ▼
                                                              Target PostgreSQL
                                                       (security group: ALLOW gateway only,
                                                        DENY everything else)
```

**6. Point clients at it** like any other Postgres connection — the gateway's host/port, the
issued `gateway_username`/secret as the DB user/password, `sslmode=require` (or stronger). Revoke
or rotate a credential any time via `POST /gateway/credentials/{id}/revoke` or `/rotate-secret` —
takes effect **immediately**, even on an already-open connection (the next query on that connection
is rejected), not just on the next new connection.

## 14. MetaSight SDK (Enterprise) — fallback for apps that can't sit behind the gateway

**Use this only when section 13's gateway genuinely isn't an option** — e.g. the target engine has
no gateway adapter yet (Oracle, MySQL, MongoDB), or the client can't be network-routed through a
gateway host at all. An application imports the `metasight_sdk` Python package and wraps its own DB
connection/cursor with it, instead of connecting through a proxy. Every query is guarded/rewritten
by the same `app/rewriters/sql_rewriter.py` / `app/services/policy_engine.py` pipeline (via the
same shared `metasight_enterprise/services/prepare.py` the gateway calls), but executes with the
*application's own real driver* (psycopg2, oracledb, pymysql, pymssql, pymongo, ...) — no wire
protocol is reimplemented, so this works for engines no gateway adapter covers yet. The tradeoff:
this requires an application code change (import the wrapper) and, unlike the gateway, there is
nothing stopping that same application from bypassing MetaSight entirely if the code change is ever
reverted — it is not a genuine enforcement boundary the way a firewalled gateway is. Requires
`metasight_enterprise` (see `enterprise/metasight_enterprise/api/sdk.py`) and the separate
`enterprise/sdk/` package.

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

## 15. Log rotation

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

## 16. Backups

- **Database**: `pg_dump` on a schedule, stored off-host/off-site. This is the system of record
  for everything — policies, audit logs, PAM access requests/privileges.
- **Secrets**: back up `/etc/metasight/backend.env` encrypted (e.g. via your secrets manager),
  separately from the DB dump.
- **Screenshots/evidence**: back up `SCREENSHOT_STORAGE_DIR` per your evidence-retention policy.

## 17. Upgrading

```bash
cd /opt/metasight/backend
sudo -u metasight git pull   # or deploy new code
sudo -u metasight venv/bin/pip install -r requirements.txt
sudo -u metasight venv/bin/alembic upgrade head
sudo systemctl restart metasight-worker metasight-beat metasight-api metasight-gateway
cd ../frontend && npm ci && VITE_API_URL=https://metasight.example.com npm run build
sudo cp -r dist/* /opt/metasight/frontend/dist/
```

## 18. Production hardening checklist

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
- [ ] If deploying the MetaSight Gateway (section 13): the target database's security group/
      firewall allows connections **only** from the gateway host — otherwise clients can bypass
      the gateway entirely and it isn't a real enforcement boundary. `GET /gateway/backend-
      credentials` (returns real DB passwords) is reachable only from the gateway host, never
      publicly. Confirmed the target application actually uses Simple Query protocol (no
      server-side prepared statements) — the gateway does not support Extended Query yet. Real TLS
      certificates are in place (not the quick self-signed dev cert from section 13's example).
- [ ] If distributing the MetaSight SDK (section 14, fallback only): each application's API key is
      stored in that application's own secret store, not committed to source control. Confirmed the
      target application's DB driver actually returns the fields your policies expect from
      `cursor.description` (column names) — the SDK masks by name, matching what
      `/sdk/prepare` returned.
