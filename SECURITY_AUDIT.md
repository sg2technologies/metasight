# MetaSight — Security & Correctness Audit

Findings from a full audit of the DAM/PAM enforcement logic, backend deploy-readiness, and the Go
agent, done ahead of packaging this for a real deployment (see [`DEPLOYMENT.md`](DEPLOYMENT.md)).
Status is marked **Fixed** (code changed, verified), **Mitigated** (materially improved, residual
risk documented), or **Backlog** (documented, deliberately not changed this pass — with why).

## Critical

| # | Finding | Status | Notes |
|---|---|---|---|
| 1 | `SELECT ... INTO table` bypassed the SELECT-only query gateway — sqlglot re-serializes it as `CREATE TABLE ... AS SELECT`, materializing an **unmasked** copy of denied/masked data server-side. | **Fixed** | Rejected at both `app/rewriters/sql_rewriter.py` (`_guard_sql`, also now always invoked on the legacy single-table path which previously skipped it entirely) and `app/core/query_engine.py:_validate_select` (the actual execution-time gate). Verified with `sqlglot.exp.Into` detection tests. |
| 2 | Mongo query path only stripped `deny`-policy fields when the *client's own* `projection` happened to exclude them; omitting `projection` (the common case) returned denied fields raw. | **Fixed** | `app/api/query.py` now strips `denied_col_keys` from every returned row server-side, unconditionally, independent of connector type or client-supplied projection — mirrors how masking is already enforced post-fetch. |
| 3 | Policy engine allowed full, unmasked access with **no audit warning** whenever a resource had no explicit rule and hadn't been scanned yet (new/unclassified tables wide open by default). | **Fixed** | `app/services/policy_engine.py` now denies by default for unclassified resources; `DEFAULT_UNCLASSIFIED_POLICY` setting (`config.py`) is an explicit, documented escape hatch back to the old permissive behavior. Always logs a WARNING either way. |
| 4 | PAM JIT grant/revoke built SQL via naive `str.format()` of a free-text, user-supplied `db_username` into `GRANT`/`ALTER ROLE` templates — SQL injection executed with DBA-level target credentials, triggered by an ordinary access-request approval. | **Fixed** | Strict identifier allowlist (`^[A-Za-z_][A-Za-z0-9_$]{0,127}$`) enforced in both the `AccessRequestCreate` pydantic validator (`app/api/pam_access_requests.py`) and defense-in-depth inside `app/services/pam_jit.py:grant_privilege`. |
| 5 | Auto-revoke of expired elevated privileges ran only as an in-process, in-memory APScheduler job started by the FastAPI app — dies with the web process, duplicates across gunicorn workers. | **Fixed** | Moved to a Celery Beat periodic task (`app/workers/tasks.py:revoke_expired_pam_privileges`), always scheduled. `deploy/systemd/metasight-beat.service` runs it as a single, independently-supervised (`Restart=always`) process. Residual risk: still a single point of failure if beat itself is down and unattended — documented in the deploy checklist; true HA would need a distributed scheduler, out of scope here. |
| 6 | Super-admin login compared the plaintext env-var password with `==` (timing side-channel) and completely bypassed the account-lockout counter used for normal logins. | **Fixed** | `app/api/auth.py` now uses `secrets.compare_digest` for both email and password, and routes through the same `_is_locked_out`/`_record_attempt` mechanism as normal login. |
| 7 | `database.py` silently fell back to a local, per-process SQLite file if Postgres was unreachable at import time — reproduced live during this audit. | **Fixed** | Fallback removed entirely; connection failures now propagate and crash the process so systemd surfaces the failure instead of silently forking application state. Added explicit pool sizing (`pool_size=10, max_overflow=20, pool_recycle=1800`). |
| 8 | `SETUP_SECRET` header check used `!=` instead of constant-time comparison. | **Fixed** | `secrets.compare_digest` in `app/api/auth.py`. |

## High

| # | Finding | Status | Notes |
|---|---|---|---|
| 9 | `app/main.py` startup ran `Base.metadata.create_all` + ad hoc `ALTER TABLE` on every process boot alongside Alembic — schema drift, racy concurrent DDL across gunicorn workers. | **Fixed** | Removed. Schema changes are exclusively `alembic upgrade head`, run as an explicit `ExecStartPre` deploy step (`deploy/systemd/metasight-api.service`). |
| 10 | `requirements.txt` had essentially no version pins — non-reproducible installs. | **Fixed** | Pinned to exact versions captured via `pip freeze` from a known-working environment. Added the previously-missing `gunicorn` (needed for the systemd deploy). Removed `apscheduler` (no longer used after #5). |
| 11 | Dev/scratch artifacts committed with real hardcoded credentials (`debug_db.py`, `scratch/reset_password.py` with a real-looking email+password, 35+ other ad hoc DB-mutating scripts, `metasight.db`, `celerybeat-schedule.*`, a dead duplicate `backend/alembic/` tree, stray `agent.exe`/`agent.exe~`, an unused 143MB `backend/agent/gomodcache/`). | **Fixed** | All removed. Root `.gitignore` added so they don't come back once this becomes a git repo. |
| 12 | `agent_runner.py` hardcoded a fallback password (`"Admin@1234"`), hardcoded `http://localhost:8000`, and only knew how to spawn a Windows `.exe` — silently unusable on Linux. | **Fixed** | Fallback password removed (raises a clear error instead); server URL now reads `AGENT_CALLBACK_URL` (config.py); spawn path now raises a clear, actionable error on non-Windows hosts pointing at `install.sh`/systemd instead of silently failing. |
| 13 | Go agent's `isBlockedOp` was a bare `strings.HasPrefix` keyword match — bypassed by a leading comment, `BEGIN…`/`DO $$…` wrapping, or a stacked statement. | **Mitigated** | Now strips leading comments/whitespace/semicolons before matching (`stripLeadingNoise` in `main.go`), closing the simplest bypass. Wrapped/stacked-statement bypasses remain — this is a keyword heuristic, not a SQL parser, and is documented in-code and in `DEPLOYMENT.md` as a tripwire, not a security boundary; real enforcement for a direct-DB-access threat model belongs at the database grant level. |
| 14 | Go agent's DB monitoring connections defaulted to `sslmode=disable`; the backend↔agent reporter had no retry/backoff (events silently dropped on any outage). | **Mitigated** | Added `--db-sslmode`/`MS_DB_SSLMODE` flag (postgres: `disable`\|`require`\|`verify-full`; mysql: mapped to the driver's `tls=` modes) — default kept at `disable` for backward compatibility with installs whose DB side has no TLS configured; set to `require`/`verify-full` in production (see deploy checklist). Reporter now retries transient failures (network errors, 5xx) up to 3 attempts with exponential backoff before dropping — still no durable on-disk queue for outages longer than a few seconds, which is out of scope for this pass. Also: agent now logs a startup WARNING if `MS_SERVER` is `http://`. |
| 15 | `policy_cache.py` deserialized with `pickle` from Redis — unnecessary deserialization-RCE surface for a security product. | **Fixed** | Switched to `json` (`PolicyDecision` is a plain dataclass of primitives; round-trips via `dataclasses.asdict`/`**kwargs`). |
| 16 | `encryption.py` used AES-CFB with no authentication tag — ciphertext malleable, bit-flips silently corrupt decrypted plaintext. | **Fixed** | Moved to AES-256-GCM for all new encryption, with a 4-byte magic-prefix version marker (`MSG1`) so existing v1 (CFB) ciphertexts already in the database keep decrypting correctly; they transparently upgrade to v2 the next time that DataSource's config is saved. |
| 17 | Auto-approval of low-risk access requests updated status to `APPROVED` but never actually called `grant_privilege` — audit-trail integrity bug (dead `background_tasks` parameter). | **Fixed** | `app/api/pam_access_requests.py`'s auto-approve path now calls `grant_privilege` after commit, mirroring the pattern already used in the manual `approve_request` endpoint. |
| 18 | CORS defaulted to `["*"]` + `allow_credentials=True` (Starlette treats this as "any origin, with credentials"); `/docs`/`/redoc`/`/openapi.json` exposed unconditionally. | **Mitigated** | `ENV=production` (new setting, defaults to `production`) now disables `/docs`/`/redoc`/`/openapi.json`. `CORS_ORIGINS` still defaults to `["*"]` for local-dev convenience, but the app now logs a startup WARNING when it's left that way — operators must still set it explicitly per environment (documented in the hardening checklist). |
| 19 | No SQLAlchemy pool sizing for multi-process production (gunicorn workers + celery worker + beat all hitting one Postgres). | **Fixed** | Explicit `pool_size`, `max_overflow`, `pool_timeout`, `pool_recycle` in `app/core/database.py`. |
| 20 | slowapi rate limiting used in-memory storage — the "10/minute" login limit became effectively `10 × N` under N gunicorn workers. | **Fixed** | Both `Limiter(...)` instances (`app/api/auth.py`, `app/main.py`) now use `storage_uri=settings.REDIS_BROKER_URL`. |

## Backlog (documented, not code-fixed this pass)

| Finding | Why deferred |
|---|---|
| `AgentRegistration.api_key` stored in plaintext in the primary DB. | Fixing this properly means a show-once-then-hash rework of the agent-registration UX (like a GitHub PAT), not a one-line change; a DB compromise already implies broader exposure. Recommend for a follow-up pass. |
| `security_checker.py`'s MySQL grants heuristic can be fooled by a `SHOW GRANTS` row that happens to mention `information_schema`. | This is an advisory posture-scoring tool, not an enforcement control — a false negative here doesn't bypass any actual data-access protection. |
| PAM screen/clipboard capture has no in-app consent/notice UI, and is on by default in PAM agent mode. | Not fixable in code alone — this needs organizational controls (login banner, employee notice, legal/compliance sign-off) that vary by jurisdiction. Added a one-time startup log notice (`main_pam.go`) as a minimal signal, and made this the first item in `DEPLOYMENT.md`'s hardening checklist. Do not enable `--record-screen`/`--record-clipboard` in production before that sign-off exists. |
| Full SQL parsing for the Go agent's blocked-ops detection (vs. the improved-but-still-heuristic keyword match). | The correct fix for the threat model (users connecting directly to a DB, bypassing MetaSight's gateway) is restricting what the database itself lets that account do, not a smarter client-side keyword matcher — documented in `DEPLOYMENT.md` and in-code. |
| No durable on-disk queue in the Go agent's reporter for outages longer than the new retry window (~3s). | Would need a real persistent queue (spool file + replay) to not lose events across longer outages; scoped out of this pass, noted as a residual gap under finding #14 above. |

## Strengths confirmed during the audit (not changed)

- SQL rewriter's bottom-up recursive rewriting correctly defeats the classic bypasses it's
  designed against (CTE/UNION column-leak via aliasing, scalar-subquery leakage, LATERAL joins) —
  hand-traced against the canonical bypasses in its own docstring.
- PolicyEngine's *error* path (exceptions during evaluation) is fail-closed (500), distinct from
  the fail-open *business-logic* path fixed above (#3) — a genuine strength, not misrepresented.
- Argon2id password hashing (`app/core/security.py`), consistent constant-time verification via
  passlib.
- Consistent `X-Agent-Key` enforcement across every agent-facing ingestion endpoint
  (`pam_agent_events.py`, `pam_agents.py`), with 256-bit random API keys.
- AES-GCM (and, before this pass, AES-CFB) credential encryption always used a fresh random
  IV/nonce per record — no ECB, no IV reuse.
- Go agent's HTTP client never disables TLS certificate verification (no `InsecureSkipVerify`
  anywhere) — the plaintext-by-default issue was about the *scheme* operators choose, not broken
  validation when HTTPS is used.
- Native DAM polling (`dam_native_poller.py`) isolates failures per-source (one bad connection
  doesn't abort the whole poll cycle) and uses a watermark with overlap window to avoid gap-loss.
