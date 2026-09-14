# MetaSight Editions — Community vs Enterprise

This document is the single source of truth for what ships in **Community**
(free, self-hosted, this repository) versus **Enterprise** (paid, self-hosted,
private `enterprise/` distribution). It exists so the boundary is explicit and
auditable in one place, not scattered across code comments.

Status: verified 2026-09-14 — see "How this was verified" below.

## Model: code presence, not a license key

There is no feature-flag or entitlement-check layer. The boundary is **"is
the `metasight_enterprise` package installed next to this backend, and is
the Enterprise frontend overlay built in."** Community deployments that never
install `enterprise/` simply don't have the routes, tables, Celery beat
tasks, or UI — there's nothing to unlock and nothing to bypass.

- **Backend seam**: every Enterprise touchpoint in `backend/app/` is behind
  `try: import metasight_enterprise / except ImportError`. See
  `backend/app/main.py` (route registration), `backend/app/workers/celery_app.py`
  (PAM auto-revoke beat schedule), `backend/app/migrations/env.py` (PAM model
  registration for Alembic autogenerate). A handful of best-effort
  cross-references (`backend/app/api/query.py`, `backend/app/api/agents.py`,
  `backend/app/services/dam_native_poller.py`) wrap the optional import in a
  broad `except Exception` and degrade silently — e.g. a blocked-query
  screenshot trigger just doesn't fire if Enterprise isn't installed.
- **Frontend seam**: `frontend/src/plugins/pam/index.ts` is a Community stub
  (`navItems: []`, `routes: []`). `App.tsx`/`Layout.tsx` render from that
  registry and never import an Enterprise page directly. Enterprise's build
  overlays the same file path with the real one (11 pages). A production
  Community build was checked this session — the compiled bundle contains no
  PAM business logic, only inert label strings (`"PAM Endpoint"` as an agent
  type option) and one best-effort fetch to `/pam/sessions/*/screenshots`
  that resolves to an empty list on 404.
- **Shared table, split by data**: `AgentRegistration` is one table used by
  both editions' agents, distinguished by a `"pam:"` `db_type` prefix —
  Community's DB-mode agent registration/management lives at `/agents`
  (`backend/app/api/agents.py`); Enterprise's PAM-endpoint agent (screen/
  clipboard/USB monitoring) lives at `/pam/agents`.
- **Migrations**: two Alembic branches rooted at the same revision.
  Community's chain ends at `add_agent_policy_cols`; Enterprise's `pam`
  branch (`pam_001_full_schema → pam_002_jit`) lives in
  `enterprise/metasight_enterprise/migrations/versions/`. Community-only
  deployments run `alembic upgrade head`; combined deployments run
  `alembic upgrade heads` (plural).

## Feature matrix

| Area | Community (Free) | Enterprise (Paid) |
|---|---|---|
| **Data catalog** | Full: multi-source schema/table/column catalog, paginated + searched server-side, lazy column loading, department tagging (`app/api/departments.py`, `Catalog.tsx`) | — (same catalog, PAM adds correlation on top) |
| **PII discovery** | Full: pattern-based column classification, PII-only filter, `Discovery.tsx` | — |
| **Data masking** | Full: role-based masking levels, per-type maskers (email, phone, SSN, credit card, name, address, IP, DOB, government ID, amount, account, secret, location — `app/services/masking.py`) | — |
| **Tokenization** | Full: reversible tokenization service (`app/services/tokenization.py`) | — |
| **Row-level security** | Full: PostgreSQL RLS policy generation (`app/services/pg_rls.py`), policy engine with per-column allow/mask/deny/tokenize decisions (`app/services/policy_engine.py`) | — |
| **Query gateway** | Full: SQL rewriting, masking/RLS injection, blocked-query enforcement, approval workflow for CRITICAL-risk queries (`app/api/query.py`, `app/api/approvals.py`, `Query.tsx`, `BlockedCommands.tsx`) | — |
| **Risk scoring** | Full: rule-based query risk score + level (LOW/MEDIUM/HIGH/CRITICAL) from denied/masked/tokenized columns, join depth, row filters (`app/services/risk_scorer.py`) — deliberately **not** marketed as AI; it's rules + thresholds | Enterprise has its own PAM session/privilege risk scorer (`metasight_enterprise/services/pam_risk.py`) — a different, session-level risk model, not a paywalled version of this one |
| **Native/agentless DAM** | Full: passive activity polling and sensitive-object tracking against the source DB itself, no agent required (`app/models/dam.py`, `app/services/dam_native_poller.py`) | Full **PAM** on top: access requests, JIT privilege grants, session policy, session recording, correlation, evidence capture, compliance reporting (`enterprise/metasight_enterprise/`) |
| **DB-mode agent** | Full: register/manage the Go agent for database-session interception (`app/api/agents.py`, mounted at `/agents`; agent binary downloads at `app/api/downloads.py`) | PAM-endpoint-mode agent (screen/clipboard/USB monitoring) at `/pam/agents` |
| **Security posture** | Full: per-source privilege checks, hardening guides, in-database hardening, webhook alerts (`app/services/security_checker.py`, `app/api/security.py`, `Security.tsx`) | — |
| **Audit trail** | Full: data-change and privileged-activity logging, governance audit center (`app/services/governance_audit.py`, `app/api/audit.py`, `AuditLog.tsx`, `GovernanceAuditCenter.tsx`) | Adds session screenshots/recordings and cross-session correlation as enrichment on top of the same audit views |
| **Connectors** | Full: native fast-path scanning for 25+ SQL/warehouse engines (`app/ingestion/native_scanner.py`) + NoSQL/object-store scanning for MongoDB, Cassandra, Elasticsearch/OpenSearch, DynamoDB, Redis, S3, Oracle ERP (`app/ingestion/nosql_scanner.py`), with automatic fallback to the OpenMetadata ingestion workflow for the long tail of BI/pipeline/ML-catalog connectors | — |
| **Multi-tenant admin** | Full: tenant/user management, superadmin console, department management (`app/api/superadmin.py`, `app/api/users.py`, `app/api/departments.py`, `SuperAdmin.tsx`, `Users.tsx`) | — |
| **Secrets** | Full: encrypted credential storage by default; optional HashiCorp Vault integration, status surfaced in Settings (`app/core/vault_client.py`, `app/api/settings.py`) | — |
| **Access requests / JIT** | — | Full: request → approve → time-boxed privilege grant → auto-revoke sweep (`metasight_enterprise/services/pam_jit.py`, Celery beat) |
| **Session recording & evidence** | — | Full: workstation screenshots, session correlation, evidence packaging for audits (`metasight_enterprise/api/pam_sessions.py`, `pam_evidence.py`, `pam_correlation.py`) |
| **Compliance reporting** | — | Full: `metasight_enterprise/api/pam_compliance.py` |

## What "Community" does not mean

- Not a time-boxed trial and not artificially crippled — every row marked
  "Full" above is the complete implementation, not a teaser.
- Not SaaS in either edition — both run entirely inside the operator's own
  environment; Enterprise is a paid *self-hosted* upgrade, not a hosted tier.
- Community has no dependency on Enterprise. Enterprise depends on Community
  (`enterprise/pyproject.toml` installs against this backend), never the
  reverse.

## How this was verified (2026-09-14)

- `npx tsc --noEmit` on `frontend/` — clean.
- `npx vite build` on `frontend/` (Community, no Enterprise overlay) —
  succeeds; bundle grepped for PAM business logic (access requests, session
  recording, JIT, correlation) — none present, only the two documented
  best-effort touchpoints described above.
- Every `metasight_enterprise` import site in `backend/app/` inspected by
  hand — each is inside a `try/except ImportError` (or a wider
  `except Exception` around a best-effort side-effect), so Community boots
  and runs with `enterprise/` completely absent.
- Swept `backend/app` and `frontend/src` for `TODO`/`FIXME`/`NotImplementedError`/
  stub markers — the only `NotImplementedError`s are the intentional
  connector-coverage fallback in `native_scanner.py`/`nosql_scanner.py` (caught
  by `app/workers/tasks.py` to fall back to the OpenMetadata workflow), not
  incomplete Community features.
- Not done this session (out of scope by request): booting both editions
  against a live Postgres end-to-end. Static verification only — see
  the memory note this extends for that outstanding item.

## Where to look next

If a future change adds a new cross-edition touchpoint, follow the existing
pattern: guard the import, degrade to "feature absent" rather than erroring,
and add a row to the table above in the same PR.
