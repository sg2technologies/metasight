# MetaSight

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Data-centric privileged access security — self-hosted, entirely inside your own environment.**

MetaSight secures privileged access to sensitive data: it catalogs what you have, finds the PII in it, masks and tokenizes it in flight, enforces row-level access, and keeps an audit trail of who touched what — including Oracle EBS/AIX and other legacy-heavy enterprise estates at 10,000+ table scale. Nothing is SaaS; every edition runs entirely inside your own environment.

This repository is the **Community edition**: the full data catalog, PII discovery, masking/tokenization, query gateway, native DB activity monitoring, and security-posture engine — the same components every MetaSight deployment is built on. It's licensed under Apache 2.0: use it, modify it, self-host it, or build on it, commercially or not — see [License](#license) below.

---

## Features

- **Data catalog** across 25+ SQL/warehouse engines plus MongoDB, Cassandra, Elasticsearch/OpenSearch, DynamoDB, Redis, S3, and Oracle ERP, with automatic fallback to an OpenMetadata ingestion workflow for the long tail of BI/pipeline/ML-catalog connectors
- **PII discovery** — pattern-based column classification across the catalog
- **Masking & tokenization** — role-based masking for email, phone, SSN, credit card, name, address, IP, DOB, government ID, and more; reversible tokenization where you need it back
- **Query gateway (HTTP API)** — SQL rewriting that injects masking and row-level security, blocks and flags risky queries, and routes CRITICAL-risk queries through an approval workflow
- **MetaSight Gateway (wire protocol)** — a transparent PostgreSQL/MySQL proxy applications and BI tools connect through with their normal driver, `psql`, or `mysql` client — **no code change required**; every query gets the same masking/RLS/policy enforcement as the HTTP gateway above, inline
- **Rule-based risk scoring** on every query (denied/masked/tokenized columns, join depth, row filters) — transparent thresholds, not a black box
- **Native, agentless DB activity monitoring (DAM)** — passive polling against the source database, no agent required
- **DB-mode agent** for database-session interception, with binary downloads and self-install scripts built in
- **Security posture checks** — per-source privilege audits, hardening guides, and in-database hardening you can apply directly
- **Audit trail & governance center** across every data change and privileged action, with a downloadable compliance summary export
- **Single sign-on (OIDC) & two-factor authentication (TOTP)** — admin-configurable from Settings, no redeploy required
- **SIEM & chat alerting** — Slack, Microsoft Teams, or a generic structured-JSON webhook for any SIEM ingestion endpoint
- **Role-based access control** with department-scoped policies, plus maker-checker approval on high-risk queries
- **Admin console** — users, departments, and organization-wide settings for your deployment

## Installation

**Requirements:** Docker + Docker Compose. That's it — Postgres, Redis, Vault, the backend, and the frontend all run as containers; nothing else to install locally.

```bash
cp .env.example .env      # fill in real secrets — see the comments in the file; never commit .env
docker compose up -d --build
```

- **Frontend**: http://localhost:3000
- **Backend / API**: http://localhost:8000
- **MetaSight Gateway** (PostgreSQL wire-protocol proxy, MySQL also supported): `localhost:6543` — connect with `psql` or any compatible driver once you've created a gateway credential (admin nav → Gateway Credentials, or `POST /gateway/credentials`); the `gateway` container generates its own self-signed dev TLS cert on first start. Enable the MySQL listener alongside it by setting `GATEWAY_MYSQL_PORT` in `docker-compose.yml`.
- Migrations run automatically on first boot (the `backend` container runs `alembic upgrade head` before starting).
- One-time bootstrap (create the first tenant + admin), same as the production flow in [DEPLOYMENT.md](DEPLOYMENT.md):

  ```bash
  curl -X POST http://localhost:8000/auth/setup \
    -H "X-Setup-Secret: <the SETUP_SECRET you put in .env>" \
    -H "Content-Type: application/json" \
    -d '{"tenant_name": "Acme Corp", "admin_email": "admin@acme.example", "admin_password": "..."}'
  ```

This is the dev/local path. For a hardened bare-metal/VM production install (systemd units, gunicorn, nginx/TLS, the Go agent, backups, upgrades, hardening checklist — doesn't use `docker-compose.yml` at all), see [DEPLOYMENT.md](DEPLOYMENT.md). Deploying against Oracle EBS/AIX specifically: [DEPLOYMENT-ORACLE-EBS-AIX.md](DEPLOYMENT-ORACLE-EBS-AIX.md).

## Testing a deployment

Once the stack is up (either path above) and bootstrap has run, verify it's actually working:

```bash
# 1. Containers healthy / API responding
curl http://localhost:8000/health

# 2. Full end-to-end smoke test — walks every core endpoint (auth, data sources,
#    catalog scan, policies, query gateway, audit trail) against a running instance
cd backend
pip install -r requirements.txt   # only needed outside the docker container
python scripts/test_endpoints.py
```

`test_endpoints.py` reads `API_BASE_URL` and `SETUP_SECRET` from `.env`; it prompts for admin
credentials if `TEST_ADMIN_EMAIL` / `TEST_ADMIN_PASSWORD` aren't set. It prints PASS/FAIL per
endpoint, so a clean run is a good signal the deployment (or a change to `backend/app/`) hasn't
broken anything before you rely on it.

## Project layout

```
backend/     FastAPI (Python) — the API, scanners, policy/masking engine
frontend/    React 19 + Vite
```

Stack: FastAPI + PostgreSQL (metadata store) + Redis/Celery (async scan jobs) + React/Vite. HashiCorp Vault is optional for secrets; encrypted credential storage is the default.

## Security & privacy

- Self-hosted only, in both editions — no SaaS option, no data ever leaves your environment by default.
- Credentials are AES-256 encrypted at rest; HashiCorp Vault is a drop-in option.
- The audit trail and governance center run entirely against your own database — see [Audit trail & governance center](#features) above.
- Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a public issue for it.

## Enterprise edition

**MetaSight Enterprise** builds on this same Community engine with full privileged access management (PAM), broader database coverage, and compliance-grade reporting — for organizations that need the whole package under one roof.

Enterprise is a **separate, proprietary product**, privately distributed — a paid, self-hosted upgrade with the same "runs entirely inside your environment" model as Community, never SaaS (see [License](#license) below).

**What Enterprise adds:**

- **Access requests & just-in-time privilege** — request → approve → time-boxed grant → automatic revoke, with maker-checker enforced on every approval
- **Session recording & replay** — workstation screenshots and full session evidence, correlated across systems for a single timeline of "who did what, when"
- **Endpoint agent** — screen, clipboard, and USB monitoring, beyond Community's database-session-level agent
- **Behavioral risk analytics** — session and privilege-level risk scoring that builds on Community's query-level rules
- **Compliance framework reporting** — SOX, PCI-DSS, ISO 27001, GDPR, and DPDP reports mapped to real controls, backed by the same audit data Community already collects
- **Full multi-tenant administration** — run many tenants from one deployment, with a dedicated superadmin console
- **Broader database engine coverage** — Oracle and additional engines via the MetaSight SDK, for applications that can't sit behind a network gateway

**→ [metasight.pro](https://metasight.pro/)**

## Support

Community edition is free to self-host — no license, no account, no entitlement check. **SG2 Technologies** also offers commercial support contracts for Community deployments, in addition to Enterprise licensing, if you want a vendor on the hook rather than going it alone.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contact

**info@sg2technologies.com**

## License

Copyright © 2026 SG2 Technologies.

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify, and redistribute this code — including commercially — under the terms of that license.

This applies to everything in this repository: `backend/` and `frontend/`. MetaSight Enterprise (access requests/JIT, session recording, correlation, evidence, compliance reporting, and related tooling) is separate, proprietary software licensed by SG2 Technologies, and is not part of this repository — see [Enterprise edition](#enterprise-edition) above.

## Author

**Gopi Narayanaswamy** — [github.com/ngopi37](https://github.com/ngopi37) · [gopinarayanaswamy.consulting](https://gopinarayanaswamy.consulting/)
