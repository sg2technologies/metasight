# MetaSight

Data-centric privileged access security for the databases regulated and
legacy-heavy enterprises actually run — including Oracle EBS/AIX, at
10,000+ table scale.

MetaSight secures privileged access to sensitive data: it catalogs what you
have, finds the PII in it, masks and tokenizes it in flight, enforces
row-level access, and keeps an audit trail of who touched what — all
self-hosted, entirely inside your own environment.

This repository is **MetaSight Community** — free, open-source (Apache-2.0),
and a complete product on its own. See [EDITIONS.md](EDITIONS.md) for exactly
what's in Community versus the paid, privately-distributed **Enterprise**
edition (full PAM: access requests/JIT, session recording, correlation,
compliance reporting) — same "runs entirely inside your environment" model,
not SaaS.

## What's in Community

- **Data catalog** across 25+ SQL/warehouse engines plus MongoDB, Cassandra,
  Elasticsearch/OpenSearch, DynamoDB, Redis, S3, and Oracle ERP, with
  automatic fallback to an OpenMetadata ingestion workflow for the long tail
  of BI/pipeline/ML-catalog connectors.
- **PII discovery** — pattern-based column classification across the catalog.
- **Masking & tokenization** — role-based masking for email, phone, SSN,
  credit card, name, address, IP, DOB, government ID, and more; reversible
  tokenization where you need it back.
- **Query gateway** — SQL rewriting that injects masking and row-level
  security, blocks and flags risky queries, and routes CRITICAL-risk queries
  through an approval workflow.
- **Rule-based risk scoring** on every query (denied/masked/tokenized
  columns, join depth, row filters) — not AI, just transparent thresholds.
- **Native, agentless DB activity monitoring (DAM)** — passive polling
  against the source database, no agent required.
- **DB-mode agent** for database-session interception, with binary
  downloads and self-install scripts built in.
- **Security posture checks** — per-source privilege audits, hardening
  guides, and in-database hardening you can apply directly.
- **Audit trail & governance center** across every data change and
  privileged action.
- **Multi-tenant admin** — tenants, users, departments, a superadmin console.

Full detail, with the exact files backing each item, is in
[EDITIONS.md](EDITIONS.md).

## Architecture

```
metasight/
├── backend/     FastAPI (Python) — the API, scanners, policy/masking engine
├── frontend/    React 19 + Vite
└── enterprise/  Not in this repo — a separate private distribution that
                 depends on this backend/frontend, never the reverse
```

Stack: FastAPI + PostgreSQL (metadata store) + Redis/Celery (async scan
jobs) + React/Vite. HashiCorp Vault is optional for secrets; encrypted
credential storage is the default.

## Getting started

See [DEPLOYMENT.md](DEPLOYMENT.md) for a full bare-metal/VM install
(PostgreSQL, Redis, systemd units, nginx/TLS, the Go agent, backups,
upgrades, production hardening). If you're specifically deploying against
Oracle EBS/AIX, see
[DEPLOYMENT-ORACLE-EBS-AIX.md](DEPLOYMENT-ORACLE-EBS-AIX.md).

Quick local dev loop:

```bash
# Backend
cd backend
python -m venv venv && venv/Scripts/activate   # or `source venv/bin/activate` on Linux/macOS
pip install -r requirements.txt
cp .env.production.example .env                 # fill in your own secrets — never commit this file
alembic upgrade head
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

## Security

Found a vulnerability? Please see [SECURITY.md](SECURITY.md) — don't open a
public issue for it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
