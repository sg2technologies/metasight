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
- **Query gateway** — SQL rewriting that injects masking and row-level security, blocks and flags risky queries, and routes CRITICAL-risk queries through an approval workflow
- **Rule-based risk scoring** on every query (denied/masked/tokenized columns, join depth, row filters) — not AI, just transparent thresholds
- **Native, agentless DB activity monitoring (DAM)** — passive polling against the source database, no agent required
- **DB-mode agent** for database-session interception, with binary downloads and self-install scripts built in
- **Security posture checks** — per-source privilege audits, hardening guides, and in-database hardening you can apply directly
- **Audit trail & governance center** across every data change and privileged action
- **Multi-tenant admin** — tenants, users, departments, a superadmin console

Full detail, with the exact files backing each item, is in [EDITIONS.md](EDITIONS.md).

## Installation

**Requirements:** Python 3.9+, Node.js 18+, PostgreSQL, Redis.

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

For a full bare-metal/VM production install (PostgreSQL, Redis, systemd units, nginx/TLS, the Go agent, backups, upgrades, hardening checklist), see [DEPLOYMENT.md](DEPLOYMENT.md). Deploying against Oracle EBS/AIX specifically: [DEPLOYMENT-ORACLE-EBS-AIX.md](DEPLOYMENT-ORACLE-EBS-AIX.md).

## Project layout

```
backend/     FastAPI (Python) — the API, scanners, policy/masking engine
frontend/    React 19 + Vite
enterprise/  Not in this repo — a separate private distribution that
             depends on this backend/frontend, never the reverse
```

Stack: FastAPI + PostgreSQL (metadata store) + Redis/Celery (async scan jobs) + React/Vite. HashiCorp Vault is optional for secrets; encrypted credential storage is the default.

## Security & privacy

- Self-hosted only, in both editions — no SaaS option, no data ever leaves your environment by default.
- Credentials are AES-256 encrypted at rest; HashiCorp Vault is a drop-in option.
- The audit trail and governance center run entirely against your own database — see [Audit trail & governance center](#features) above.
- Found a vulnerability? See [SECURITY.md](SECURITY.md) — please don't open a public issue for it.

## Enterprise edition

Need access requests with just-in-time privilege grants, session recording, cross-session correlation, an evidence repository for audits, or compliance reporting? **MetaSight Enterprise** builds on this same Community engine with full PAM (privileged access management).

Enterprise is a **separate, proprietary product**, privately distributed — its access-request/JIT workflow, session recording, correlation engine, evidence repository, and compliance reporting are not included in this repository (see [License](#license) below). It's a paid, self-hosted upgrade — same "runs entirely inside your environment" model as Community, never SaaS.

**What Enterprise adds:**

- **Access requests & JIT** — request → approve → time-boxed privilege grant → automatic revoke
- **Session recording & evidence** — workstation screenshots, cross-session correlation, evidence packaging for audits
- **Endpoint agent** — screen/clipboard/USB monitoring, beyond Community's DB-session-level agent
- **Compliance reporting** built on the same audit data Community already collects

The exact Community/Enterprise boundary — mapped to real files, not marketing copy — is in [EDITIONS.md](EDITIONS.md).

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
