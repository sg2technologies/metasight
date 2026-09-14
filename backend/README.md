# MetaSight Backend

FastAPI backend for MetaSight (Community edition) — self-hosted, multi-tenant
data catalog, PII discovery, masking/tokenization, and the query gateway.
See the repo root [README.md](../README.md) for what MetaSight is and
[EDITIONS.md](../EDITIONS.md) for the Community/Enterprise boundary. Not
SaaS — this runs entirely inside your own environment.

## Prerequisites
- Python 3.9+
- PostgreSQL
- Redis

## Setup

1. **Clone repo & install dependencies:**
   ```sh
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

2. **Set environment variables:**
   - Create a `.env` file in the root with:
     ```env
     POSTGRES_USER=postgres
     POSTGRES_PASSWORD=postgres
     POSTGRES_DB=metadata_db
     POSTGRES_HOST=localhost
     POSTGRES_PORT=5432
     JWT_SECRET_KEY=supersecret
     ENCRYPTION_KEY=32byteslongsecretkeymustbe32b!
     REDIS_BROKER_URL=redis://localhost:6379/0
     ```

3. **Run Alembic migrations:**
   ```sh
   alembic -c alembic.ini upgrade head
   ```

4. **Start FastAPI app:**
   ```sh
   uvicorn app.main:app --reload
   ```

5. **Start Celery worker:**
   ```sh
   celery -A app.workers.celery_app.celery_app worker --loglevel=info
   ```

## API Endpoints
- `POST /auth/login` — JWT login
- `POST /sources` — Register data source (encrypted config)
- `POST /sources/{id}/scan` — Trigger scan
- `GET /scans/{id}` — Scan status
- `GET /tables?tenant_id=...` — List tables

## Notes
- All credentials are AES-256 encrypted in DB.
- Only workers can decrypt credentials.
- All endpoints require JWT Bearer token.
- Native fast-path scanning covers 25+ SQL/warehouse engines plus MongoDB,
  Cassandra, Elasticsearch/OpenSearch, DynamoDB, Redis, S3, and Oracle ERP
  (see `app/ingestion/native_scanner.py` and `nosql_scanner.py`); anything
  else falls back to the OpenMetadata ingestion workflow.

---

For production deployment (systemd units, nginx, migrations, hardening checklist), see
[`DEPLOYMENT.md`](../DEPLOYMENT.md) at the repo root. See [`SECURITY_AUDIT.md`](../SECURITY_AUDIT.md)
for the security/correctness audit this deployment packaging was built on top of.
