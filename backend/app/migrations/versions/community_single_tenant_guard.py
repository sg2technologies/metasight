"""Community edition: enforce at most one tenant row

Revision ID: community_single_tenant_guard
Revises: scan_runs_progress_001
Create Date: 2026-09-16

Community edition is single-tenant (the tenant-CRUD API now lives exclusively
in metasight_enterprise.superadmin_tenants — see app/main.py, which no longer
registers any /superadmin/tenants route at all for a Community build). This
migration backs that up with a hard DB-level guarantee rather than relying on
route removal alone: a partial unique index on a constant expression means
every row in `tenants` collides on the same index key, so a second INSERT
fails with IntegrityError regardless of which code path attempts it (a raw
SQL script, a future bug, a restored backup with stray data, etc).

Enterprise deployments are multi-tenant and must drop this index — see the
DROP INDEX step at the start of the Enterprise `pam_001_full_schema`
migration chain, and the Community→Enterprise upgrade note in DEPLOYMENT.md.
"""
from typing import Sequence, Union
from alembic import op

revision: str = 'community_single_tenant_guard'
down_revision: Union[str, None] = 'scan_runs_progress_001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS tenants_single_row_guard ON tenants ((1))"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS tenants_single_row_guard")
