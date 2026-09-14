"""add vault_path to data_sources

Revision ID: 906d47f6ced3
Revises: dam_001_tables
Create Date: 2026-06-17 19:48:21.286930

Rebased onto dam_001_tables (was pam_002_jit) when Community/Enterprise
migrations split into separate branches rooted at 0446e2c417eb — this is a
Community-only, core change (data_sources.vault_path) and has no business
depending on the Enterprise 'pam' branch to run.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '906d47f6ced3'
down_revision: Union[str, None] = 'dam_001_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('data_sources', sa.Column('vault_path', sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column('data_sources', 'vault_path')
