"""Missing column: scan_runs.progress

Revision ID: scan_runs_progress_001
Revises: add_agent_policy_cols
Create Date: 2026-09-14

Same root cause as missing_core_tables_001 (see that file's docstring) —
found by running a systematic diff of every ORM model's columns against a
live, fully-migrated database (inspect(engine) vs Base.metadata), not just
by hitting it in the UI. ScanRun.progress (app/models/models.py) has never
had a migration: the initial migration's scan_runs table predates this
column, and nothing since added it. Triggering a scan against a fresh
Community database crashed with `UndefinedColumn: scan_runs.progress does
not exist` the moment SQLAlchemy tried to read the row back after insert.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'scan_runs_progress_001'
down_revision: Union[str, None] = 'add_agent_policy_cols'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scan_runs', sa.Column('progress', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_runs', 'progress')
