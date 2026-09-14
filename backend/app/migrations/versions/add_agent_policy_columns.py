"""add policy columns to agent_registrations

Revision ID: add_agent_policy_cols
Revises: missing_core_tables_001
Create Date: 2026-06-17

Adds live access-control policy fields to agent_registrations:
  allowed_ips, allowed_users, blocked_ops, block_mode,
  alert_on_bypass, agent_ip, config_pulled_at

Re-pointed to follow missing_core_tables_001 (was 906d47f6ced3 directly) —
that migration is what actually creates agent_registrations; see its
docstring. Nothing in this file's upgrade()/downgrade() changed.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'add_agent_policy_cols'
down_revision: Union[str, None] = 'missing_core_tables_001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on:    Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('agent_registrations', sa.Column('allowed_ips',      sa.JSON(),    nullable=True))
    op.add_column('agent_registrations', sa.Column('allowed_users',    sa.JSON(),    nullable=True))
    op.add_column('agent_registrations', sa.Column('blocked_ops',      sa.JSON(),    nullable=True))
    op.add_column('agent_registrations', sa.Column('block_mode',       sa.Boolean(), nullable=True))
    op.add_column('agent_registrations', sa.Column('alert_on_bypass',  sa.Boolean(), nullable=True))
    op.add_column('agent_registrations', sa.Column('agent_ip',         sa.String(),  nullable=True))
    op.add_column('agent_registrations', sa.Column('config_pulled_at', sa.DateTime(timezone=True), nullable=True))

    # Back-fill existing rows with safe defaults
    op.execute("""
        UPDATE agent_registrations SET
            allowed_ips     = '[]'::json,
            allowed_users   = '["metasight_gateway"]'::json,
            blocked_ops     = '["DROP","TRUNCATE","GRANT","REVOKE"]'::json,
            block_mode      = false,
            alert_on_bypass = true
        WHERE allowed_ips IS NULL
    """)


def downgrade() -> None:
    op.drop_column('agent_registrations', 'config_pulled_at')
    op.drop_column('agent_registrations', 'agent_ip')
    op.drop_column('agent_registrations', 'alert_on_bypass')
    op.drop_column('agent_registrations', 'block_mode')
    op.drop_column('agent_registrations', 'blocked_ops')
    op.drop_column('agent_registrations', 'allowed_users')
    op.drop_column('agent_registrations', 'allowed_ips')
