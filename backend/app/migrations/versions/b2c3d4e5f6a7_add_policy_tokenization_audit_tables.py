"""add policy tokenization audit tables and column classifications

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-26 10:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add classification fields to columns table
    op.add_column('columns', sa.Column('pii_type', sa.String(), nullable=True))
    op.add_column('columns', sa.Column('classification', sa.String(), nullable=True))
    op.add_column('columns', sa.Column('action', sa.String(), nullable=True))

    # policy_rules
    op.create_table(
        'policy_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('resource', sa.String(), nullable=False),
        sa.Column('classification', sa.String(), nullable=False, server_default='PUBLIC'),
        sa.Column('source_type', sa.String(), nullable=False, server_default='postgres'),
        sa.Column('column_policies', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('row_filters', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('resource', 'tenant_id', name='_policy_resource_tenant_uc'),
    )
    op.create_index(op.f('ix_policy_rules_id'), 'policy_rules', ['id'], unique=False)

    # token_vault
    op.create_table(
        'token_vault',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('encrypted_value', sa.String(), nullable=False),
        sa.Column('column_name', sa.String(), nullable=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )
    op.create_index(op.f('ix_token_vault_id'), 'token_vault', ['id'], unique=False)
    op.create_index(op.f('ix_token_vault_token'), 'token_vault', ['token'], unique=True)

    # audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('resource', sa.String(), nullable=False),
        sa.Column('action', sa.String(), nullable=False, server_default='query'),
        sa.Column('original_query', sa.String(), nullable=True),
        sa.Column('rewritten_query', sa.String(), nullable=True),
        sa.Column('policy_applied', sa.String(), nullable=True),
        sa.Column('row_count', sa.Integer(), nullable=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('token_vault')
    op.drop_table('policy_rules')
    op.drop_column('columns', 'action')
    op.drop_column('columns', 'classification')
    op.drop_column('columns', 'pii_type')
