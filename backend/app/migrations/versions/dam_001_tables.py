"""Community DAM tables — DBActivity, SensitiveObject, DamPollWatermark

Revision ID: dam_001_tables
Revises: 0446e2c417eb
Create Date: 2026-09-12

These three tables back native/agentless DAM polling (app/services/
dam_native_poller.py) and are Community-edition, unlike the rest of the PAM
platform (see the sibling 'pam' branch rooted at the same parent revision,
0446e2c417eb, which lives in the Enterprise package).

pam_db_activities and pam_sensitive_objects were previously created inline
inside pam_001_full_schema (Enterprise's migration) before the Community/
Enterprise split — moved here unchanged. pam_dam_poll_watermarks never had
a migration of its own even though the ORM model (DamPollWatermark) already
existed; native DAM polling would fail the first time it ran against a
freshly-migrated database. Added here.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'dam_001_tables'
down_revision: Union[str, None] = '0446e2c417eb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.create_table('pam_db_activities',
        sa.Column('id',             sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id',      sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('session_id',     sa.String(128), nullable=True),  # PAMSession.id when Enterprise is installed — no FK, see app/models/dam.py
        sa.Column('data_source_id', sa.Integer(), sa.ForeignKey('data_sources.id'), nullable=True),
        sa.Column('agent_name',     sa.String(256), nullable=False),
        sa.Column('db_type',        sa.String(64),  nullable=False),
        sa.Column('db_user',        sa.String(256), nullable=False),
        sa.Column('os_user',        sa.String(256), nullable=True),
        sa.Column('client_ip',      sa.String(64),  nullable=True),
        sa.Column('client_host',    sa.String(256), nullable=True),
        sa.Column('client_app',     sa.String(256), nullable=True),
        sa.Column('db_name',        sa.String(256), nullable=True),
        sa.Column('schema_name',    sa.String(256), nullable=True),
        sa.Column('object_name',    sa.String(256), nullable=True),
        sa.Column('operation',      sa.String(32),  nullable=False),
        sa.Column('sql_text',       sa.Text(), nullable=True),
        sa.Column('sql_hash',       sa.String(64),  nullable=True),
        sa.Column('rows_affected',  sa.BigInteger(), nullable=True),
        sa.Column('exec_time_ms',   sa.Integer(), nullable=True),
        sa.Column('status',         sa.String(32), server_default='SUCCESS'),
        sa.Column('error_msg',      sa.Text(), nullable=True),
        sa.Column('occurred_at',    sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('risk_score',     sa.Float(), server_default='0'),
        sa.Column('risk_flags',     postgresql.ARRAY(sa.String()), server_default='{}'),
        sa.Column('sensitivity',    sa.String(32), nullable=True),
        sa.Column('session_pid',    sa.String(64),  nullable=True),
    )
    op.create_index('ix_pam_da_tenant',  'pam_db_activities', ['tenant_id'])
    op.create_index('ix_pam_da_session', 'pam_db_activities', ['session_id'])
    op.create_index('ix_pam_da_user',    'pam_db_activities', ['db_user'])
    op.create_index('ix_pam_da_time',    'pam_db_activities', ['occurred_at'])

    op.create_table('pam_sensitive_objects',
        sa.Column('id',          sa.Integer(), primary_key=True),
        sa.Column('tenant_id',   sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('db_type',     sa.String(64),  nullable=False),
        sa.Column('schema_name', sa.String(256), nullable=True),
        sa.Column('object_name', sa.String(256), nullable=False),
        sa.Column('sensitivity', sa.String(32), server_default='CONFIDENTIAL'),
        sa.Column('tags',        postgresql.ARRAY(sa.String()), server_default='{}'),
        sa.Column('created_at',  sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint('tenant_id', 'db_type', 'schema_name', 'object_name', name='_sensitive_obj_uc'),
    )

    op.create_table('pam_dam_poll_watermarks',
        sa.Column('id',             sa.Integer(), primary_key=True),
        sa.Column('data_source_id', sa.Integer(), sa.ForeignKey('data_sources.id'), nullable=False),
        sa.Column('last_polled_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_event_key', sa.String(256), nullable=True),
        sa.UniqueConstraint('data_source_id', name='_dam_poll_watermark_ds_uc'),
    )


def downgrade() -> None:
    op.drop_table('pam_dam_poll_watermarks')
    op.drop_table('pam_sensitive_objects')
    op.drop_table('pam_db_activities')
