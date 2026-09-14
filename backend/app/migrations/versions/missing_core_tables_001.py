"""Missing core tables: agent_registrations, security_events, data_change_audits,
privileged_activities, session_recordings, system_settings, login_attempts,
query_approvals, department_management

Revision ID: missing_core_tables_001
Revises: 906d47f6ced3
Create Date: 2026-09-14

Found running `alembic upgrade head` against a genuinely fresh database
(docker-compose.yml's postgres service) for the first time: these 9 tables
have existed as ORM models — some since the very first version of this
schema — but never had a migration of their own. `add_agent_policy_cols`
(the next migration in this chain) does `ALTER TABLE agent_registrations
ADD COLUMN ...` and crashed with `UndefinedTable` because nothing before it
ever created that table.

Same root cause as dam_001_tables.py's pam_dam_poll_watermarks fix: every
real deployment so far predates the app/main.py change that removed
`Base.metadata.create_all()` from server startup (see that file's
docstring) — these tables were always silently created that way, so the
gap was invisible until a deployment relied on Alembic alone for a
completely fresh database. Docker Compose's postgres service is exactly
that case.

Column definitions copied from app/models/models.py as of this date —
keep in sync if those models change before this migration is ever run
against a real database (i.e. don't edit this file after that; add a new
migration instead, same as any other schema change).
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'missing_core_tables_001'
down_revision: Union[str, None] = '906d47f6ced3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    op.create_table('agent_registrations',
        sa.Column('id',              sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id',       sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('name',            sa.String(), nullable=False),
        sa.Column('db_type',         sa.String(), nullable=False),
        sa.Column('source_id',       sa.Integer(), nullable=True),
        sa.Column('api_key',         sa.String(), nullable=False),
        sa.Column('last_seen',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('active_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at',      sa.DateTime(timezone=True), nullable=True),
        # NOT the allowed_ips/allowed_users/blocked_ops/... policy columns —
        # deliberately left out here so the very next migration,
        # add_agent_policy_cols, still does the job it always did (ALTER +
        # backfill existing rows), unmodified. This table just needs to
        # exist before that migration's ALTER TABLE runs.
    )
    op.create_index('ix_agent_registrations_api_key', 'agent_registrations', ['api_key'], unique=True)

    op.create_table('security_events',
        sa.Column('id',           sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id',    sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('agent_id',     sa.Integer(), sa.ForeignKey('agent_registrations.id'), nullable=False),
        sa.Column('source_id',    sa.Integer(), nullable=True),
        sa.Column('db_type',      sa.String(), nullable=False),
        sa.Column('session_pid',  sa.String(), nullable=True),
        sa.Column('db_user',      sa.String(), nullable=True),
        sa.Column('client_ip',    sa.String(), nullable=True),
        sa.Column('client_addr',  sa.String(), nullable=True),
        sa.Column('app_name',     sa.String(), nullable=True),
        sa.Column('database',     sa.String(), nullable=True),
        sa.Column('current_sql',  sa.String(), nullable=True),
        sa.Column('state',        sa.String(), nullable=True),
        sa.Column('blocked',      sa.Integer(), nullable=False, server_default='0'),
        sa.Column('acknowledged', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('timestamp',    sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table('data_change_audits',
        sa.Column('id',              sa.Integer(), primary_key=True, index=True),
        sa.Column('entity',          sa.String(), nullable=False),
        sa.Column('entity_id',       sa.String(), nullable=True),
        sa.Column('table_name',      sa.String(), nullable=True),
        sa.Column('record_pk',       sa.String(), nullable=True),
        sa.Column('column_name',     sa.String(), nullable=False),
        sa.Column('old_value',       sa.String(), nullable=True),
        sa.Column('new_value',       sa.String(), nullable=True),
        sa.Column('changed_by',      sa.String(), nullable=False),
        sa.Column('changed_role',    sa.String(), nullable=True),
        sa.Column('changed_at',      sa.DateTime(timezone=True), nullable=True),
        sa.Column('operation_type',  sa.String(), nullable=False, server_default='UPDATE'),
        sa.Column('approval_status', sa.String(), nullable=True, server_default='not_required'),
        sa.Column('approval_id',     sa.Integer(), nullable=True),
        sa.Column('source_type',     sa.String(), nullable=True),
        sa.Column('source_id',       sa.Integer(), nullable=True),
        sa.Column('session_id',      sa.String(), nullable=True),
        sa.Column('request_id',      sa.String(), nullable=True),
        sa.Column('metadata',        sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('tenant_id',       sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
    )
    op.create_index('ix_data_change_audits_entity', 'data_change_audits', ['entity'])
    op.create_index('ix_data_change_audits_entity_id', 'data_change_audits', ['entity_id'])
    op.create_index('ix_data_change_audits_table_name', 'data_change_audits', ['table_name'])
    op.create_index('ix_data_change_audits_record_pk', 'data_change_audits', ['record_pk'])
    op.create_index('ix_data_change_audits_column_name', 'data_change_audits', ['column_name'])
    op.create_index('ix_data_change_audits_changed_by', 'data_change_audits', ['changed_by'])
    op.create_index('ix_data_change_audits_changed_at', 'data_change_audits', ['changed_at'])
    op.create_index('ix_data_change_audits_operation_type', 'data_change_audits', ['operation_type'])
    op.create_index('ix_data_change_audits_session_id', 'data_change_audits', ['session_id'])
    op.create_index('ix_data_change_audits_tenant_id', 'data_change_audits', ['tenant_id'])

    op.create_table('privileged_activities',
        sa.Column('id',          sa.Integer(), primary_key=True, index=True),
        sa.Column('actor_email', sa.String(), nullable=False),
        sa.Column('actor_role',  sa.String(), nullable=False),
        sa.Column('action',      sa.String(), nullable=False),
        sa.Column('target_type', sa.String(), nullable=True),
        sa.Column('target_id',   sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('risk_level',  sa.String(), nullable=False, server_default='LOW'),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('session_id',  sa.String(), nullable=True),
        sa.Column('ip_address',  sa.String(), nullable=True),
        sa.Column('user_agent',  sa.String(), nullable=True),
        sa.Column('metadata',    sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('tenant_id',   sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
    )
    op.create_index('ix_privileged_activities_actor_email', 'privileged_activities', ['actor_email'])
    op.create_index('ix_privileged_activities_actor_role', 'privileged_activities', ['actor_role'])
    op.create_index('ix_privileged_activities_action', 'privileged_activities', ['action'])
    op.create_index('ix_privileged_activities_target_type', 'privileged_activities', ['target_type'])
    op.create_index('ix_privileged_activities_target_id', 'privileged_activities', ['target_id'])
    op.create_index('ix_privileged_activities_risk_level', 'privileged_activities', ['risk_level'])
    op.create_index('ix_privileged_activities_occurred_at', 'privileged_activities', ['occurred_at'])
    op.create_index('ix_privileged_activities_session_id', 'privileged_activities', ['session_id'])
    op.create_index('ix_privileged_activities_tenant_id', 'privileged_activities', ['tenant_id'])

    op.create_table('session_recordings',
        sa.Column('id',               sa.Integer(), primary_key=True, index=True),
        sa.Column('session_id',       sa.String(), nullable=False),
        sa.Column('user_email',       sa.String(), nullable=False),
        sa.Column('role',             sa.String(), nullable=False),
        sa.Column('replay_provider',  sa.String(), nullable=False, server_default='manual'),
        sa.Column('recording_url',    sa.String(), nullable=True),
        sa.Column('started_at',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('ended_at',         sa.DateTime(timezone=True), nullable=True),
        sa.Column('status',           sa.String(), nullable=False, server_default='active'),
        sa.Column('metadata',         sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('tenant_id',        sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.UniqueConstraint('session_id', 'tenant_id', name='_session_recording_tenant_uc'),
    )
    op.create_index('ix_session_recordings_session_id', 'session_recordings', ['session_id'])
    op.create_index('ix_session_recordings_user_email', 'session_recordings', ['user_email'])
    op.create_index('ix_session_recordings_role', 'session_recordings', ['role'])
    op.create_index('ix_session_recordings_started_at', 'session_recordings', ['started_at'])
    op.create_index('ix_session_recordings_status', 'session_recordings', ['status'])
    op.create_index('ix_session_recordings_tenant_id', 'session_recordings', ['tenant_id'])

    op.create_table('system_settings',
        sa.Column('id',         sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id',  sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('config',     sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_by', sa.String(), nullable=True),
        sa.UniqueConstraint('tenant_id'),
    )

    op.create_table('login_attempts',
        sa.Column('id',           sa.Integer(), primary_key=True, index=True),
        sa.Column('email',        sa.String(), nullable=False),
        sa.Column('ip_address',   sa.String(), nullable=True),
        sa.Column('success',      sa.Integer(), nullable=False, server_default='0'),
        sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_login_attempts_email', 'login_attempts', ['email'])

    op.create_table('query_approvals',
        sa.Column('id',               sa.Integer(), primary_key=True, index=True),
        sa.Column('tenant_id',        sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('requester_email',  sa.String(), nullable=False),
        sa.Column('requester_role',   sa.String(), nullable=False),
        sa.Column('source_id',        sa.Integer(), nullable=False),
        sa.Column('sql',              sa.String(), nullable=False),
        sa.Column('risk_score',       sa.Integer(), nullable=False),
        sa.Column('risk_level',       sa.String(), nullable=False),
        sa.Column('status',           sa.String(), nullable=False, server_default='pending'),
        sa.Column('approval_token',   sa.String(), nullable=True),
        sa.Column('approver_email',   sa.String(), nullable=True),
        sa.Column('approver_note',    sa.String(), nullable=True),
        sa.Column('created_at',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at',       sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at',       sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_query_approvals_approval_token', 'query_approvals', ['approval_token'], unique=True)

    op.create_table('department_management',
        sa.Column('id',            sa.Integer(), primary_key=True, index=True),
        sa.Column('department_id', sa.Integer(), sa.ForeignKey('departments.id'), nullable=False),
        sa.Column('source_name',   sa.String(), nullable=False),
        sa.Column('database_name', sa.String(), nullable=False),
        sa.Column('tables',        sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('tenant_id',     sa.Integer(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('created_at',    sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('department_management')
    op.drop_table('query_approvals')
    op.drop_table('login_attempts')
    op.drop_table('system_settings')
    op.drop_table('session_recordings')
    op.drop_table('privileged_activities')
    op.drop_table('data_change_audits')
    op.drop_table('security_events')
    op.drop_table('agent_registrations')
