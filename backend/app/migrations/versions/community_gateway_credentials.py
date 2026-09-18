"""Gateway credentials table (MetaSight Gateway — Community, PostgreSQL adapter)

Revision ID: community_gateway_credentials
Revises: community_single_tenant_guard
Create Date: 2026-09-18

Backs backend/gateway/ — Go-based mandatory network proxies real DB clients
connect through (psql, mysql CLI, BI tools, applications using their normal
driver, no code change required), enforcing the same policy/masking
pipeline as /query/execute (app/services/gateway_prepare.py) inline on
every query. Clients authenticate with a gateway-issued identity stored
here, never the target DataSource's own DB password.

This table was originally introduced on the Enterprise `pam` branch as
`pam_005_gateway_credentials` when the gateway was Enterprise-only
(PostgreSQL adapter). It has no dependency on any Enterprise-only table —
only `tenants`/`data_sources`/`users`/`departments`, all Community — so
re-tiering the gateway itself (Postgres + MySQL) into Community moves this
migration onto the Community branch too. `pam_005_gateway_credentials` has
been deleted from the Enterprise migration chain; Enterprise's `pam` branch
head reverts to `pam_004_sdk_credentials`.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'community_gateway_credentials'
down_revision: Union[str, None] = 'community_single_tenant_guard'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'gateway_credentials',
        sa.Column('id',                      sa.Integer(),   primary_key=True),
        sa.Column('tenant_id',                sa.Integer(),   sa.ForeignKey('tenants.id'),      nullable=False),
        sa.Column('data_source_id',            sa.Integer(),   sa.ForeignKey('data_sources.id'), nullable=False),
        sa.Column('user_id',                   sa.Integer(),   sa.ForeignKey('users.id'),        nullable=True),
        sa.Column('gateway_username',           sa.String(256), nullable=False),
        sa.Column('secret_hash',               sa.String(256), nullable=False),
        sa.Column('display_name',              sa.String(256), nullable=False),
        sa.Column('role_override',             sa.String(64),  nullable=True),
        sa.Column('department_id_override',    sa.Integer(),   sa.ForeignKey('departments.id'),  nullable=True),
        sa.Column('region_override',            sa.String(64),  nullable=True),
        sa.Column('status',                    sa.String(32),  server_default='ACTIVE'),
        sa.Column('created_by_id',              sa.Integer(),   sa.ForeignKey('users.id'),        nullable=True),
        sa.Column('created_at',                 sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('last_used_at',               sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at',                 sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at',                 sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('gateway_username', name='_gateway_credentials_username_uc'),
    )
    op.create_index('ix_gateway_credentials_username', 'gateway_credentials', ['gateway_username'])
    op.create_index('ix_gateway_credentials_tenant',   'gateway_credentials', ['tenant_id'])
    op.create_index('ix_gateway_credentials_source',   'gateway_credentials', ['data_source_id'])
    op.create_index('ix_gateway_credentials_status',   'gateway_credentials', ['status'])


def downgrade() -> None:
    op.drop_table('gateway_credentials')
