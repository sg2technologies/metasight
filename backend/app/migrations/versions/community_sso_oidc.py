"""Add OIDC SSO columns to users

Revision ID: community_sso_oidc
Revises: community_mfa_totp
Create Date: 2026-09-18

Backs app/api/sso.py's OIDC login/callback flow. sso_issuer/sso_subject
identify a user by their IdP-issued subject claim; hashed_password stays
NOT NULL even for SSO-only accounts (they get a random, never-verified-
against hash at creation, not a schema change touching every other
password code path). The (sso_issuer, sso_subject) unique constraint is
safe with both columns nullable — Postgres treats each NULL as distinct,
so the many non-SSO users (NULL, NULL) never collide with each other.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'community_sso_oidc'
down_revision: Union[str, None] = 'community_mfa_totp'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('sso_subject', sa.String(), nullable=True))
    op.add_column('users', sa.Column('sso_issuer', sa.String(), nullable=True))
    op.create_index('ix_users_sso_subject', 'users', ['sso_subject'])
    op.create_unique_constraint('_users_sso_identity_uc', 'users', ['sso_issuer', 'sso_subject'])


def downgrade() -> None:
    op.drop_constraint('_users_sso_identity_uc', 'users', type_='unique')
    op.drop_index('ix_users_sso_subject', table_name='users')
    op.drop_column('users', 'sso_issuer')
    op.drop_column('users', 'sso_subject')
