"""Add TOTP MFA columns to users

Revision ID: community_mfa_totp
Revises: community_agent_key_encryption
Create Date: 2026-09-18

Backs app/api/auth.py's /auth/mfa/enroll, /enroll/confirm, /disable, and
/challenge endpoints. totp_secret is populated as soon as enrollment starts
but totp_enabled stays False until a real code is confirmed — a started-but-
never-confirmed enrollment never gates login. Direct columns on `users`
(not a side table), matching how department_id/allowed_roles were already
added to this schema for similar per-user auth-adjacent state.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'community_mfa_totp'
down_revision: Union[str, None] = 'community_agent_key_encryption'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('totp_secret', sa.String(), nullable=True))
    op.add_column('users', sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='false'))


def downgrade() -> None:
    op.drop_column('users', 'totp_enabled')
    op.drop_column('users', 'totp_secret')
