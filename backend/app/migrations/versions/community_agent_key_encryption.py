"""Encrypt AgentRegistration.api_key at rest

Revision ID: community_agent_key_encryption
Revises: community_gateway_credentials
Create Date: 2026-09-18

AgentRegistration.api_key was stored in plaintext (a known SECURITY_AUDIT.md
backlog item). Fixed with reversible AES-GCM encryption (app.core.encryption.
aes_cipher — the same mechanism already used for DataSource.encrypted_config)
rather than a one-way hash like GatewayCredential/SDKCredential use: unlike
those, app/core/agent_runner.py's "Start Agent" local-testing convenience
spawns agent.exe itself and must pass the raw key back as a CLI argument, so
the plaintext has to stay recoverable. key_prefix (first 12 chars of the raw
key) gives an indexed lookup before the decrypt-and-compare step, replacing
the old direct `WHERE api_key = X` plaintext lookup.

Existing rows already hold real plaintext keys, so this backfills
key_prefix/encrypted_api_key FROM the existing plaintext value (no need for
already-deployed agents to re-register — their stored raw key keeps working
unchanged; only server-side validation/storage changes) before dropping the
old column.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = 'community_agent_key_encryption'
down_revision: Union[str, None] = 'community_gateway_credentials'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('agent_registrations', sa.Column('key_prefix', sa.String(16), nullable=True))
    op.add_column('agent_registrations', sa.Column('encrypted_api_key', sa.String(256), nullable=True))

    # Backfill from the existing plaintext api_key — needs Python (AES-GCM
    # encryption), not a raw SQL UPDATE.
    from app.core.encryption import aes_cipher

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, api_key FROM agent_registrations")).fetchall()
    for row_id, api_key in rows:
        conn.execute(
            sa.text(
                "UPDATE agent_registrations SET key_prefix = :prefix, encrypted_api_key = :enc WHERE id = :id"
            ),
            {"prefix": api_key[:12], "enc": aes_cipher.encrypt(api_key), "id": row_id},
        )

    op.alter_column('agent_registrations', 'key_prefix', nullable=False)
    op.alter_column('agent_registrations', 'encrypted_api_key', nullable=False)
    op.create_unique_constraint('uq_agent_registrations_key_prefix', 'agent_registrations', ['key_prefix'])

    op.drop_index('ix_agent_registrations_api_key', table_name='agent_registrations')
    op.drop_column('agent_registrations', 'api_key')


def downgrade() -> None:
    op.add_column('agent_registrations', sa.Column('api_key', sa.String(), nullable=True))

    # api_key can be recovered by decrypting encrypted_api_key — it was never
    # a one-way hash, so downgrade doesn't lose data.
    from app.core.encryption import aes_cipher

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, encrypted_api_key FROM agent_registrations")).fetchall()
    for row_id, encrypted_api_key in rows:
        conn.execute(
            sa.text("UPDATE agent_registrations SET api_key = :key WHERE id = :id"),
            {"key": aes_cipher.decrypt(encrypted_api_key), "id": row_id},
        )

    op.alter_column('agent_registrations', 'api_key', nullable=False)
    op.create_index('ix_agent_registrations_api_key', 'agent_registrations', ['api_key'], unique=True)

    op.drop_constraint('uq_agent_registrations_key_prefix', 'agent_registrations', type_='unique')
    op.drop_column('agent_registrations', 'key_prefix')
    op.drop_column('agent_registrations', 'encrypted_api_key')
