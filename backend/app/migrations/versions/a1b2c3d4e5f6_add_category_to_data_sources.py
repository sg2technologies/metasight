"""add category to data_sources

Revision ID: a1b2c3d4e5f6
Revises: f2aa0c737ecb
Create Date: 2026-03-25 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f2aa0c737ecb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'data_sources',
        sa.Column('category', sa.String(), nullable=False, server_default='database'),
    )


def downgrade() -> None:
    op.drop_column('data_sources', 'category')
