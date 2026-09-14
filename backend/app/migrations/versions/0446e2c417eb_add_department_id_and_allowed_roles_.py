"""add department_id and allowed_roles columns

Revision ID: 0446e2c417eb
Revises: 5322e905a7cd
Create Date: 2026-06-16 21:31:28.819057

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0446e2c417eb'
down_revision: Union[str, None] = '5322e905a7cd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create departments table first — it was missing from all prior migrations
    op.create_table(
        'departments',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', 'tenant_id', name='_dept_name_tenant_uc'),
    )
    op.create_index(op.f('ix_departments_id'), 'departments', ['id'], unique=False)

    op.add_column('columns', sa.Column('allowed_roles', sa.JSON(), server_default='["admin", "analyst"]', nullable=False))
    op.add_column('tables', sa.Column('department_id', sa.Integer(), nullable=True))
    op.add_column('tables', sa.Column('allowed_roles', sa.JSON(), server_default='["admin", "analyst"]', nullable=False))
    op.create_foreign_key(None, 'tables', 'departments', ['department_id'], ['id'])
    op.add_column('users', sa.Column('department_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'users', 'departments', ['department_id'], ['id'])


def downgrade() -> None:
    op.drop_constraint(None, 'users', type_='foreignkey')
    op.drop_column('users', 'department_id')
    op.drop_constraint(None, 'tables', type_='foreignkey')
    op.drop_column('tables', 'allowed_roles')
    op.drop_column('tables', 'department_id')
    op.drop_column('columns', 'allowed_roles')
    op.drop_index(op.f('ix_departments_id'), table_name='departments')
    op.drop_table('departments')
