"""hash api keys for security

Revision ID: aa85513865c9
Revises: 001
Create Date: 2025-12-10 01:22:21.597782

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aa85513865c9'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rename 'key' column to 'key_hash'
    op.alter_column('api_keys', 'key', new_column_name='key_hash')
    
    # Add 'key_prefix' column
    op.add_column('api_keys', sa.Column('key_prefix', sa.String(), nullable=False, server_default='sk_live_'))
    
    # Remove server default after adding
    op.alter_column('api_keys', 'key_prefix', server_default=None)


def downgrade() -> None:
    # Remove 'key_prefix' column
    op.drop_column('api_keys', 'key_prefix')
    
    # Rename 'key_hash' back to 'key'
    op.alter_column('api_keys', 'key_hash', new_column_name='key')
