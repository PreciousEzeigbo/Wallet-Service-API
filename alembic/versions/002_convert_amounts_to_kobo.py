"""Convert all amounts from float (Naira) to integer (kobo)

Revision ID: 002_convert_kobo
Revises: aa85513865c9
Create Date: 2025-12-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002_convert_kobo'
down_revision = 'aa85513865c9'
branch_labels = None
depends_on = None


def upgrade():
    # Convert wallet balance from float (Naira) to integer (kobo)
    # Multiply by 100 and convert to integer
    op.execute("""
        UPDATE wallets 
        SET balance = CAST(balance * 100 AS INTEGER)
    """)
    
    # Convert transaction amounts from float (Naira) to integer (kobo)
    op.execute("""
        UPDATE transactions 
        SET amount = CAST(amount * 100 AS INTEGER)
    """)
    
    # Change column types
    op.alter_column('wallets', 'balance',
                    existing_type=sa.Float(),
                    type_=sa.Integer(),
                    existing_nullable=True)
    
    op.alter_column('transactions', 'amount',
                    existing_type=sa.Float(),
                    type_=sa.Integer(),
                    existing_nullable=False)


def downgrade():
    # Convert back from kobo to Naira
    op.alter_column('wallets', 'balance',
                    existing_type=sa.Integer(),
                    type_=sa.Float(),
                    existing_nullable=True)
    
    op.alter_column('transactions', 'amount',
                    existing_type=sa.Integer(),
                    type_=sa.Float(),
                    existing_nullable=False)
    
    op.execute("""
        UPDATE wallets 
        SET balance = CAST(balance AS FLOAT) / 100
    """)
    
    op.execute("""
        UPDATE transactions 
        SET amount = CAST(amount AS FLOAT) / 100
    """)
