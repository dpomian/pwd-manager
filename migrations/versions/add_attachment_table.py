"""Add attachment table for encrypted file storage

Revision ID: add_attachment_table
Revises: 363da605ac29
Create Date: 2024-12-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_attachment_table'
down_revision = '363da605ac29'
branch_labels = None
depends_on = None


def upgrade():
    # Create attachment table if it doesn't exist
    op.create_table('attachment',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('secret_entry_id', sa.Integer(), nullable=False),
        sa.Column('original_filename', sa.String(length=255), nullable=False),
        sa.Column('mime_type', sa.String(length=100), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('storage_filename', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['secret_entry_id'], ['password_entry.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('attachment')
