"""Add title and has_login_info fields to SecretEntry

Revision ID: add_title_login_info
Revises: add_attachment_table
Create Date: 2025-12-15

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_title_login_info'
down_revision = 'add_attachment_table'
branch_labels = None
depends_on = None


def upgrade():
    # Add title column - use website as default for existing entries
    with op.batch_alter_table('password_entry') as batch_op:
        batch_op.add_column(sa.Column('title', sa.String(200), nullable=True))
        batch_op.add_column(sa.Column('has_login_info', sa.Boolean(), nullable=True))
    
    # Set default values for existing entries
    op.execute("UPDATE password_entry SET title = website WHERE title IS NULL")
    op.execute("UPDATE password_entry SET has_login_info = 1 WHERE has_login_info IS NULL")
    
    # Make columns non-nullable after setting defaults
    with op.batch_alter_table('password_entry') as batch_op:
        batch_op.alter_column('title', nullable=False)
        batch_op.alter_column('has_login_info', nullable=False, server_default=sa.text('0'))
        # Make website, username, password nullable
        batch_op.alter_column('website', nullable=True)
        batch_op.alter_column('username', nullable=True)
        batch_op.alter_column('encrypted_password', nullable=True)


def downgrade():
    with op.batch_alter_table('password_entry') as batch_op:
        batch_op.drop_column('title')
        batch_op.drop_column('has_login_info')
        batch_op.alter_column('website', nullable=False)
        batch_op.alter_column('username', nullable=False)
        batch_op.alter_column('encrypted_password', nullable=False)
