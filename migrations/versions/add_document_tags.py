"""Add tags field to Document

Revision ID: add_document_tags
Revises: add_title_and_has_login_info
Create Date: 2026-07-29

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "add_document_tags"
down_revision = "add_title_login_info"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col["name"] for col in inspector.get_columns("document")]

    if "tags" not in columns:
        with op.batch_alter_table("document", schema=None) as batch_op:
            batch_op.add_column(sa.Column("tags", sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table("document", schema=None) as batch_op:
        batch_op.drop_column("tags")
