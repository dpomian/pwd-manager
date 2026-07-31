"""document collection many to many

Revision ID: d9687915ac54
Revises: 7b0c18b8befb
Create Date: 2026-07-31

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "d9687915ac54"
down_revision = "7b0c18b8befb"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()
    document_columns = {c["name"] for c in inspector.get_columns("document")}

    if "document_collection" not in tables:
        op.create_table(
            "document_collection",
            sa.Column("document_id", sa.Integer(), nullable=False),
            sa.Column("collection_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["document_id"], ["document.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["collection_id"], ["collection.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("document_id", "collection_id"),
        )

    if "collection_id" in document_columns:
        conn.execute(
            sa.text(
                "INSERT OR IGNORE INTO document_collection (document_id, collection_id) "
                "SELECT id, collection_id FROM document WHERE collection_id IS NOT NULL"
            )
        )

        fks = inspector.get_foreign_keys("document")
        fk_name = next(
            (fk["name"] for fk in fks if fk.get("referred_table") == "collection"),
            None,
        )

        with op.batch_alter_table("document", schema=None) as batch_op:
            if fk_name:
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            batch_op.drop_column("collection_id")


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    document_columns = {c["name"] for c in inspector.get_columns("document")}

    if "collection_id" not in document_columns:
        with op.batch_alter_table("document", schema=None) as batch_op:
            batch_op.add_column(sa.Column("collection_id", sa.Integer(), nullable=True))
            batch_op.create_foreign_key("fk_document_collection", "collection", ["collection_id"], ["id"])

    conn.execute(
        sa.text(
            "UPDATE document SET collection_id = ("
            "SELECT collection_id FROM document_collection "
            "WHERE document_collection.document_id = document.id LIMIT 1"
            ")"
        )
    )

    if "document_collection" in inspector.get_table_names():
        op.drop_table("document_collection")
