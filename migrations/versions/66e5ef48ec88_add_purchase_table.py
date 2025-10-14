"""add purchase table

Revision ID: 66e5ef48ec88
Revises: a3dd230f0258
Create Date: 2025-09-24 12:41:52.997137
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = "66e5ef48ec88"
down_revision = "a3dd230f0258"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    insp = inspect(bind)

    # Ne JAMAIS dropper les anciennes tables ici. On ajoute juste "purchase".
    if "purchase" not in set(insp.get_table_names()):
        op.create_table(
            "purchase",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("amount_cents", sa.Integer(), nullable=False),
            sa.Column("credits", sa.Integer(), nullable=False),
            sa.Column("currency", sa.String(length=8), nullable=False, server_default="eur"),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="succeeded"),
            sa.Column("stripe_session_id", sa.String(length=128), nullable=True),
            sa.Column("stripe_payment_intent", sa.String(length=128), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        with op.batch_alter_table("purchase") as batch_op:
            batch_op.create_index("ix_purchase_user_id", ["user_id"], unique=False)
            batch_op.create_index("ix_purchase_status", ["status"], unique=False)


def downgrade():
    bind = op.get_bind()
    insp = inspect(bind)

    if "purchase" in set(insp.get_table_names()):
        with op.batch_alter_table("purchase") as batch_op:
            # Supprime d’abord les index si ils existent
            try:
                batch_op.drop_index("ix_purchase_status")
            except Exception:
                pass
            try:
                batch_op.drop_index("ix_purchase_user_id")
            except Exception:
                pass

        op.drop_table("purchase")
