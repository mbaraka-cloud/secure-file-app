"""billing tables

Revision ID: 3942deb6586e
Revises: e814a28d01ee
Create Date: 2025-09-18 18:08:10.696825
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = "3942deb6586e"
down_revision = "e814a28d01ee"
branch_labels = None
depends_on = None


def _ensure_table(name: str, create_fn):
    bind = op.get_bind()
    insp = inspect(bind)
    if name not in set(insp.get_table_names()):
        create_fn()


def upgrade():
    # credit_transactions
    def create_credit_tx():
        op.create_table(
            "credit_transactions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("change", sa.Integer(), nullable=False),
            sa.Column("reason", sa.String(length=64), nullable=False),
            sa.Column("reference", sa.String(length=128), nullable=True),
            sa.Column("meta_json", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        with op.batch_alter_table("credit_transactions") as b:
            b.create_index("ix_credit_transactions_user_id", ["user_id"], unique=False)

    _ensure_table("credit_transactions", create_credit_tx)

    # download_lots
    def create_download_lots():
        op.create_table(
            "download_lots",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("recipient_user_id", sa.Integer(), nullable=False),
            sa.Column("share_id", sa.Integer(), nullable=True),
            sa.Column("total_bytes", sa.BigInteger(), nullable=False),
            sa.Column("cost_credits", sa.Integer(), nullable=False),
            sa.Column("token", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("consumed_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        with op.batch_alter_table("download_lots") as b:
            b.create_index("ix_download_lots_recipient_user_id", ["recipient_user_id"], unique=False)
            b.create_index("ix_download_lots_share_id", ["share_id"], unique=False)
            b.create_index("ix_download_lots_token", ["token"], unique=True)

    _ensure_table("download_lots", create_download_lots)

    # payment_sessions
    def create_payment_sessions():
        op.create_table(
            "payment_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("stripe_session_id", sa.String(length=128), nullable=False),
            sa.Column("stripe_payment_intent", sa.String(length=128), nullable=True),
            sa.Column("amount", sa.Integer(), nullable=False),
            sa.Column("currency", sa.String(length=8), nullable=False),
            sa.Column("credits_purchased", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("stripe_session_id"),
        )
        with op.batch_alter_table("payment_sessions") as b:
            b.create_index("ix_payment_sessions_user_id", ["user_id"], unique=False)
            b.create_index("ix_payment_sessions_stripe_payment_intent", ["stripe_payment_intent"], unique=False)

    _ensure_table("payment_sessions", create_payment_sessions)

    # wallets
    def create_wallets():
        op.create_table(
            "wallets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("balance_credits", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        )
        with op.batch_alter_table("wallets") as b:
            b.create_index("ix_wallets_user_id", ["user_id"], unique=True)

    _ensure_table("wallets", create_wallets)


def downgrade():
    # ordre inverse + drop index safe
    for tbl, idxs in [
        ("wallets", ["ix_wallets_user_id"]),
        ("payment_sessions", ["ix_payment_sessions_user_id", "ix_payment_sessions_stripe_payment_intent"]),
        ("download_lots", ["ix_download_lots_token", "ix_download_lots_share_id", "ix_download_lots_recipient_user_id"]),
        ("credit_transactions", ["ix_credit_transactions_user_id"]),
    ]:
        bind = op.get_bind()
        insp = inspect(bind)
        if tbl in set(insp.get_table_names()):
            with op.batch_alter_table(tbl) as b:
                for idx in idxs:
                    try:
                        b.drop_index(idx)
                    except Exception:
                        pass
            op.drop_table(tbl)
