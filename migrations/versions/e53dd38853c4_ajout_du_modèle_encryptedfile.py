"""Ajout du modèle EncryptedFile

Revision ID: e53dd38853c4
Revises:
Create Date: 2025-04-06 18:10:37.365479
"""
from alembic import op
from sqlalchemy import text

revision = "e53dd38853c4"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Si la table n'existe pas, ce DROP ne cassera pas la migration
    op.execute(text('DROP TABLE IF EXISTS "user" CASCADE'))


def downgrade():
    # (Downgrade auto-généré : recrée l’ancienne table user si besoin)
    import sqlalchemy as sa
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("email", sa.String(length=150), nullable=False),
        sa.Column("password_hash", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=10), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
