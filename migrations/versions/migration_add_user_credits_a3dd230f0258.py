"""add user credits column

Revision ID: a3dd230f0258
Revises: 3942deb6586e
Create Date: 2025-09-19
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a3dd230f0258'
down_revision = '3942deb6586e'
branch_labels = None
depends_on = None

def upgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    # Récupère la liste des colonnes existantes de la table 'user'
    cols = [c['name'] for c in insp.get_columns('user')]
    if 'credits' not in cols:
        op.add_column(
            'user',
            sa.Column('credits', sa.Integer(), nullable=False, server_default='0')
        )
        # Supprime la valeur par défaut serveur après création (pratique pour SQLite)
        op.alter_column('user', 'credits', server_default=None)

def downgrade():
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = [c['name'] for c in insp.get_columns('user')]
    if 'credits' in cols:
        op.drop_column('user', 'credits')
