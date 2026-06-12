"""add unique constraint on xauth_tenant_members(user_id, tenant_id)

Revision ID: a3f2c1d8e9b0
Revises: d1469d156d48
Create Date: 2026-06-10

Empêche la création de doublons de membership (même user dans le même tenant).
"""

from collections.abc import Sequence
from typing import Union

from alembic import op

revision: str = "a3f2c1d8e9b0"
down_revision: Union[str, Sequence[str], None] = "d1469d156d48"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Supprime les éventuels doublons avant d'ajouter la contrainte.
    # Garde la ligne la plus ancienne (joined_at le plus petit) pour chaque paire.
    op.execute("""
        DELETE FROM xauth_tenant_members
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM xauth_tenant_members
            GROUP BY user_id, tenant_id
        )
    """)
    op.create_unique_constraint(
        "uq_tenant_member",
        "xauth_tenant_members",
        ["user_id", "tenant_id"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_tenant_member", "xauth_tenant_members", type_="unique")
