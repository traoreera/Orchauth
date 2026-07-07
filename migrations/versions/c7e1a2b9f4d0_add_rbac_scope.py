"""add generic scope (scope_type, scope_id) to member roles & permissions

Revision ID: c7e1a2b9f4d0
Revises: a3f2c1d8e9b0
Create Date: 2026-07-02

Phase 1 de l'architecture distribuée : donner un SCOPE générique à la RBAC.
NULL/NULL = assignation GLOBALE au tenant (comportement historique, zéro rupture).
Sinon l'assignation n'est effective que dans (scope_type, scope_id) — ex:
scope_type="entrepot", scope_id=<uuid entrepôt>. scope_id est opaque (pas de FK).

Les contraintes d'unicité intègrent désormais le scope pour qu'un même rôle/
permission puisse coexister en global ET dans un/plusieurs scopes.

NB : Orchauth crée le schéma via create_all sur DB fraîche ; cette migration sert
aux environnements pilotés par alembic. En dev sur DB existante, les colonnes ont
été ajoutées par ALTER manuel (voir docs/architecture-distribuee.md, Phase 1).
"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "c7e1a2b9f4d0"
down_revision: Union[str, Sequence[str], None] = "a3f2c1d8e9b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("xauth_member_roles") as batch:
        batch.add_column(sa.Column("scope_type", sa.String(length=50), nullable=True))
        batch.add_column(sa.Column("scope_id", sa.String(length=36), nullable=True))
        batch.drop_constraint("uq_member_role", type_="unique")
        batch.create_unique_constraint(
            "uq_member_role",
            ["user_id", "tenant_id", "role_id", "scope_type", "scope_id"],
        )

    with op.batch_alter_table("xauth_member_permissions") as batch:
        batch.add_column(sa.Column("scope_type", sa.String(length=50), nullable=True))
        batch.add_column(sa.Column("scope_id", sa.String(length=36), nullable=True))
        batch.drop_constraint("uq_member_permission", type_="unique")
        batch.create_unique_constraint(
            "uq_member_permission",
            ["user_id", "tenant_id", "permission_id", "scope_type", "scope_id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("xauth_member_permissions") as batch:
        batch.drop_constraint("uq_member_permission", type_="unique")
        batch.create_unique_constraint(
            "uq_member_permission", ["user_id", "tenant_id", "permission_id"]
        )
        batch.drop_column("scope_id")
        batch.drop_column("scope_type")

    with op.batch_alter_table("xauth_member_roles") as batch:
        batch.drop_constraint("uq_member_role", type_="unique")
        batch.create_unique_constraint(
            "uq_member_role", ["user_id", "tenant_id", "role_id"]
        )
        batch.drop_column("scope_id")
        batch.drop_column("scope_type")
