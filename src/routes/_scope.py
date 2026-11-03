from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from ..repositories.user import TenantMemberRepository

# Le rôle qui administre UNE organisation : invitations, membres, rôles et permissions de celle-ci. Créé et garni par
# `services/seed.py` (`TENANT_ADMIN_PERMISSIONS`), reçu par le propriétaire à la création de son organisation
# (`routes/tenants.py`, `services/auth/onboarding.py`) ; le donner à un membre, c'est déléguer l'administration.
from ..services.seed import TENANT_ADMIN_ROLE


def payload_field(payload: Any, key: str, default: Any = None) -> Any:
    """Extrait un champ d'un AuthPayload (dict-like ou objet)."""
    if hasattr(payload, "get"):
        return payload.get(key, default)
    return getattr(payload, key, default)


def is_platform_admin(payload: Any) -> bool:
    return "admin:*" in (payload_field(payload, "permissions", []) or [])


async def require_tenant_admin(
    session: Any,
    payload: Any,
    tenant_id: str,
    *,
    role_name: str = TENANT_ADMIN_ROLE,
) -> Any:
    """Administrer CETTE organisation : admin plateforme, propriétaire, ou membre portant le rôle `tenant_admin`.

    Avant, tout passait par le seul drapeau `is_owner`, posé à la création et jamais transférable : les grants du
    rôle `tenant_admin` n'ouvraient aucune porte et une organisation n'avait qu'un administrateur, définitif. Le
    propriétaire reste administrateur de droit (son rôle peut manquer : la seed le prévoit explicitement).

    Ce que cela ne donne pas : les permissions non délégables. `grant_permission_to_member` et
    `create_tenant_role` refusent tout ce qui n'est pas `tenant_grantable`, donc un administrateur
    d'organisation ne peut pas se fabriquer `admin:*` ni `user:delete`.
    """
    if is_platform_admin(payload):
        return None
    user_id = payload_field(payload, "sub")
    membership = await TenantMemberRepository(session).get_membership(user_id, tenant_id)
    if membership is None:
        raise HTTPException(
            status_code=403,
            detail="Accès refusé : vous n'êtes pas membre de ce tenant",
        )
    if membership.is_owner:
        return membership
    from ..services.rbac.members import MemberRoleService  # import local : évite un cycle routes <-> services

    if role_name not in await MemberRoleService(session).get_roles_for_user(user_id, tenant_id):
        raise HTTPException(
            status_code=403,
            detail=f"Réservé aux administrateurs de l'organisation (rôle « {role_name} »)",
        )
    return membership


async def require_tenant_scope(
    session: Any,
    payload: Any,
    tenant_id: str,
    *,
    owner_only: bool = False,
) -> Any:
    """
    Vérifie que l'appelant a le droit d'agir sur CE tenant précis.

    - admin plateforme (admin:*) → accès total (bypass).
    - sinon : doit être membre du tenant ; si owner_only, doit en être owner.

    Empêche un tenant_admin du tenant A de toucher au tenant B.
    Retourne le TenantMember (ou None pour l'admin plateforme).
    """
    if is_platform_admin(payload):
        return None
    user_id = payload_field(payload, "sub")
    membership = await TenantMemberRepository(session).get_membership(
        user_id, tenant_id
    )
    if membership is None:
        raise HTTPException(
            status_code=403,
            detail="Accès refusé : vous n'êtes pas membre de ce tenant",
        )
    if owner_only and not membership.is_owner:
        raise HTTPException(
            status_code=403,
            detail="Réservé au propriétaire du tenant",
        )
    return membership
