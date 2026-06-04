from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from ..repositories.user import TenantMemberRepository


def payload_field(payload: Any, key: str, default: Any = None) -> Any:
    """Extrait un champ d'un AuthPayload (dict-like ou objet)."""
    if hasattr(payload, "get"):
        return payload.get(key, default)
    return getattr(payload, key, default)


def is_platform_admin(payload: Any) -> bool:
    return "admin:*" in (payload_field(payload, "permissions", []) or [])


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
