from __future__ import annotations

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload
from xcore.sdk import require_permission

from ..repositories.session import SessionRepository
from ..repositories.user import TenantMemberRepository, UserRepository
from ..services.audit import AuditService
from ._scope import is_platform_admin, payload_field


class UserAdminResponse(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
    is_active: bool
    mfa_enabled: bool
    created_at: str

    model_config = {"from_attributes": True}


class UserPatchRequest(BaseModel):
    is_active: Optional[bool] = None


def admin_router(db: Any, cache: Any = None, token_service: Any = None) -> APIRouter:
    router = APIRouter(prefix="/admin", tags=["admin"])

    @router.get("/users", response_model=List[UserAdminResponse])
    async def list_users(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        _: AuthPayload = Depends(require_permission("user:list")),
    ) -> Any:
        """Liste tous les utilisateurs (admin uniquement)."""
        async with db.session() as session:
            repo = UserRepository(session)
            users = await repo.list_all(limit=limit, offset=offset)
            return [
                {
                    "id": u.id,
                    "email": u.email,
                    "username": u.username,
                    "is_active": u.is_active,
                    "mfa_enabled": u.mfa_enabled,
                    "created_at": u.created_at.isoformat(),
                }
                for u in users
            ]

    @router.get("/users/{user_id}", response_model=UserAdminResponse)
    async def get_user(
        user_id: str,
        caller: AuthPayload = Depends(require_permission("user:read")),
    ) -> Any:
        """Lit un compte. `user:read` est accordé à TOUT utilisateur inscrit (`USER_PERMISSIONS`) et est délégable :
        il ne peut donc pas être, à lui seul, le droit de lire n'importe quel compte de la plateforme par son UUID.
        On exige en plus de PARTAGER une organisation avec la cible — ce dont un annuaire a besoin — l'admin
        plateforme passant partout, et chacun pouvant toujours se lire lui-même.
        """
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            if not is_platform_admin(caller) and user_id != payload_field(caller, "sub"):
                member_repo = TenantMemberRepository(session)
                mine = {m.tenant_id for m in await member_repo.get_memberships_for_user(payload_field(caller, "sub"))}
                theirs = {m.tenant_id for m in await member_repo.get_memberships_for_user(user_id)}
                if not (mine & theirs):
                    # « Introuvable », pas « interdit » : un UUID ne doit pas révéler qu'un compte existe.
                    raise HTTPException(status_code=404, detail="User not found")
            return {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled,
                "created_at": user.created_at.isoformat(),
            }

    @router.patch("/users/{user_id}", response_model=UserAdminResponse)
    async def update_user(
        user_id: str,
        body: UserPatchRequest,
        admin: AuthPayload = Depends(require_permission("user:update")),
    ) -> Any:
        """Active ou désactive un utilisateur."""
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")

            changed: dict[str, Any] = {}
            if body.is_active is not None and user.is_active != body.is_active:
                user.is_active = body.is_active
                changed["is_active"] = body.is_active

                # Révoquer toutes les sessions si on désactive le compte
                if not body.is_active:
                    session_repo = SessionRepository(session)
                    sessions = await session_repo.get_active_sessions_for_user(user_id)
                    for s in sessions:
                        if cache and s.last_jti and token_service:
                            ttl = token_service.access_expire * 60 + 30
                            await cache.set(f"xauth:jti_bl:{s.last_jti}", "1", ttl=ttl)
                    await session_repo.revoke_all_for_user(user_id)

            if changed:
                audit = AuditService(session)
                action = "user.banned" if changed.get("is_active") is False else "user.updated"
                await audit.log_event(
                    action=action,
                    user_id=admin["sub"],
                    resource="user",
                    resource_id=user_id,
                    metadata=changed,
                )
                await session.flush()

            await session.commit()
            await session.refresh(user)
            return {
                "id": user.id,
                "email": user.email,
                "username": user.username,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled,
                "created_at": user.created_at.isoformat(),
            }

    @router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_user(
        user_id: str,
        admin: AuthPayload = Depends(require_permission("user:delete")),
    ) -> None:
        """Supprime définitivement un utilisateur et toutes ses données."""
        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")

            audit = AuditService(session)
            await audit.log_event(
                action="user.deleted",
                user_id=admin["sub"],
                resource="user",
                resource_id=user_id,
                metadata={"email": user.email},
            )

            await session.delete(user)
            await session.commit()

    return router
