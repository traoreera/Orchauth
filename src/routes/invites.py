from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.invite import InviteService
from ..repositories.rbac import RoleRepository
from ..schemas.invite import AcceptInviteRequest, InviteCreate, InviteResponse
from ._scope import is_platform_admin, require_tenant_scope


def invites_router(
    db: Any,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/invites", tags=["invites"])

    @router.post("/", response_model=InviteResponse, status_code=status.HTTP_201_CREATED)
    async def create_invite(
        body: InviteCreate,
        user: AuthPayload = Depends(require_permission("invites:write")),
    ) -> Any:
        async with db.session() as session:
            # L'appelant doit être owner du tenant ciblé (ou admin plateforme) :
            # empêche d'inviter sur le tenant d'autrui.
            await require_tenant_scope(session, user, body.tenant_id, owner_only=True)

            # Anti-escalade : un owner ne peut pas attribuer un rôle portant
            # admin:* (god-mode plateforme). Seul l'admin plateforme le peut.
            if body.role_id and not is_platform_admin(user):
                role = await RoleRepository(session).get_with_permissions(body.role_id)
                if role is None:
                    raise HTTPException(status_code=400, detail="Rôle invalide")
                if any(p.name == "admin:*" for p in role.permissions):
                    raise HTTPException(
                        status_code=403,
                        detail="Attribution d'un rôle administrateur plateforme interdite",
                    )

            svc = InviteService(session, events)
            try:
                invite = await svc.create_invite(
                    tenant_id=body.tenant_id,
                    invited_by=user["sub"],
                    email=body.email,
                    role_id=body.role_id,
                    expires_hours=body.expires_hours,
                )
                await session.commit()
                await session.refresh(invite)

                # Envoyer l'email d'invitation
                await email_service.invite.send_invitation(
                    to=invite.email,
                    invite_token=invite.token,
                    tenant_name=body.tenant_id,
                    invited_by=user["sub"],
                    expires_hours=body.expires_hours,
                )

                return invite
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/{tenant_id}", response_model=List[InviteResponse])
    async def list_invites(
        tenant_id: str,
        user: AuthPayload = Depends(require_permission("invites:read")),
    ) -> Any:
        async with db.session() as session:
            # Lecture limitée aux invitations de SON tenant (ou admin plateforme).
            await require_tenant_scope(session, user, tenant_id)
            svc = InviteService(session)
            return await svc.list_invites(tenant_id)

    @router.get("/token/{token}", response_model=InviteResponse)
    async def get_invite(token: str) -> Any:
        """Public — permet à un invité de voir les détails avant d'accepter."""
        async with db.session() as session:
            svc = InviteService(session)
            invite = await svc.get_invite_by_token(token)
            if invite is None:
                raise HTTPException(status_code=404, detail="Invite not found")
            return invite

    @router.post("/accept", response_model=dict)
    async def accept_invite(
        body: AcceptInviteRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """
        L'utilisateur doit être authentifié.
        Le user_id vient du token — body.user_id est ignoré.
        """
        async with db.session() as session:
            svc = InviteService(session)
            try:
                membership = await svc.accept_invite(
                    token=body.token,
                    user_id=user["sub"],
                )
                await session.commit()
                return {
                    "success": True,
                    "tenant_id": membership.tenant_id,
                    "user_id": membership.user_id,
                    "role_id": membership.role_id,
                }
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    return router
