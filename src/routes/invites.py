from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.invite import InviteService
from ..repositories.rbac import RoleRepository
from ..repositories.user import UserRepository
from ..repositories.tenant import TenantRepository
from ..schemas.invite import AcceptInviteRequest, InviteCreate, InviteResponse
from ._scope import is_platform_admin, require_tenant_scope


def invites_router(
    db: Any,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/invites", tags=["invites"])

    async def _notify(session, user_id: str, text: str, extra: dict | None = None) -> None:
        """Pousse une notification SSE via ext.notification.publish."""
        if events is None:
            return
        payload = {"user_id": user_id, "text": text, "channels": ["notification"], **(extra or {})}
        await events.emit("ext.notification.publish", payload)

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

                # Notifier l'inviteur (confirmation)
                await _notify(session, user["sub"],
                    f"Invitation envoyée à {invite.email}",
                    {"event": "invite.created", "invite_id": str(invite.id), "email": invite.email})

                # Notifier l'invité s'il a déjà un compte
                user_repo = UserRepository(session)
                invitee = await user_repo.get_by_email(invite.email)
                if invitee:
                    tenant = await TenantRepository(session).get(body.tenant_id)
                    tenant_name = tenant.name if tenant else body.tenant_id
                    await _notify(session, str(invitee.id),
                        f"Vous avez été invité à rejoindre {tenant_name}",
                        {"event": "invite.received", "invite_id": str(invite.id),
                         "tenant_id": body.tenant_id, "tenant_name": tenant_name,
                         "token": invite.token})

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

                # Notifier l'inviteur que son invitation a été acceptée
                invite_obj = await svc.get_invite_by_token(body.token)
                if invite_obj:
                    tenant = await TenantRepository(session).get(membership.tenant_id)
                    tenant_name = tenant.name if tenant else membership.tenant_id
                    accepter = await UserRepository(session).get(user["sub"])
                    accepter_label = accepter.email if accepter else user["sub"]
                    await _notify(session, invite_obj.invited_by,
                        f"{accepter_label} a rejoint {tenant_name}",
                        {"event": "invite.accepted", "tenant_id": membership.tenant_id,
                         "user_id": user["sub"]})

                return {
                    "success": True,
                    "tenant_id": membership.tenant_id,
                    "user_id": membership.user_id,
                    "role_id": membership.role_id,
                }
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/me", response_model=List[InviteResponse])
    async def my_invites(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Retourne les invitations en attente pour l'email de l'utilisateur connecté."""
        async with db.session() as session:
            user_repo = UserRepository(session)
            db_user = await user_repo.get(user["sub"])
            if db_user is None:
                raise HTTPException(status_code=404, detail="User not found")
            svc = InviteService(session)
            return await svc.list_for_email(db_user.email)

    @router.delete("/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_invite(
        invite_id: str,
        user: AuthPayload = Depends(require_permission("invites:write")),
    ) -> None:
        """Révoque une invitation (l'inviteur ou un admin plateforme uniquement)."""
        async with db.session() as session:
            svc = InviteService(session)
            try:
                await svc.revoke_invite(
                    invite_id=invite_id,
                    requester_id=user["sub"],
                    is_platform_admin=is_platform_admin(user),
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc))

    return router
