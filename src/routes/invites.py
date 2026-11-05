from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.invite import InviteService
from ..repositories.invite import InviteRepository
from ..repositories.rbac import RoleRepository
from ..repositories.user import UserRepository
from ..repositories.tenant import TenantRepository
from ..schemas.invite import AcceptInviteRequest, InviteCreate, InviteResponse
from ._scope import is_platform_admin, require_tenant_admin, require_tenant_scope

from xcore.sdk import get_logger

logger = get_logger("xauth.invites")


def invites_router(
    db: Any,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
    # Pour demander au moteur de DocTypes où une organisation attend ses gens (`meta.interface`). Absent :
    # le lien reste le web, comme avant ce réglage.
    plugin_caller: Any = None,
) -> APIRouter:
    router = APIRouter(prefix="/invites", tags=["invites"])

    async def _notify(session, user_id: str, text: str, extra: dict | None = None) -> None:
        """Pousse une notification SSE via ext.notification.publish."""
        if events is None:
            return
        payload = {"user_id": user_id, "text": text, "channels": ["notification"], **(extra or {})}
        await events.emit("ext.notification.publish", payload)

    async def _interface_of(tenant_id: str) -> str:
        """Où cette organisation attend ses gens (`meta.interface` du moteur de DocTypes).

        Jamais bloquant : sans le moteur, ou s'il ne répond pas, on garde le web — le comportement d'avant ce
        réglage. Une préférence d'affichage ne doit pas empêcher une invitation de partir.
        """
        if plugin_caller is None:
            return "web"
        try:
            answer = await plugin_caller("xcore-doctype", "meta.interface", {"tenant": tenant_id})
        except Exception as exc:  # noqa: BLE001
            logger.info("interface de %s inconnue (%s) : lien web", tenant_id, exc)
            return "web"
        chosen = (answer or {}).get("interface")
        return chosen if chosen in ("web", "desktop", "both") else "web"

    @router.post("/", response_model=InviteResponse, status_code=status.HTTP_201_CREATED)
    async def create_invite(
        body: InviteCreate,
        user: AuthPayload = Depends(require_permission("invites:write")),
    ) -> Any:
        async with db.session() as session:
            # Inviter est une opération d'ADMINISTRATION de l'organisation, pas un privilège du propriétaire : le rôle
            # `tenant_admin` (que le propriétaire porte, et qu'il peut donner) l'ouvre. `invites:write` ci-dessus reste
            # le grant, la portée dit DANS QUELLE organisation.
            await require_tenant_admin(session, user, body.tenant_id)

            if body.role_id and not is_platform_admin(user):
                try:
                    await InviteService(session)._validate_role_for_tenant(body.tenant_id, body.role_id)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc

            # Charge le tenant AVANT le commit pour avoir le vrai nom
            tenant = await TenantRepository(session).get(body.tenant_id)
            tenant_name = tenant.name if tenant else body.tenant_id

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

                # Email avec le vrai nom du tenant, et le lien que l'organisation attend : web ou application
                # installée (`System Settings.interface`, demandé au moteur). Inviter quelqu'un dans une
                # organisation qui travaille sur l'application, puis lui envoyer un lien vers un Desk web, c'est
                # l'envoyer au mauvais endroit dès le premier geste.
                await email_service.invite.send_invitation(
                    to=invite.email,
                    invite_token=invite.token,
                    tenant_name=tenant_name,
                    invited_by=user["sub"],
                    expires_hours=body.expires_hours,
                    interface=await _interface_of(body.tenant_id),
                )

                # Notifier l'inviteur (confirmation)
                await _notify(session, user["sub"],
                    f"Invitation envoyée à {invite.email}",
                    {"event": "invite.created", "invite_id": str(invite.id), "email": invite.email})

                # Notifier l'invité s'il a déjà un compte
                user_repo = UserRepository(session)
                invitee = await user_repo.get_by_email(invite.email)
                if invitee:
                    await _notify(session, str(invitee.id),
                        f"Vous avez été invité à rejoindre {tenant_name}",
                        {"event": "invite.received", "invite_id": str(invite.id),
                         "tenant_id": body.tenant_id, "tenant_name": tenant_name,
                         "token": invite.token})

                result = invite.__dict__.copy()
                result["tenant_name"] = tenant_name
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    # ── Routes sans paramètre de chemin dynamique en premier ──────────────────
    # IMPORTANT : /me, /token/{token} et /accept doivent être AVANT /{tenant_id}
    # sinon FastAPI route /me → /{tenant_id}="me" et la route est silencieusement ignorée.

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
            invites = await svc.list_for_email(db_user.email)

            # Enrichit chaque invitation avec le nom lisible du tenant
            tenant_repo = TenantRepository(session)
            results = []
            for inv in invites:
                t = await tenant_repo.get(inv.tenant_id)
                item = inv.__dict__.copy()
                item["tenant_name"] = t.name if t else None
                results.append(item)
            return results

    @router.get("/token/{token}", response_model=InviteResponse)
    async def get_invite(token: str) -> Any:
        """Public — permet à un invité de voir les détails avant d'accepter."""
        async with db.session() as session:
            svc = InviteService(session)
            invite = await svc.get_invite_by_token(token)
            if invite is None:
                raise HTTPException(status_code=404, detail="Invite not found")
            tenant = await TenantRepository(session).get(invite.tenant_id)
            item = invite.__dict__.copy()
            item["tenant_name"] = tenant.name if tenant else None
            return item

    @router.post("/accept", response_model=dict)
    async def accept_invite(
        body: AcceptInviteRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = InviteService(session)
            try:
                # Charge l'invite AVANT accept pour avoir invited_by après commit
                invite_obj = await svc.get_invite_by_token(body.token)

                membership = await svc.accept_invite(
                    token=body.token,
                    user_id=user["sub"],
                )
                await session.commit()

                # Notifier l'inviteur que son invitation a été acceptée
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

    # ── Routes avec paramètre dynamique (après les routes fixes) ──────────────

    @router.get("/{tenant_id}", response_model=List[InviteResponse])
    async def list_invites(
        tenant_id: str,
        user: AuthPayload = Depends(require_permission("invites:read")),
    ) -> Any:
        async with db.session() as session:
            await require_tenant_scope(session, user, tenant_id)
            svc = InviteService(session)
            invites = await svc.list_invites(tenant_id)

            tenant = await TenantRepository(session).get(tenant_id)
            tenant_name = tenant.name if tenant else None
            results = []
            for inv in invites:
                item = inv.__dict__.copy()
                item["tenant_name"] = tenant_name
                results.append(item)
            return results

    @router.delete("/{invite_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_invite(
        invite_id: str,
        user: AuthPayload = Depends(require_permission("invites:write")),
    ) -> None:
        """Révoque une invitation : son auteur, un administrateur de l'organisation visée, ou l'admin plateforme."""
        async with db.session() as session:
            svc = InviteService(session)
            privileged = is_platform_admin(user)
            if not privileged:
                # Une invitation appartient à son organisation : un administrateur de celle-ci peut la retirer, même
                # s'il ne l'a pas envoyée. On lit l'organisation de l'invitation avant d'en juger.
                invite = await InviteRepository(session).get(invite_id)
                if invite is None:
                    raise HTTPException(status_code=404, detail="Invite not found")
                try:
                    await require_tenant_admin(session, user, invite.tenant_id)
                    privileged = True
                except HTTPException:
                    privileged = False  # pas administrateur : seul son auteur peut la retirer
            try:
                await svc.revoke_invite(
                    invite_id=invite_id,
                    requester_id=user["sub"],
                    privileged=privileged,
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc))

    return router
