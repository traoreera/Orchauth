from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

logger = get_logger("xauth.invite")

from ..models.invite import Invite
from ..models.user import TenantMember
from ..repositories.invite import InviteRepository
from ..repositories.rbac import RoleRepository
from ..repositories.user import TenantMemberRepository
from .events import XAuthEvents
from .seed import TENANT_ADMIN_ROLE


class InviteService:
    def __init__(self, session: AsyncSession, events: XAuthEvents | None = None) -> None:
        self._session = session
        self._events = events

    async def _validate_role_for_tenant(self, tenant_id: str, role_id: Optional[str]) -> None:
        """Un rôle d'invitation doit suivre la même règle que l'assignation standard RBAC.

        - les rôles du tenant ciblé sont autorisés
        - le rôle global `tenant_admin` est autorisé
        - tout autre rôle global, et les rôles d'un autre tenant, sont refusés
        """
        if role_id is None:
            return

        role_repo = RoleRepository(self._session)
        role = await role_repo.get_with_permissions(role_id)
        if role is None:
            raise ValueError("Rôle invalide")

        # On applique exactement la même règle que `_get_assignable_role`.
        if role.tenant_id == tenant_id or (
            role.tenant_id is None and role.name == TENANT_ADMIN_ROLE
        ):
            if any(p.name == "admin:*" for p in (role.permissions or [])):
                raise ValueError("Rôle administrateur plateforme interdit dans une invitation")
            return

        raise ValueError("Le rôle n'appartient pas à ce tenant")

    async def create_invite(
        self,
        tenant_id: str,
        invited_by: str,
        email: str,
        role_id: Optional[str] = None,
        expires_hours: int = 72,
    ) -> Invite:
        await self._validate_role_for_tenant(tenant_id, role_id)

        repo = InviteRepository(self._session)
        invite = Invite(
            tenant_id=tenant_id,
            role_id=role_id,
            invited_by=invited_by,
            email=email,
            token=str(uuid4()),
            expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=expires_hours),
        )
        saved = await repo.save(invite)
        if self._events:
            await self._events.invite_created(
                invite_id=str(saved.id), email=email, tenant_id=tenant_id, invited_by=invited_by
            )
        logger.info("Invite created: email=%s tenant=%s by=%s", email, tenant_id, invited_by)
        return saved

    async def accept_invite(self, token: str, user_id: str) -> TenantMember:
        repo = InviteRepository(self._session)
        invite = await repo.get_by_token(token)

        if invite is None:
            raise ValueError("Invite not found")
        if not invite.is_active:
            raise ValueError("Invite is no longer active")
        if invite.used_at is not None:
            raise ValueError("Invite has already been used")

        now = datetime.now(tz=timezone.utc)
        expires = invite.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            raise ValueError("Invite has expired")

        await self._validate_role_for_tenant(invite.tenant_id, invite.role_id)

        # Create membership
        member_repo = TenantMemberRepository(self._session)
        existing = await member_repo.get_membership(user_id, invite.tenant_id)
        if existing is not None:
            raise ValueError("User is already a member of this tenant")

        membership = TenantMember(
            user_id=user_id,
            tenant_id=invite.tenant_id,
            role_id=invite.role_id,
        )
        await member_repo.save(membership)

        # Mark invite used
        invite.used_at = now
        invite.is_active = False
        await self._session.flush()

        if self._events:
            await self._events.invite_accepted(
                invite_id=str(invite.id), user_id=user_id, tenant_id=invite.tenant_id
            )

        logger.info("Invite accepted: invite=%s user=%s tenant=%s", invite.id, user_id, invite.tenant_id)
        return membership

    async def list_invites(self, tenant_id: str) -> list[Invite]:
        repo = InviteRepository(self._session)
        return await repo.list_for_tenant(tenant_id)

    async def get_invite_by_token(self, token: str) -> Optional[Invite]:
        repo = InviteRepository(self._session)
        return await repo.get_by_token(token)

    async def list_for_email(self, email: str) -> list[Invite]:
        """Invitations en attente pour l'adresse email de l'user connecté."""
        repo = InviteRepository(self._session)
        return await repo.list_for_email(email)

    async def revoke_invite(self, invite_id: str, requester_id: str, privileged: bool = False) -> Invite:
        """`privileged` : l'appelant peut révoquer l'invitation d'un AUTRE — admin plateforme, ou administrateur de
        l'organisation visée (la route le juge : une invitation appartient à son organisation, pas à son auteur).
        """
        repo = InviteRepository(self._session)
        invite = await repo.get(invite_id)
        if invite is None:
            raise ValueError("Invite not found")
        if not privileged and invite.invited_by != requester_id:
            raise PermissionError("Not allowed to revoke this invite")
        invite.is_active = False
        await self._session.flush()
        logger.info("Invite revoked: invite=%s by=%s", invite_id, requester_id)
        return invite
