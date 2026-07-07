from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.tenant import Tenant
from ...models.user import TenantMember
from ...repositories.invite import InviteRepository
from ...repositories.rbac import RoleRepository
from ...repositories.session import SessionRepository
from ...repositories.tenant import TenantRepository
from ...repositories.user import TenantMemberRepository, UserRepository
from ..audit import AuditService
from ..events import XAuthEvents
from ..token import TokenService
from .session import SessionService

logger = get_logger(__name__)


class OnboardingService:
    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        events: XAuthEvents | None = None,
        owner_role_name: str = "tenant_admin",
    ) -> None:
        self._session = session
        self._token = token_service
        self._events = events
        self._owner_role_name = owner_role_name

    async def setup_create_tenant(
        self,
        refresh_token: str,
        name: str,
        slug: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        session_svc = SessionService(self._session, self._token, self._events)
        session = await session_svc.resolve_pending_session(refresh_token)

        tenant_repo = TenantRepository(self._session)
        if await tenant_repo.get_by_slug(slug) is not None:
            raise ValueError(f"Le slug '{slug}' est déjà utilisé")

        tenant = Tenant(name=name, slug=slug)
        await tenant_repo.save(tenant)

        role_repo = RoleRepository(self._session)
        global_roles = await role_repo.list_for_tenant(None)
        owner_role = next(
            (r for r in global_roles if r.name == self._owner_role_name), None
        )
        if owner_role is None:
            logger.warning(
                "[xauth] Role '%s' not found — owner created without role for tenant %s",
                self._owner_role_name,
                slug,
            )

        member_repo = TenantMemberRepository(self._session)
        membership = TenantMember(
            user_id=session.user_id,
            tenant_id=tenant.id,
            role_id=owner_role.id if owner_role else None,
            is_owner=True,
        )
        await member_repo.save(membership)

        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=tenant.id
        )
        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)
        session.tenant_id = tenant.id
        session.last_jti = jti
        session.refresh_token = new_refresh_hashed
        await self._session.flush()

        audit = AuditService(self._session)
        await audit.log_event(
            action="tenant.created",
            user_id=session.user_id,
            tenant_id=tenant.id,
            resource="tenant",
            resource_id=tenant.id,
            ip_address=ip_address,
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
            "user_id": session.user_id,
            "tenant_id": tenant.id,
            "mfa_required": False,
            "onboarding_required": False,
            "tenants": None,
        }

    async def setup_join_tenant(
        self,
        refresh_token: str,
        invite_token: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        session_svc = SessionService(self._session, self._token, self._events)
        session = await session_svc.resolve_pending_session(refresh_token)
        now = datetime.now(tz=timezone.utc)

        user_repo = UserRepository(self._session)
        user = await user_repo.get(session.user_id)
        if user is None:
            raise ValueError("Utilisateur introuvable")

        invite_repo = InviteRepository(self._session)
        invite = await invite_repo.get_by_token(invite_token)

        if invite is None or not invite.is_active or invite.used_at is not None:
            raise ValueError("Code d'invitation invalide ou déjà utilisé")

        invite_expires = invite.expires_at
        if invite_expires.tzinfo is None:
            invite_expires = invite_expires.replace(tzinfo=timezone.utc)
        if invite_expires < now:
            raise ValueError("Le code d'invitation a expiré")

        if invite.email.lower() != user.email.lower():
            raise ValueError(
                "Cette invitation n'est pas destinée à votre adresse email"
            )

        member_repo = TenantMemberRepository(self._session)
        if await member_repo.get_membership(user.id, invite.tenant_id) is not None:
            raise ValueError("Vous êtes déjà membre de ce tenant")

        membership = TenantMember(
            user_id=user.id,
            tenant_id=invite.tenant_id,
            role_id=invite.role_id,
        )
        await member_repo.save(membership)

        invite.used_at = now
        invite.is_active = False
        await self._session.flush()

        access_token, jti = self._token.create_access_token(
            user_id=user.id, tenant_id=invite.tenant_id
        )
        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)
        session.tenant_id = invite.tenant_id
        session.last_jti = jti
        session.refresh_token = new_refresh_hashed
        await self._session.flush()

        audit = AuditService(self._session)
        await audit.log_event(
            action="tenant.joined",
            user_id=user.id,
            tenant_id=invite.tenant_id,
            resource="tenant",
            resource_id=invite.tenant_id,
            ip_address=ip_address,
        )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": invite.tenant_id,
            "mfa_required": False,
            "onboarding_required": False,
            "tenants": None,
        }
