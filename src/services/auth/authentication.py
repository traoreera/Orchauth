from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.session import Session
from ...models.user import TenantMember, User
from ...repositories.session import SessionRepository
from ...repositories.tenant import TenantRepository
from ...repositories.user import TenantMemberRepository, UserRepository
from ..audit import AuditService
from ..events import XAuthEvents
from ..token import TokenService
from .password import get_pwd_context

logger = get_logger(__name__)


class AuthenticationService:
    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        events: XAuthEvents | None = None,
        cache: Any = None,
    ) -> None:
        self._session = session
        self._token = token_service
        self._events = events
        self._cache = cache

    async def login(
        self,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> dict[str, Any]:
        audit = AuditService(self._session)
        user_repo = UserRepository(self._session)
        user = await user_repo.get_by_email(email)
        if user is None or not get_pwd_context().verify(password, user.hashed_password):
            await audit.log_event(
                action="login.failed",
                ip_address=ip_address,
                metadata={"email": email, "reason": "invalid_credentials"},
            )
            if self._events:
                await self._events.user_login_failed(
                    email=email, ip=ip_address, reason="invalid_credentials"
                )
            logger.warning("Login failed: invalid credentials for %s (ip=%s)", email, ip_address)
            raise ValueError("Invalid credentials")
        if not user.is_active:
            await audit.log_event(
                action="login.failed",
                user_id=user.id,
                ip_address=ip_address,
                metadata={"reason": "account_inactive"},
            )
            if self._events:
                await self._events.user_login_failed(
                    email=email, ip=ip_address, reason="account_inactive"
                )
            logger.warning("Login failed: account inactive for %s (ip=%s)", email, ip_address)
            raise ValueError("Account is inactive")

        member_repo = TenantMemberRepository(self._session)

        if not tenant_id:
            memberships = await member_repo.get_memberships_for_user(user.id)

            if not memberships:
                access_token, jti = self._token.create_access_token(
                    user_id=user.id, tenant_id=None
                )
                refresh_token_plain = self._token.create_refresh_token()
                refresh_token_hashed = self._token.hash_token(refresh_token_plain)
                session_repo = SessionRepository(self._session)
                if device_fingerprint:
                    await session_repo.revoke_active_for_device(user.id, device_fingerprint)
                pending_session = Session.build(
                    user_id=user.id,
                    refresh_token=refresh_token_hashed,
                    device_fingerprint=device_fingerprint,
                    ip_address=ip_address,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(days=self._token.refresh_expire),
                    last_jti=jti,
                )
                await session_repo.save(pending_session)
                await audit.log_event(
                    action="login.onboarding_required",
                    user_id=user.id,
                    ip_address=ip_address,
                    metadata={"reason": "no_membership"},
                )
                await self._events.user_login(
                    user_id=user.id, ip=ip_address, email=email
                )
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token_plain,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": None,
                    "mfa_required": False,
                    "onboarding_required": True,
                    "tenants": [],
                }

            if len(memberships) == 1:
                tenant_id = memberships[0].tenant_id
            else:
                refresh_token_plain = self._token.create_refresh_token()
                refresh_token_hashed = self._token.hash_token(refresh_token_plain)
                session = Session.build(
                    user_id=user.id,
                    refresh_token=refresh_token_hashed,
                    device_fingerprint=device_fingerprint,
                    ip_address=ip_address,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(days=self._token.refresh_expire),
                )
                await SessionRepository(self._session).save(session)

                tenant_repo = TenantRepository(self._session)
                tenants = []
                for m in memberships:
                    t = await tenant_repo.get(m.tenant_id)
                    tenants.append(
                        {
                            "id": m.tenant_id,
                            "name": t.name if t else None,
                            "slug": t.slug if t else None,
                            "role_id": m.role_id,
                            "is_owner": m.is_owner,
                        }
                    )

                return {
                    "access_token": "",
                    "refresh_token": refresh_token_plain,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": None,
                    "mfa_required": user.mfa_enabled,
                    "tenants": tenants,
                }
        else:
            membership = await member_repo.get_membership(user.id, tenant_id)
            if membership is None:
                raise ValueError("User is not a member of this tenant")
            if not membership.user_tenant_status:
                raise ValueError("Your account is desactivate on this organisation")

        refresh_token_plain = self._token.create_refresh_token()
        refresh_token_hashed = self._token.hash_token(refresh_token_plain)
        session_repo = SessionRepository(self._session)

        if user.mfa_enabled:
            mfa_token = self._token.create_mfa_challenge_token(
                user_id=user.id, tenant_id=tenant_id
            )
            return {
                "access_token": "",
                "refresh_token": "",
                "mfa_token": mfa_token,
                "token_type": "bearer",
                "user_id": user.id,
                "tenant_id": tenant_id,
                "mfa_required": True,
                "tenants": None,
            }

        access_token, jti = self._token.create_access_token(
            user_id=user.id, tenant_id=tenant_id, email=user.email
        )

        if device_fingerprint:
            await session_repo.revoke_active_for_device(user.id, device_fingerprint)

        session = Session.build(
            user_id=user.id,
            tenant_id=tenant_id,
            refresh_token=refresh_token_hashed,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token.refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(session)

        await audit.log_event(
            action="login.success",
            user_id=user.id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            resource="session",
            resource_id=session.id,
        )
        if self._events:
            await self._events.user_login(
                user_id=user.id, email=user.email, ip=ip_address, tenant_id=tenant_id
            )

        logger.info("Login successful: user=%s tenant=%s ip=%s", user.id, tenant_id, ip_address)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    async def select_tenant(
        self,
        refresh_token: str,
        tenant_id: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)

        if session is None:
            raise ValueError("Invalid or expired refresh token")

        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")

        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(session.user_id, tenant_id)
        if membership is None:
            raise ValueError("User is not a member of this tenant")

        if session.user.mfa_enabled:
            # `session.user` est déjà chargée en eager loading par
            # SessionRepository.get_by_refresh_token() (selectinload) — on
            # évite volontairement `membership.user`, qui lazy-load et lève
            # MissingGreenlet en session async (TenantMemberRepository.get_membership
            # ne fait pas de selectinload sur .user).
            mfa_token = self._token.create_mfa_challenge_token(user_id=session.user_id, tenant_id=tenant_id)
            return {
                "access_token": "",
                "refresh_token": "",
                "mfa_token": mfa_token,
                "token_type": "bearer",
                "user_id": session.user_id,
                "tenant_id": tenant_id,
                "mfa_required": True,
                "tenants": None,
            }
            # TODO: document it for frontend api integration to update this verification elements

        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=tenant_id
        )

        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)

        session.is_revoked = True
        await self._session.flush()

        new_session = Session.build(
            user_id=session.user_id,
            tenant_id=tenant_id,
            refresh_token=new_refresh_hashed,
            device_fingerprint=session.device_fingerprint,
            ip_address=ip_address or session.ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token.refresh_expire),
            last_jti=jti,
        )
        await SessionRepository(self._session).save(new_session)

        if self._events:
            await self._events.user_login(
                user_id=session.user_id,
                email=session.user.email,
                ip=ip_address,
                tenant_id=tenant_id,
            )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
            "user_id": session.user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    async def verify_mfa_and_issue_token(
        self,
        mfa_token: str,
        totp_code: str,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> dict[str, Any]:
        try:
            claims = self._token.verify_mfa_challenge_token(mfa_token)
        except ValueError as exc:
            raise ValueError(f"Challenge MFA invalide : {exc}") from exc

        user_id = claims["sub"]
        tenant_id = claims.get("tenant_id")

        from ..mfa import MFAService # fixed: import here to avoid circular import

        mfa_svc = MFAService(self._session)
        valid = await mfa_svc.verify_totp(user_id, totp_code)
        if not valid:
            raise ValueError("Code MFA invalide ou expiré")

        refresh_plain = self._token.create_refresh_token()
        refresh_hashed = self._token.hash_token(refresh_plain)
        access_token, jti = self._token.create_access_token(
            user_id=user_id, tenant_id=tenant_id
        )

        session_repo = SessionRepository(self._session)
        if device_fingerprint:
            await session_repo.revoke_active_for_device(user_id, device_fingerprint)

        session = Session.build(
            user_id=user_id,
            tenant_id=tenant_id,
            refresh_token=refresh_hashed,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token.refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(session)

        return {
            "access_token": access_token,
            "refresh_token": refresh_plain,
            "token_type": "bearer",
            "user_id": user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }
