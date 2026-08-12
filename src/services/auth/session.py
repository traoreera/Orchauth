from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.session import Session
from ...repositories.session import SessionRepository
from ..audit import AuditService
from ..events import XAuthEvents
from ..token import TokenService
from .password import _JTI_BLACKLIST_PREFIX

logger = get_logger(__name__)


class SessionService:
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

    async def refresh(
        self, refresh_token: str, ip_address: Optional[str] = None
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
            logger.warning("Refresh token expired for user %s", session.user_id)
            raise ValueError("Refresh token expired")

        session.is_revoked = True
        await self._session.flush()

        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)

        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=session.tenant_id
        )

        new_session = Session.build(
            user_id=session.user_id,
            tenant_id=session.tenant_id,
            refresh_token=new_refresh_hashed,
            device_fingerprint=session.device_fingerprint,
            ip_address=ip_address or session.ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token.refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(new_session)

        if self._events:
            await self._events.session_refreshed(
                user_id=session.user_id, tenant_id=session.tenant_id
            )

        logger.info("Session refreshed: user=%s tenant=%s", session.user_id, session.tenant_id)

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
        }

    async def logout(self, refresh_token: str) -> None:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)
        if session:
            audit = AuditService(self._session)
            await audit.log_event(
                action="logout",
                user_id=session.user_id,
                tenant_id=session.tenant_id,
                resource="session",
                resource_id=session.id,
            )
            logger.info("User logged out: user=%s tenant=%s", session.user_id, session.tenant_id)
            if self._cache and session.last_jti:
                ttl = self._token.access_expire * 60 + 30
                await self._cache.set(
                    f"{_JTI_BLACKLIST_PREFIX}{session.last_jti}", "1", ttl=ttl
                )
            session.is_revoked = True
            await self._session.flush()
            if self._events:
                await self._events.user_logout(user_id=session.user_id)

    async def resolve_pending_session(self, refresh_token: str) -> Session:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)
        if session is None or session.is_revoked:
            raise ValueError("Invalid or expired refresh token")
        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")
        return session

    async def invalidate_all_sessions(self, user_id: str) -> None:
        await SessionRepository(self._session).revoke_all_for_user(user_id=user_id)

        if self._events:
            await self._events.password_changed(user_id=user_id)