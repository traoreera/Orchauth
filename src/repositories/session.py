from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..models.session import Session
from .base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    model = Session

    async def get_by_refresh_token(self, hashed_token: str) -> Optional[Session]:
        result = await self.session.execute(
            select(Session)
            .options(selectinload(Session.user))
            .where(Session.refresh_token == hashed_token)
            .where(Session.is_revoked.is_(False))
        )
        return result.scalar_one_or_none()

    async def get_active_sessions_for_user(self, user_id: str) -> list[Session]:
        result = await self.session.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .where(Session.is_revoked.is_(False))
        )
        return list(result.scalars().all())

    async def revoke_all_for_user(self, user_id: str) -> None:
        sessions = await self.get_active_sessions_for_user(user_id)
        for s in sessions:
            s.is_revoked = True
        await self.session.flush()

    async def revoke_active_for_device(self, user_id: str, device_fingerprint: str) -> int:
        """Révoque les sessions actives du même (user, appareil) — appelé avant
        d'en créer une nouvelle pour éviter l'accumulation de sessions périmées
        sur le même appareil (reconnexions après expiration, redémarrage app…).
        """
        result = await self.session.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .where(Session.device_fingerprint == device_fingerprint)
            .where(Session.is_revoked.is_(False))
        )
        sessions = list(result.scalars().all())
        for s in sessions:
            s.is_revoked = True
        if sessions:
            await self.session.flush()
        return len(sessions)
