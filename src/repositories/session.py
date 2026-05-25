from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from ..models.session import Session
from .base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    model = Session

    async def get_by_refresh_token(self, hashed_token: str) -> Optional[Session]:
        result = await self.session.execute(
            select(Session)
            .where(Session.refresh_token == hashed_token)
            .where(Session.is_revoked == False)  # noqa: E712
        )
        return result.scalar_one_or_none()

    async def get_active_sessions_for_user(self, user_id: str) -> list[Session]:
        result = await self.session.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .where(Session.is_revoked == False)  # noqa: E712
        )
        return list(result.scalars().all())

    async def revoke_all_for_user(self, user_id: str) -> None:
        sessions = await self.get_active_sessions_for_user(user_id)
        for s in sessions:
            s.is_revoked = True
        await self.session.flush()
