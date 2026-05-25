from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from ..models.oauth import OAuthAccount
from .base import BaseRepository


class OAuthAccountRepository(BaseRepository[OAuthAccount]):
    model = OAuthAccount

    async def get_by_provider(
        self, provider: str, provider_user_id: str
    ) -> Optional[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount)
            .where(OAuthAccount.provider == provider)
            .where(OAuthAccount.provider_user_id == provider_user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_user_and_provider(
        self, user_id: str, provider: str
    ) -> Optional[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount)
            .where(OAuthAccount.user_id == user_id)
            .where(OAuthAccount.provider == provider)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: str) -> list[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount).where(OAuthAccount.user_id == user_id)
        )
        return list(result.scalars().all())
