from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update

from ..models.invite import Invite
from .base import BaseRepository


class InviteRepository(BaseRepository[Invite]):
    model = Invite

    async def get_by_token(self, token: str) -> Optional[Invite]:
        result = await self.session.execute(
            select(Invite).where(Invite.token == token)
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: str) -> list[Invite]:
        result = await self.session.execute(
            select(Invite).where(Invite.tenant_id == tenant_id)
        )
        return list(result.scalars().all())

    async def deactivate_expired(self) -> int:
        """Marque comme inactives toutes les invitations expirées. Retourne le nombre traité."""
        now = datetime.now(tz=timezone.utc)
        result = await self.session.execute(
            update(Invite)
            .where(Invite.is_active == True)  # noqa: E712
            .where(Invite.expires_at < now)
            .values(is_active=False)
        )
        await self.session.flush()
        return result.rowcount
