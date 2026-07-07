from __future__ import annotations

from sqlalchemy import select, update

from ..models.notification import Notification
from .base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    model = Notification

    async def list_for_user(self, user_id: str, limit: int = 100, offset: int = 0) -> list[Notification]:
        result = await self.session.execute(
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def mark_read(self, notification_id: str, user_id: str) -> bool:
        result = await self.session.execute(
            update(Notification)
            .where(Notification.id == notification_id, Notification.user_id == user_id)
            .values(is_read=True)
        )
        return result.rowcount > 0

    async def mark_all_read(self, user_id: str) -> int:
        result = await self.session.execute(
            update(Notification)
            .where(Notification.user_id == user_id, Notification.is_read.is_(False))
            .values(is_read=True)
        )
        return result.rowcount

    async def delete_for_user(self, notification_id: str, user_id: str) -> bool:
        n = await self.session.get(Notification, notification_id)
        if not n or n.user_id != user_id:
            return False
        await self.session.delete(n)
        return True
