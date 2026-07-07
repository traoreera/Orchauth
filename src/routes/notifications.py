from __future__ import annotations

import html
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..models.notification import Notification
from ..repositories.notification import NotificationRepository


class NotificationOut(BaseModel):
    id: str
    user_id: str
    tenant_id: Optional[str]
    title: str
    message: Optional[str]
    type: str
    link: Optional[str]
    is_read: bool
    created_at: str

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm(cls, n: Notification) -> "NotificationOut":
        return cls(
            id=n.id,
            user_id=n.user_id,
            tenant_id=n.tenant_id,
            title=html.escape(n.title) if n.title else n.title,
            message=html.escape(n.message) if n.message else n.message,
            type=n.type,
            link=n.link if n.link and not n.link.startswith("javascript:") else None,
            is_read=n.is_read,
            created_at=n.created_at.isoformat(),
        )


class CreateNotificationBody(BaseModel):
    title: str
    message: Optional[str] = None
    type: str = "SYSTEM"
    link: Optional[str] = None
    user_id: Optional[str] = None  # si absent → utilisateur courant


def notifications_router(db: Any) -> APIRouter:
    router = APIRouter(prefix="/notifications", tags=["notifications"])

    @router.get("", response_model=List[NotificationOut])
    async def list_notifications(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            repo = NotificationRepository(session)
            items = await repo.list_for_user(user["sub"], limit=limit, offset=offset)
            return [NotificationOut.from_orm(n) for n in items]

    @router.post("", response_model=NotificationOut, status_code=status.HTTP_201_CREATED)
    async def create_notification(
        body: CreateNotificationBody,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        if body.link and body.link.startswith("javascript:"):
            raise HTTPException(status_code=400, detail="Invalid link")
        target_user_id = body.user_id or user["sub"]
        tenant_id = (user.get("user") or {}).get("tenant_id")
        async with db.session() as session:
            repo = NotificationRepository(session)
            n = Notification(
                user_id=target_user_id,
                tenant_id=tenant_id,
                title=body.title,
                message=body.message,
                type=body.type,
                link=body.link,
            )
            n = await repo.save(n)
            await session.commit()
            await session.refresh(n)
            return NotificationOut.from_orm(n)

    @router.patch("/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
    async def mark_read(
        notification_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        async with db.session() as session:
            repo = NotificationRepository(session)
            await repo.mark_read(notification_id, user["sub"])
            await session.commit()

    @router.patch("/read-all", status_code=status.HTTP_204_NO_CONTENT)
    async def mark_all_read(
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        async with db.session() as session:
            repo = NotificationRepository(session)
            await repo.mark_all_read(user["sub"])
            await session.commit()

    @router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_notification(
        notification_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        async with db.session() as session:
            repo = NotificationRepository(session)
            await repo.delete_for_user(notification_id, user["sub"])
            await session.commit()

    return router
