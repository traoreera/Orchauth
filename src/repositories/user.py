from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..models.user import User, TenantMember
from .base import BaseRepository



class UserRepository(BaseRepository[User]):
    model = User

    async def get_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_with_memberships(self, user_id: str) -> Optional[User]:
        result = await self.session.execute(
            select(User)
            .options(selectinload(User.tenant_memberships))
            .where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self, limit: int = 50, offset: int = 0) -> list[User]:
        result = await self.session.execute(
            select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())


class TenantMemberRepository(BaseRepository[TenantMember]):
    model = TenantMember

    async def get_membership(
        self, user_id: str, tenant_id: str
    ) -> Optional[TenantMember]:
        result = await self.session.execute(
            select(TenantMember)
            .where(TenantMember.user_id == user_id)
            .where(TenantMember.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()

    async def get_memberships_for_user(self, user_id: str) -> list[TenantMember]:
        result = await self.session.execute(
            select(TenantMember).where(TenantMember.user_id == user_id)
        )
        return list(result.scalars().all())

    async def get_members_of_tenant(self, tenant_id: str) -> list[TenantMember]:
        result = await self.session.execute(
            select(TenantMember)
            .options(selectinload(TenantMember.user))
            .where(TenantMember.tenant_id == tenant_id)
        )
        return list(result.scalars().all())
