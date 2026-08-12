from __future__ import annotations

from typing import Optional

from sqlalchemy import select, update
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

    async def user_tenant_status(self, tenant_id: str, user_id: str, status: bool) -> dict:
        # 1. Vérifier si l'utilisateur appartient bien au tenant
        has_membership = (await self.session.execute(
            select(TenantMember)
            .where(TenantMember.user_id == user_id)
            .where(TenantMember.tenant_id == tenant_id)
        )).scalar_one_or_none()

        if not has_membership:
            return {"error": "User not found in this tenant"}

        # 2. Mettre à jour le statut de l'utilisateur — scopé au tenant ET à l'utilisateur,
        # jamais l'un sans l'autre (sinon désactive l'utilisateur dans tous ses tenants).
        await self.session.execute(
            update(TenantMember)
            .where(TenantMember.user_id == user_id)
            .where(TenantMember.tenant_id == tenant_id)
            .values(user_tenant_status=status)
        )
        
        # 3. Valider la transaction
        await self.session.flush()

        return {
            "user_id": user_id,
            "status": status
        }