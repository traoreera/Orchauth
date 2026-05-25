from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.audit import AuditLog
from ..repositories.audit import AuditLogRepository


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def log_event(
        self,
        action: str,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        resource: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditLog:
        repo = AuditLogRepository(self._session)
        entry = AuditLog(
            action=action,
            tenant_id=tenant_id,
            user_id=user_id,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            meta=json.dumps(metadata) if metadata else None,
        )
        return await repo.save(entry)

    async def list_for_tenant(
        self, tenant_id: str, limit: int = 100, offset: int = 0
    ) -> list[AuditLog]:
        repo = AuditLogRepository(self._session)
        return await repo.list_for_tenant(tenant_id, limit=limit, offset=offset)

    async def list_for_user(
        self, user_id: str, limit: int = 100, offset: int = 0
    ) -> list[AuditLog]:
        repo = AuditLogRepository(self._session)
        return await repo.list_for_user(user_id, limit=limit, offset=offset)
