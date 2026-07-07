from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: str
    tenant_id: Optional[str]
    user_id: Optional[str]
    action: str
    resource: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    meta: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}
