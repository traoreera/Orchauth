from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class InviteCreate(BaseModel):
    tenant_id: str
    email: EmailStr
    role_id: Optional[str] = None
    expires_hours: int = 72


class AcceptInviteRequest(BaseModel):
    token: str
    user_id: str


class InviteResponse(BaseModel):
    id: str
    tenant_id: str
    tenant_name: Optional[str] = None
    email: str
    token: str
    role_id: Optional[str]
    expires_at: datetime
    used_at: Optional[datetime]
    is_active: bool
    invited_by: str

    model_config = {"from_attributes": True}
