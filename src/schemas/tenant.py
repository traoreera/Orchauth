from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class TenantCreate(BaseModel):
    name: str
    slug: str
    settings: Optional[dict] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    settings: Optional[dict] = None


class TenantSettingsUpdate(BaseModel):
    settings: dict


class TenantSettingsResponse(BaseModel):
    tenant_id: str
    settings: dict


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime
    is_owner: bool = False
    license_state: Optional[str] = None

    model_config = {"from_attributes": True}


class MemberResponse(BaseModel):
    id: str
    user_id: str
    tenant_id: str
    role_id: Optional[str]
    joined_at: datetime
    is_owner: bool
    email: Optional[str] = None

    model_config = {"from_attributes": True}
