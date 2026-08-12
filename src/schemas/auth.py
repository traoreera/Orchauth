from typing import Optional
from pydantic import BaseModel, EmailStr


class TenantInfo(BaseModel):
    id: str
    name: Optional[str] = None
    slug: Optional[str] = None
    role_id: Optional[str] = None
    is_owner: bool = False

class SelectTenantRequest(BaseModel):
    refresh_token: str
    tenant_id: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: Optional[str] = None
    device_fingerprint: Optional[str] = None


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class SetupCreateRequest(BaseModel):
    refresh_token: str
    name: str
    slug: str


class SetupJoinRequest(BaseModel):
    refresh_token: str
    invite_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None        # challenge JWT court (5 min) si mfa_required=true
    onboarding_required: bool = False
    tenants: Optional[list[TenantInfo]] = None


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool
    mfa_enabled: bool
    has_password: bool = False

    model_config = {"from_attributes": True}
