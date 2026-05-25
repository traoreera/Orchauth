from typing import Optional
from pydantic import BaseModel, EmailStr


class UserRootSchemas(BaseModel):

    ADMIN_EMAIL: str
    ADMIN_PASSWORD: str
    ADMIN_TENANT_SLUG: str
    ADMIN_TENANT_NAME: str
    ADMIN_ROLE_NAME: str
    USER_ROLE_NAME: str



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
    onboarding_required: bool = False  # ← true si l'user n'appartient à aucun tenant
    tenants: Optional[list[TenantInfo]] = None  # ← présent uniquement si multi-tenant


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool
    mfa_enabled: bool

    class Config:
        from_attributes = True
