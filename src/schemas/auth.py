from typing import Optional
from pydantic import BaseModel, EmailStr, model_validator


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
    username: Optional[str] = None  # facultatif : une seconde façon de se connecter (services/auth/username.py)


class LoginRequest(BaseModel):
    """On se connecte avec une adresse e-mail OU un nom d'utilisateur. `email` accepte aussi un nom (anciens clients : l'écran de connexion y mettait ce que
    l'on tapait) ; `username` est la forme explicite. Ce qui contient `@` est une adresse, le reste un nom : voir `identifier`."""

    email: Optional[str] = None
    username: Optional[str] = None
    password: str
    tenant_id: Optional[str] = None
    device_fingerprint: Optional[str] = None

    @model_validator(mode="after")
    def _one_identifier(self) -> "LoginRequest":
        if not (self.username or self.email or "").strip():
            raise ValueError("Adresse e-mail ou nom d'utilisateur requis")
        if len(self.identifier) > 255:
            raise ValueError("Identifiant trop long")
        return self

    @property
    def identifier(self) -> str:
        return (self.username or self.email or "").strip()


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
    username: Optional[str] = None
    is_active: bool
    mfa_enabled: bool
    has_password: bool = False

    model_config = {"from_attributes": True}
