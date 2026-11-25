from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class InviteCreate(BaseModel):
    tenant_id: str
    email: EmailStr
    role_id: Optional[str] = None
    expires_hours: int = 72


class AcceptInviteRequest(BaseModel):
    """L'invitation à accepter. L'identité de qui rejoint vient du JETON de la requête (`get_current_user`), jamais du corps :
    `user_id` est facultatif, gardé pour les clients qui l'envoyaient, et refusé s'il désigne quelqu'un d'autre que la session.
    Il était obligatoire alors que la route ne s'en servait pas : un client qui n'envoyait que `{token}` (le Desk) recevait 422
    à chaque acceptation."""

    token: str
    user_id: Optional[str] = None


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
