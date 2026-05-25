from typing import List, Optional
from pydantic import BaseModel


class RoleCreate(BaseModel):
    name: str
    tenant_id: Optional[str] = None
    description: Optional[str] = None


class PermissionCreate(BaseModel):
    name: str
    description: Optional[str] = None


class AssignPermissionRequest(BaseModel):
    permission_id: str


class AssignRoleRequest(BaseModel):
    role_id: str


class PermissionResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]

    class Config:
        from_attributes = True


class RoleResponse(BaseModel):
    id: str
    name: str
    tenant_id: Optional[str]
    description: Optional[str]
    permissions: List[PermissionResponse] = []

    class Config:
        from_attributes = True
