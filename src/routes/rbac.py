from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload
from xcore.sdk import require_permission

from ..services.rbac import RBACService
from ..schemas.rbac import (
    AssignPermissionRequest,
    AssignRoleRequest,
    PermissionCreate,
    PermissionResponse,
    RoleCreate,
    RoleResponse,
)


def rbac_router(db: Any, cache: Any = None) -> APIRouter:
    router = APIRouter(prefix="/rbac", tags=["rbac"])

    def _svc(session) -> RBACService:
        return RBACService(session, cache=cache)

    @router.post(
        "/roles",
        response_model=RoleResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_role(
        body: RoleCreate,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            role = await _svc(session).create_role(
                name=body.name,
                tenant_id=body.tenant_id,
                description=body.description,
            )
            await session.commit()
            await session.refresh(role)
            return role

    @router.get("/roles", response_model=List[RoleResponse])
    async def list_roles(
        tenant_id: str | None = None,
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            return await _svc(session).list_roles(tenant_id=tenant_id)

    @router.get("/roles/{role_id}", response_model=RoleResponse)
    async def get_role(
        role_id: str,
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            role = await _svc(session).get_role(role_id)
            if role is None:
                raise HTTPException(status_code=404, detail="Role not found")
            return role

    @router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
    async def assign_permission(
        role_id: str,
        body: AssignPermissionRequest,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            try:
                role = await _svc(session).assign_permission_to_role(
                    role_id, body.permission_id
                )
                await session.commit()
                await session.refresh(role)
                return role
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))

    @router.delete(
        "/roles/{role_id}/permissions/{permission_id}",
        response_model=RoleResponse,
    )
    async def remove_permission(
        role_id: str,
        permission_id: str,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            try:
                role = await _svc(session).remove_permission_from_role(
                    role_id, permission_id
                )
                await session.commit()
                await session.refresh(role)
                return role
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))

    @router.post("/tenants/{tenant_id}/members/{user_id}/role", response_model=dict)
    async def assign_role_to_member(
        tenant_id: str,
        user_id: str,
        body: AssignRoleRequest,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            try:
                await _svc(session).assign_role_to_member(
                    user_id, tenant_id, body.role_id
                )
                await session.commit()
                return {"success": True, "role_id": body.role_id}
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post(
        "/permissions",
        response_model=PermissionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_permission(
        body: PermissionCreate,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            perm = await _svc(session).create_permission(
                name=body.name, description=body.description
            )
            await session.commit()
            await session.refresh(perm)
            return perm

    @router.get("/permissions", response_model=List[PermissionResponse])
    async def list_permissions(
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            return await _svc(session).list_permissions()

    @router.get(
        "/users/{user_id}/tenants/{tenant_id}/permissions",
        response_model=List[str],
    )
    async def get_user_permissions(
        user_id: str,
        tenant_id: str,
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            return await _svc(session).get_permissions_for_user(user_id, tenant_id)

    return router
