from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..repositories.user import TenantMemberRepository
from ..services.rbac import (
    MemberRoleService,
    PermissionService,
    RoleService,
)
from ..schemas.rbac import (
    AssignPermissionRequest,
    AssignRoleRequest,
    CreateTenantRoleRequest,
    GrantMemberPermissionRequest,
    PermissionCreate,
    PermissionResponse,
    RoleCreate,
    RoleResponse,
)


def rbac_router(db: Any, cache: Any = None) -> APIRouter:
    router = APIRouter(prefix="/rbac", tags=["rbac"])

    async def _require_tenant_admin(
        tenant_id: str, user: AuthPayload
    ) -> None:
        """Scope owner : admin plateforme (admin:*) OU owner du tenant ciblé.

        Remplace le gate global `rbac:write` pour les opérations déléguées :
        le owner gère SON tenant sans pouvoir toucher aux autres.
        """
        if "admin:*" in (user.get("permissions", []) or []):
            return
        async with db.session() as session:
            membership = await TenantMemberRepository(session).get_membership(
                user["sub"], tenant_id
            )
        if membership is None or not membership.is_owner:
            raise HTTPException(
                status_code=403,
                detail="Réservé au propriétaire du tenant.",
            )

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
            svc = RoleService(session, cache=cache)
            role = await svc.create_role(
                name=body.name,
                tenant_id=body.tenant_id,
                description=body.description,
            )
            await session.commit()
            role = await svc.get_role(role.id)
            return RoleResponse.model_validate(role)

    @router.get("/roles", response_model=List[RoleResponse])
    async def list_roles(
        tenant_id: str | None = None,
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            roles = await RoleService(session, cache=cache).list_roles(tenant_id=tenant_id)
            return [RoleResponse.model_validate(r) for r in roles]

    @router.get("/roles/{role_id}", response_model=RoleResponse)
    async def get_role(
        role_id: str,
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            role = await RoleService(session, cache=cache).get_role(role_id)
            if role is None:
                raise HTTPException(status_code=404, detail="Role not found")
            return RoleResponse.model_validate(role)

    @router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
    async def assign_permission(
        role_id: str,
        body: AssignPermissionRequest,
        _: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            svc = RoleService(session, cache=cache)
            try:
                role = await svc.assign_permission_to_role(
                    role_id, body.permission_id
                )
                await session.commit()
                role = await svc.get_role(role.id)
                return RoleResponse.model_validate(role)
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
            svc = RoleService(session, cache=cache)
            try:
                role = await svc.remove_permission_from_role(
                    role_id, permission_id
                )
                await session.commit()
                role = await svc.get_role(role.id)
                return RoleResponse.model_validate(role)
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))

    @router.post("/tenants/{tenant_id}/members/{user_id}/role", response_model=dict)
    async def assign_role_to_member(
        tenant_id: str,
        user_id: str,
        body: AssignRoleRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        # Scope owner : le propriétaire du tenant (ou admin:*) assigne un rôle.
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            try:
                await RoleService(session, cache=cache).assign_role_to_member(
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
            perm = await PermissionService(session, cache=cache).create_permission(
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
            return await PermissionService(session, cache=cache).list_permissions()

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
            return await PermissionService(session, cache=cache).get_permissions_for_user(user_id, tenant_id)

    # ── « Moi » : droits de l'utilisateur courant (gating UI frontend) ────────
    # Authentifié uniquement — aucun droit RBAC requis : chacun lit SES propres
    # permissions dans son tenant courant.

    def _current_tenant(user: AuthPayload) -> str | None:
        return user.get("tenant_id") or user.get("user", {}).get("tenant_id")

    @router.get(
        "/me/permissions",
        response_model=List[str],
        summary="Mes permissions effectives dans le tenant courant",
    )
    async def my_permissions(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        tenant_id = _current_tenant(user)
        if not tenant_id:
            return []
        async with db.session() as session:
            return await PermissionService(session, cache=cache).get_permissions_for_user(user["sub"], tenant_id)

    @router.get(
        "/me/roles",
        response_model=List[str],
        summary="Mes rôles dans le tenant courant",
    )
    async def my_roles(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        tenant_id = _current_tenant(user)
        if not tenant_id:
            return []
        async with db.session() as session:
            return await MemberRoleService(session, cache=cache).list_member_roles(user["sub"], tenant_id)

    # ── Surface OWNER (tenant-scopée) ─────────────────────────────────────────
    # Pas de gate `rbac:write` global : on autorise le owner du tenant ciblé.
    # Catalogue agrégé depuis les plugins, borné aux permissions délégables.

    @router.get(
        "/tenants/{tenant_id}/grantable",
        response_model=List[PermissionResponse],
        summary="Permissions que le owner peut déléguer (agrégé plugins)",
    )
    async def list_grantable(
        tenant_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            # entitled_plugins=None pour l'instant (intersection entitlement
            # xlicense = hook à venir). Renvoie tout ce qui est délégable.
            return await PermissionService(session, cache=cache).list_grantable_permissions()

    @router.post(
        "/tenants/{tenant_id}/roles",
        response_model=RoleResponse,
        status_code=status.HTTP_201_CREATED,
        summary="Créer un rôle propre au tenant (owner)",
    )
    async def create_tenant_role(
        tenant_id: str,
        body: CreateTenantRoleRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            svc = RoleService(session, cache=cache)
            role = await svc.create_tenant_role(
                tenant_id=tenant_id,
                name=body.name,
                permission_names=body.permissions,
                description=body.description,
            )
            await session.commit()
            role = await svc.get_role(role.id)
            return RoleResponse.model_validate(role)

    @router.post(
        "/tenants/{tenant_id}/members/{user_id}/permissions",
        summary="Accorder une permission à un membre (toggle owner)",
    )
    async def grant_member_permission(
        tenant_id: str,
        user_id: str,
        body: GrantMemberPermissionRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> dict:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            try:
                await PermissionService(session, cache=cache).grant_permission_to_member(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    permission_name=body.permission_name,
                    granted_by=user["sub"],
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        return {"success": True, "permission": body.permission_name}

    @router.delete(
        "/tenants/{tenant_id}/members/{user_id}/permissions/{permission_name}",
        summary="Retirer une permission d'un membre (toggle owner)",
    )
    async def revoke_member_permission(
        tenant_id: str,
        user_id: str,
        permission_name: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> dict:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            removed = await PermissionService(session, cache=cache).revoke_permission_from_member(
                user_id, tenant_id, permission_name
            )
            await session.commit()
        return {"success": removed, "permission": permission_name}

    # ── Owner : gestion des rôles de tenant + listing membres ────────────────

    @router.get(
        "/tenants/{tenant_id}/roles",
        response_model=List[RoleResponse],
        summary="Lister les rôles propres au tenant (owner)",
    )
    async def list_tenant_roles(
        tenant_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            roles = await RoleService(session, cache=cache).list_tenant_roles(tenant_id)
            return [RoleResponse.model_validate(r) for r in roles]

    @router.post(
        "/tenants/{tenant_id}/roles/{role_id}/permissions",
        response_model=RoleResponse,
        summary="Ajouter une permission à un rôle de tenant (owner)",
    )
    async def add_perm_to_tenant_role(
        tenant_id: str,
        role_id: str,
        body: GrantMemberPermissionRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            svc = RoleService(session, cache=cache)
            try:
                role = await svc.add_permission_to_tenant_role(
                    tenant_id, role_id, body.permission_name
                )
                await session.commit()
                role = await svc.get_role(role.id)
                return RoleResponse.model_validate(role)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.delete(
        "/tenants/{tenant_id}/roles/{role_id}/permissions/{permission_name}",
        response_model=RoleResponse,
        summary="Retirer une permission d'un rôle de tenant (owner)",
    )
    async def remove_perm_from_tenant_role(
        tenant_id: str,
        role_id: str,
        permission_name: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            svc = RoleService(session, cache=cache)
            try:
                role = await svc.remove_permission_from_tenant_role(
                    tenant_id, role_id, permission_name
                )
                await session.commit()
                role = await svc.get_role(role.id)
                return RoleResponse.model_validate(role)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.delete(
        "/tenants/{tenant_id}/roles/{role_id}",
        summary="Supprimer un rôle de tenant (owner)",
    )
    async def delete_tenant_role(
        tenant_id: str,
        role_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> dict:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            try:
                await RoleService(session, cache=cache).delete_tenant_role(tenant_id, role_id)
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        return {"success": True, "role_id": role_id}

    @router.get(
        "/tenants/{tenant_id}/members",
        summary="Lister les membres du tenant + leur rôle (owner)",
    )
    async def list_tenant_members(
        tenant_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            return await MemberRoleService(session, cache=cache).list_tenant_members(tenant_id)

    @router.get(
        "/tenants/{tenant_id}/members/{user_id}/permissions",
        response_model=List[str],
        summary="Permissions effectives d'un membre (rôles ∪ directes)",
    )
    async def member_effective_permissions(
        tenant_id: str,
        user_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            return await PermissionService(session, cache=cache).get_permissions_for_user(user_id, tenant_id)

    # ── Owner : multi-rôles d'un membre ──────────────────────────────────────

    @router.get(
        "/tenants/{tenant_id}/members/{user_id}/roles",
        response_model=List[str],
        summary="Lister les rôles d'un membre (primaire + multi-rôles)",
    )
    async def list_member_roles(
        tenant_id: str,
        user_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            return await MemberRoleService(session, cache=cache).list_member_roles(user_id, tenant_id)

    @router.post(
        "/tenants/{tenant_id}/members/{user_id}/roles",
        summary="Ajouter un rôle à un membre (cumulatif, multi-rôles)",
    )
    async def add_role_to_member(
        tenant_id: str,
        user_id: str,
        body: AssignRoleRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> dict:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            try:
                await MemberRoleService(session, cache=cache).add_role_to_member(
                    user_id, tenant_id, body.role_id, granted_by=user["sub"]
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        return {"success": True, "role_id": body.role_id}

    @router.delete(
        "/tenants/{tenant_id}/members/{user_id}/roles/{role_id}",
        summary="Retirer un rôle d'un membre (multi-rôles)",
    )
    async def remove_role_from_member(
        tenant_id: str,
        user_id: str,
        role_id: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> dict:
        await _require_tenant_admin(tenant_id, user)
        async with db.session() as session:
            removed = await MemberRoleService(session, cache=cache).remove_role_from_member(
                user_id, tenant_id, role_id
            )
            await session.commit()
        return {"success": removed, "role_id": role_id}

    return router
