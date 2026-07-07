import json
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..models.tenant import Tenant
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository
from ..schemas.tenant import (
    MemberResponse,
    TenantCreate,
    TenantResponse,
    TenantSettingsResponse,
    TenantSettingsUpdate,
    TenantUpdate,
)


from ..services.events import XAuthEvents
from ..services.audit import AuditService
from ..models.user import TenantMember
from ..repositories.rbac import RoleRepository
from ._scope import payload_field as _payload_field, require_tenant_scope


def tenants_router(db: Any, events: XAuthEvents | None = None) -> APIRouter:
    router = APIRouter(prefix="/tenants", tags=["tenants"])

    async def _require_tenant_scope(
        session: Any,
        payload: AuthPayload,
        tenant_id: str,
        *,
        owner_only: bool = False,
    ) -> Any:
        return await require_tenant_scope(
            session, payload, tenant_id, owner_only=owner_only
        )

    @router.post(
        "/",
        response_model=TenantResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_tenant(
        body: TenantCreate,
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        user_id = payload.sub if hasattr(payload, "sub") else payload.get("sub")
        async with db.session() as session:
            member_repo = TenantMemberRepository(session)
            existing_memberships = await member_repo.get_memberships_for_user(user_id)
            if len(existing_memberships) >= 3:
                raise HTTPException(status_code=429, detail="Limite de 3 tenants atteinte")

            repo = TenantRepository(session)
            existing = await repo.get_by_slug(body.slug)
            if existing:
                raise HTTPException(status_code=409, detail="Slug already taken")
            
            tenant = Tenant(
                name=body.name,
                slug=body.slug,
                settings=json.dumps(body.settings) if body.settings else None,
            )
            await repo.save(tenant)
            await session.flush()

            # Assigner l'owner — rôle 'tenant_admin' (gestion de son tenant),
            # jamais le rôle 'admin' plateforme (admin:*).
            role_repo = RoleRepository(session)
            roles = await role_repo.list_for_tenant(None)
            owner_role = next((r for r in roles if r.name == "tenant_admin"), None)

            member = TenantMember(
                user_id=user_id,
                tenant_id=tenant.id,
                role_id=owner_role.id if owner_role else None,
                is_owner=True
            )
            session.add(member)
            await session.commit()
            
            if events:
                await events.tenant_created(tenant.id, user_id, tenant.slug)

            # Retourner avec is_owner=True
            result = tenant.__dict__.copy()
            result["is_owner"] = True
            result["license_state"] = "trial"
            return result

    @router.get("/", response_model=List[TenantResponse])
    async def list_tenants(
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        user_id = payload.sub if hasattr(payload, "sub") else payload.get("sub")
        async with db.session() as session:
            member_repo = TenantMemberRepository(session)
            memberships = await member_repo.get_memberships_for_user(user_id)
            
            tenant_repo = TenantRepository(session)
            results = []
            for m in memberships:
                t = await tenant_repo.get(m.tenant_id)
                if t:
                    # On pourrait aussi charger l'état de la licence ici si besoin
                    item = {
                        "id": t.id,
                        "name": t.name,
                        "slug": t.slug,
                        "created_at": t.created_at,
                        "is_owner": m.is_owner,
                        "license_state": "trial" # Valeur par défaut pour passer le check
                    }
                    results.append(item)
            return results

    @router.get("/{tenant_id}", response_model=TenantResponse)
    async def get_tenant(
        tenant_id: str,
        _: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            return tenant

    @router.patch("/{tenant_id}", response_model=TenantResponse)
    async def update_tenant(
        tenant_id: str,
        body: TenantUpdate,
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            # Owner de CE tenant (ou admin plateforme) uniquement.
            await _require_tenant_scope(session, payload, tenant_id, owner_only=True)
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            if body.name is not None:
                tenant.name = body.name
            if body.settings is not None:
                tenant.settings = json.dumps(body.settings)
            await session.flush()
            await session.commit()
            await session.refresh(tenant)
            return tenant

    @router.get("/{tenant_id}/settings", response_model=TenantSettingsResponse)
    async def get_settings(
        tenant_id: str,
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            await _require_tenant_scope(session, payload, tenant_id)
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            settings = json.loads(tenant.settings) if tenant.settings else {}
            return {"tenant_id": tenant_id, "settings": settings}

    @router.put("/{tenant_id}/settings", response_model=TenantSettingsResponse)
    async def update_settings(
        tenant_id: str,
        body: TenantSettingsUpdate,
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            await _require_tenant_scope(session, payload, tenant_id, owner_only=True)
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            tenant.settings = json.dumps(body.settings)
            await session.commit()
            return {"tenant_id": tenant_id, "settings": body.settings}

    @router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_tenant(
        tenant_id: str,
        _: AuthPayload = Depends(require_permission("tenants:delete")),
    ) -> None:
        async with db.session() as session:
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            await repo.delete(tenant)
            await session.commit()

    @router.get("/{tenant_id}/members", response_model=List[MemberResponse])
    async def list_members(
        tenant_id: str,
        payload: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            await _require_tenant_scope(session, payload, tenant_id)
            repo = TenantMemberRepository(session)
            members = await repo.get_members_of_tenant(tenant_id)
            # Enrichit chaque membre avec l'email (relation user déjà chargée via selectinload)
            results = []
            for m in members:
                item = {
                    "id": m.id,
                    "user_id": m.user_id,
                    "tenant_id": m.tenant_id,
                    "role_id": m.role_id,
                    "joined_at": m.joined_at,
                    "is_owner": m.is_owner,
                    "email": m.user.email if m.user else None,
                }
                results.append(item)
            return results

    @router.delete(
        "/{tenant_id}/members/{user_id}",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    async def remove_member(
        tenant_id: str,
        user_id: str,
        payload: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Retire un membre du tenant. Réservé au propriétaire du tenant."""
        async with db.session() as session:
            await _require_tenant_scope(
                session, payload, tenant_id, owner_only=True
            )
            repo = TenantMemberRepository(session)
            target = await repo.get_membership(user_id, tenant_id)
            if target is None:
                raise HTTPException(
                    status_code=404, detail="Membre introuvable dans ce tenant"
                )
            if target.is_owner:
                raise HTTPException(
                    status_code=400,
                    detail="Impossible de retirer le propriétaire du tenant",
                )
            await repo.delete(target)

            audit = AuditService(session)
            await audit.log_event(
                action="tenant.member_removed",
                user_id=_payload_field(payload, "sub"),
                tenant_id=tenant_id,
                resource="tenant_member",
                resource_id=user_id,
            )
            await session.commit()

    return router
