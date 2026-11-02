"""Les abonnements des organisations aux modules payants (services/licensing.py).

    GET    /licenses/catalog                              les modules payants de la plateforme
    GET    /licenses/tenants/{tenant_id}                  chaque module payant et l'abonnement de l'organisation (ou son absence)
    PUT    /licenses/tenants/{tenant_id}/{module}         {status, valid_until?, note?} : abonne, prolonge, suspend
    DELETE /licenses/tenants/{tenant_id}/{module}         retire l'abonnement

Lire : un MEMBRE de l'organisation (savoir ce qu'on a payé n'est pas un secret pour qui en fait partie), ou l'administrateur de la
plateforme. Écrire : `license:manage` seulement (l'administrateur de la plateforme) — le propriétaire d'une organisation ne s'abonne
pas lui-même tant que le paiement n'est pas branché. Chaque écriture va au journal d'audit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..models.license import STATUSES
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository
from ..services.audit import AuditService
from ..services.licensing import LicenseService, describe, paid_modules


class LicenseRequest(BaseModel):
    status: str = Field(description=f"un de : {', '.join(STATUSES)}")
    valid_until: Optional[datetime] = None
    note: Optional[str] = Field(default=None, max_length=1000)


def licenses_router(db: Any) -> APIRouter:
    router = APIRouter(prefix="/licenses", tags=["licenses"])

    async def _may_read(tenant_id: str, user: AuthPayload) -> None:
        perms = user.get("permissions", []) or []
        if "admin:*" in perms or "license:manage" in perms:
            return
        async with db.session() as session:
            if await TenantMemberRepository(session).get_membership(user["sub"], tenant_id) is None:
                raise HTTPException(status_code=403, detail="Réservé aux membres de l'organisation.")

    async def _tenant(session: Any, tenant_id: str) -> None:
        if await TenantRepository(session).get(tenant_id) is None:
            raise HTTPException(status_code=404, detail="Organisation introuvable.")

    def _paid(module: str) -> None:
        if module not in paid_modules():
            raise HTTPException(status_code=422, detail=f"« {module} » n'est pas un module payant de la plateforme.")

    @router.get("/catalog")
    async def catalog(_: AuthPayload = Depends(get_current_user)) -> dict:
        return {"paid_modules": sorted(paid_modules())}

    @router.get("/tenants/{tenant_id}")
    async def tenant_licenses(tenant_id: str, user: AuthPayload = Depends(get_current_user)) -> dict:
        await _may_read(tenant_id, user)
        async with db.session() as session:
            await _tenant(session, tenant_id)
            rows = {r.module: describe(r) for r in await LicenseService(session).rows(tenant_id)}
        return {"tenant_id": tenant_id, "modules": [rows.get(m) or {"module": m, "status": None, "valid": False}
                                                    for m in sorted(paid_modules())]}

    @router.put("/tenants/{tenant_id}/{module}")
    async def set_license(tenant_id: str, module: str, body: LicenseRequest,
                          user: AuthPayload = Depends(require_permission("license:manage"))) -> dict:
        _paid(module)
        if body.status not in STATUSES:
            raise HTTPException(status_code=422, detail=f"État inconnu : {body.status} (attendu : {', '.join(STATUSES)}).")
        until = body.valid_until.astimezone(timezone.utc).replace(tzinfo=None) if body.valid_until else None
        async with db.session() as session:
            await _tenant(session, tenant_id)
            row = await LicenseService(session).set(tenant_id, module, body.status, until, body.note, user["sub"])
            out = describe(row)
            await AuditService(session).log_event("license.set", tenant_id=tenant_id, user_id=user["sub"], resource="license",
                                                  resource_id=module, metadata={"status": body.status, "valid_until": out["valid_until"]})
            await session.commit()
        return out

    @router.delete("/tenants/{tenant_id}/{module}", status_code=204)
    async def remove_license(tenant_id: str, module: str,
                             user: AuthPayload = Depends(require_permission("license:manage"))) -> None:
        _paid(module)
        async with db.session() as session:
            if not await LicenseService(session).remove(tenant_id, module):
                raise HTTPException(status_code=404, detail="Aucun abonnement à ce module.")
            await AuditService(session).log_event("license.remove", tenant_id=tenant_id, user_id=user["sub"], resource="license",
                                                  resource_id=module)
            await session.commit()

    return router
