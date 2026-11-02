"""Les modules PAYANTS et les abonnements des organisations : quels droits un membre garde.

Règle, une seule : un droit dont l'espace de noms (`caisse` dans `caisse:cash_sale:write`) est un module payant n'est accordé à un
membre d'une organisation que si cette organisation a un abonnement VALIDE à ce module — état `active` ou `trial`, et date de fin
absente ou à venir. Sinon xauth le retire de ceux qu'il calcule (`PermissionService.get_permissions_for_user`, le point par où passent
le jeton, `/rbac/me/permissions` et l'IPC). Un module gratuit (absent de la liste) n'est jamais filtré.

La liste des modules payants est une CONFIGURATION de la plateforme (`licensing.paid_modules` du manifeste, ou la variable
`XAUTH_PAID_MODULES`, séparée par des virgules), posée au chargement par `configure()` : ce n'est pas un plugin qui décide s'il est
payant. Le filtre s'applique APRÈS le cache des droits : un abonnement activé ou suspendu prend effet à la requête suivante.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.license import STATUSES, TenantModule

_paid: frozenset[str] = frozenset()


def configure(paid_modules: Iterable[str]) -> None:
    global _paid
    _paid = frozenset(m.strip() for m in paid_modules if m and m.strip())


def paid_modules() -> frozenset[str]:
    return _paid


def parse_paid(config: dict[str, Any], env: dict[str, Any]) -> list[str]:
    raw = env.get("XAUTH_PAID_MODULES")
    if raw:
        return [m.strip() for m in str(raw).split(",") if m.strip()]
    return list((config.get("licensing") or {}).get("paid_modules") or [])


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def is_valid(row: TenantModule, now: Optional[datetime] = None) -> bool:
    now = now or datetime.now(tz=timezone.utc)
    if row.status not in ("active", "trial"):
        return False
    return row.valid_until is None or _utc(row.valid_until) > now


def namespace(permission: str) -> str:
    return permission.split(":", 1)[0]


def filter_permissions(permissions: Iterable[str], paid: frozenset[str], entitled: set[str]) -> list[str]:
    """Pur : les droits, moins ceux des modules payants auxquels l'organisation n'est pas abonnée."""
    return [p for p in permissions if namespace(p) not in paid or namespace(p) in entitled]


class LicenseService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def rows(self, tenant_id: str) -> list[TenantModule]:
        result = await self._session.execute(select(TenantModule).where(TenantModule.tenant_id == tenant_id).order_by(TenantModule.module))
        return list(result.scalars())

    async def entitled(self, tenant_id: str, now: Optional[datetime] = None) -> set[str]:
        """Les modules payants auxquels l'organisation est abonnée, maintenant."""
        return {r.module for r in await self.rows(tenant_id) if is_valid(r, now)}

    async def licensed(self, permissions: list[str], tenant_id: str) -> list[str]:
        paid = paid_modules()
        if not paid or not any(namespace(p) in paid for p in permissions):
            return permissions  # rien de payant en jeu : pas de requête
        return filter_permissions(permissions, paid, await self.entitled(tenant_id))

    async def set(self, tenant_id: str, module: str, status: str, valid_until: Optional[datetime], note: Optional[str],
                  actor: Optional[str]) -> TenantModule:
        if status not in STATUSES:
            raise ValueError(f"état inconnu : {status!r} (attendu : {', '.join(STATUSES)})")
        row = next((r for r in await self.rows(tenant_id) if r.module == module), None)
        if row is None:
            row = TenantModule(tenant_id=tenant_id, module=module)
            self._session.add(row)
        row.status, row.valid_until, row.note = status, valid_until, note
        row.updated_at, row.updated_by = datetime.now(tz=timezone.utc), actor
        await self._session.flush()
        return row

    async def remove(self, tenant_id: str, module: str) -> bool:
        row = next((r for r in await self.rows(tenant_id) if r.module == module), None)
        if row is None:
            return False
        await self._session.delete(row)
        await self._session.flush()
        return True


def describe(row: TenantModule) -> dict[str, Any]:
    return {
        "module": row.module,
        "status": row.status,
        "valid_until": _utc(row.valid_until).isoformat() if row.valid_until else None,
        "valid": is_valid(row),
        "note": row.note,
        "updated_at": _utc(row.updated_at).isoformat() if row.updated_at else None,
    }
