from __future__ import annotations

import re
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.rbac import Permission
from ...repositories.rbac import PermissionRepository

logger = get_logger("xauth.rbac.grants")

RESERVED_NAMESPACES = {"admin", "rbac", "auth", "tenants", "user", "license", "plugins"}
_GRANT_NAME_RE = re.compile(r"^[a-z0-9_]+:[a-z0-9_]+(:[a-z0-9_]+)*$")


def _is_valid_grant(plugin: str, name: str) -> bool:
    if plugin in RESERVED_NAMESPACES:
        return False
    if not name or not _GRANT_NAME_RE.match(name):
        return False
    return name.split(":", 1)[0] == plugin


class PluginGrantService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def reconcile_plugin_grants(
        self, plugin: str, grants: list[dict]
    ) -> dict[str, int]:
        perm_repo = PermissionRepository(self._session)
        desired: dict[str, dict] = {}
        for g in grants or []:
            name = (g or {}).get("name")
            if _is_valid_grant(plugin, name):
                desired[name] = g

        upserted = 0
        for name, g in desired.items():
            perm = await perm_repo.get_by_name(name)
            if perm is None:
                perm = Permission(name=name)
            perm.description = g.get("description")
            perm.group = g.get("group")
            perm.tenant_grantable = bool(g.get("tenant_grantable", False))
            perm.source_plugin = plugin
            perm.active = True
            await perm_repo.save(perm)
            upserted += 1

        disabled = 0
        for perm in await perm_repo.list_by_plugin(plugin):
            if perm.name not in desired and perm.active:
                perm.active = False
                await perm_repo.save(perm)
                disabled += 1

        logger.info(
            "Plugin '%s' grants reconciled: %d upserted, %d disabled",
            plugin, upserted, disabled,
        )
        return {"upserted": upserted, "disabled": disabled}

    async def disable_plugin(self, plugin: str) -> int:
        perm_repo = PermissionRepository(self._session)
        count = 0
        for perm in await perm_repo.list_by_plugin(plugin):
            if perm.active:
                perm.active = False
                await perm_repo.save(perm)
                count += 1
        logger.info("Plugin '%s' disabled: %d permissions deactivated", plugin, count)
        return count
