from __future__ import annotations

from xcore.sdk import (
    AutoDispatchMixin,
    action,
    error,
    get_logger,
    ok,
    schema,
)

logger = get_logger(__name__)


class IPCCommands(AutoDispatchMixin):
    """
    IPC actions for the xauth plugin.
    Inheriting class must provide self._db and self._cache attributes
    plus self._token_service as a TokenService instance.
    """

    @action("xauth.verify_token")
    @schema(
        version="1.0",
        input={"token": (str, ...)},
        output={"user_id": str, "tenant_id": str, "permissions": list, "jti": str},
        type_response="model",
        unset=False,
    )
    async def _ipc_verify_token(self, payload) -> dict:
        try:
            claims = self._token_service.verify_access_token(payload.token)
            tenant_id = claims.get("tenant_id")
            user_id = claims["sub"]
            permissions: list[str] = []
            if tenant_id:
                async with self._db.session() as session:
                    from .services.rbac import PermissionService
                    svc = PermissionService(session, cache=self._cache)
                    permissions = await svc.get_permissions_for_user(user_id, tenant_id)
            return ok(
                user_id=user_id,
                tenant_id=tenant_id,
                permissions=permissions,
                jti=claims.get("jti"),
            )
        except ValueError as exc:
            return error(str(exc), code="invalid_token")
        except Exception as exc:
            return error(f"Token verification failed: {exc}", code="error")

    @action("xauth.has_permission")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "tenant_id": (str, ...), "permission": (str, ...)},
        output={"has_permission": bool},
        type_response="model",
        unset=False,
    )
    async def _ipc_has_permission(self, payload) -> dict:
        try:
            async with self._db.session() as session:
                from .services.rbac import PermissionService
                svc = PermissionService(session, cache=self._cache)
                result = await svc.has_permission(payload.user_id, payload.tenant_id, payload.permission)
            return ok(has_permission=result)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.has_permission_scoped")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...),
            "tenant_id": (str, ...),
            "permission": (str, ...),
            "scope_type": (str, None),
            "scope_id": (str, None),
        },
        output={"has_permission": bool},
        type_response="model",
        unset=False,
    )
    async def _ipc_has_permission_scoped(self, payload) -> dict:
        """Vérifie une permission dans un scope (ex: scope_type="entrepot", scope_id=<uuid>).

        scope_type/scope_id absents ⇒ équivaut à xauth.has_permission (global).
        Une permission globale (scope NULL) reste valable dans tout scope.
        """
        try:
            async with self._db.session() as session:
                from .services.rbac import PermissionService
                svc = PermissionService(session, cache=self._cache)
                result = await svc.has_permission(
                    payload.user_id,
                    payload.tenant_id,
                    payload.permission,
                    getattr(payload, "scope_type", None),
                    getattr(payload, "scope_id", None),
                )
            return ok(has_permission=result)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.get_user")
    @schema(
        version="1.0",
        input={"user_id": (str, ...)},
        output={"user": dict},
        type_response="model",
        unset=False,
    )
    async def _ipc_get_user(self, payload) -> dict:
        try:
            async with self._db.session() as session:
                from .repositories.user import UserRepository
                repo = UserRepository(session)
                user = await repo.get(payload.user_id)
                if user is None:
                    return error("User not found", code="not_found")
                return ok(user={
                    "id": user.id,
                    "email": user.email,
                    "is_active": user.is_active,
                    "mfa_enabled": user.mfa_enabled,
                })
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.get_tenant")
    @schema(
        version="1.0",
        input={"tenant_id": (str, ...)},
        output={"tenant": dict},
        type_response="model",
        unset=False,
    )
    async def _ipc_get_tenant(self, payload) -> dict:
        try:
            async with self._db.session() as session:
                from .repositories.tenant import TenantRepository
                repo = TenantRepository(session)
                tenant = await repo.get(payload.tenant_id)
                if tenant is None:
                    return error("Tenant not found", code="not_found")
                return ok(tenant={
                    "id": tenant.id,
                    "name": tenant.name,
                    "slug": tenant.slug,
                })
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.tenant_access")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "tenant_id": (str, ...), "permissions": (list, None)},
        output={"has_access": bool, "can_manage": bool},
        type_response="model",
        unset=False,
    )
    async def _ipc_tenant_access(self, payload) -> dict:
        try:
            perms = getattr(payload, "permissions", None) or []
            if "admin:*" in perms:
                return ok(has_access=True, can_manage=True)
            async with self._db.session() as session:
                from .repositories.user import TenantMemberRepository
                member_repo = TenantMemberRepository(session)
                membership = await member_repo.get_membership(payload.user_id, payload.tenant_id)
                if membership is None:
                    return ok(has_access=False, can_manage=False)
                can_manage = bool(membership.is_owner) or any(
                    p in perms for p in ("license:write", "license:manage")
                )
                return ok(has_access=True, can_manage=can_manage)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.create_invite")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...),
            "invited_by": (str, ...),
            "email": (str, ...),
            "role_id": (str, None),
            "expires_hours": (int, 72),
        },
        output={"invite": dict},
        type_response="model",
        unset=False,
    )
    async def _ipc_create_invite(self, payload) -> dict:
        try:
            async with self._db.session() as session:
                from .services.invite import InviteService
                svc = InviteService(session)
                invite = await svc.create_invite(
                    tenant_id=payload.tenant_id,
                    invited_by=payload.invited_by,
                    email=payload.email,
                    role_id=getattr(payload, "role_id", None),
                    expires_hours=getattr(payload, "expires_hours", 72),
                )
                await session.commit()
                return ok(invite={
                    "id": invite.id,
                    "token": invite.token,
                    "email": invite.email,
                    "tenant_id": invite.tenant_id,
                    "expires_at": invite.expires_at.isoformat(),
                })
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.log_event")
    @schema(
        version="1.0",
        input={
            "action": (str, ...),
            "tenant_id": (str, None),
            "user_id": (str, None),
            "resource": (str, None),
            "resource_id": (str, None),
            "ip_address": (str, None),
            "user_agent": (str, None),
            "metadata": (dict, None),
        },
        output={"audit_log_id": str},
        type_response="model",
        unset=False,
    )
    async def _ipc_log_event(self, payload) -> dict:
        try:
            async with self._db.session() as session:
                from .services.audit import AuditService
                svc = AuditService(session)
                entry = await svc.log_event(
                    action=payload.action,
                    tenant_id=getattr(payload, "tenant_id", None),
                    user_id=getattr(payload, "user_id", None),
                    resource=getattr(payload, "resource", None),
                    resource_id=getattr(payload, "resource_id", None),
                    ip_address=getattr(payload, "ip_address", None),
                    user_agent=getattr(payload, "user_agent", None),
                    metadata=getattr(payload, "metadata", None),
                )
                await session.commit()
                return ok(audit_log_id=entry.id)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.users.list.tenant")
    @schema(
        version="1.0",
        input={"tenant_id": (str, None)},
        output={"users": list},
        type_response="model",
        unset=False,
    )
    async def _ipc_list_tenant_users(self, payload):
        from .repositories.user import TenantMemberRepository
        async with self._db.session() as sess:
            repo = TenantMemberRepository(sess)
            users = await repo.get_members_of_tenant(payload.tenant_id)
            logger.info(f"users: {users}, tenant_id: {payload.tenant_id}")
        return ok(users=[user.user_id for user in users])
