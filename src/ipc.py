from __future__ import annotations

from typing import Optional

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
        return ok(users=[{
            "id": user.user_id,
            "email":user.user.email 
            }for user in users])


    @action("xauth.users.change.status")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...),
            "user_id": (str, ...),
            "enabled": (bool, False)
        },
        output={
            "user_id":(str, ...),
            "status":(bool, False)
        }, type_response= 'model',unset=True,
    )
    async def _ipc_user_status(self, payload):

        from .repositories.user import TenantMemberRepository
        async with self._db.session() as sess:
            user = await TenantMemberRepository(sess).user_tenant_status(
                tenant_id= payload.tenant_id,
                user_id= payload.user_id,
                status= payload.enabled
            )
            if not user or "error" in user:
                return error(str(user.get("error", "not working failed")) if user else "not working failed", code="not_found")
            await sess.commit()
            return ok(**user)

    @action("xauth.organisation.list.tenant")
    @schema(version= "0.1.0", output={"tenant":(list[str], [])})
    async def _ipc_all_tenant(self, payload):
        from .repositories.tenant import TenantRepository
        async with self._db.session() as sess:
            return ok(tenant = (await TenantRepository(sess).get_all()))

    # ── Google (Gmail / Calendar) au nom d'un utilisateur ───────────────────
    #
    # Auth est le seul plugin à posséder les jetons Google chiffrés
    # (OAuthAccount) — les autres plugins passent par ces actions IPC plutôt
    # que de manipuler un access_token directement, qui ne traverse jamais
    # la frontière IPC. Chaque action ci-dessous suit le même squelette
    # (_google_call résout le token puis invoque la méthode correspondante
    # de ext.google) — voir extensions/googleService/service.py pour le détail
    # de chaque appel HTTP réel.

    async def _google_access_token(self, sess, user_id: str) -> str:
        from .services.oauth import OAuthService

        svc = OAuthService(
            sess, self._token_service, self._cache,
            self._oauth_providers, token_cipher=self._token_cipher,
        )
        token = await svc.get_valid_access_token(user_id, "google")
        if not token:
            raise ValueError(
                "Aucun compte Google lié (avec les scopes Gmail/Calendar) pour cet utilisateur."
            )
        return token

    async def _google_call(self, user_id: str, method_name: str, *args, **kwargs):
        if self._google is None:
            raise RuntimeError("Extension ext.google non configurée.")
        async with self._db.session() as sess:
            token = await self._google_access_token(sess, user_id)
            await sess.commit()
        method = getattr(self._google, method_name)
        return await method(token, *args, **kwargs)

    def _google_error(self, exc: Exception, action_name: str, user_id: str):
        if isinstance(exc, RuntimeError) and "non configurée" in str(exc):
            return error(str(exc), code="unavailable")
        if isinstance(exc, ValueError):
            return error(str(exc), code="no_google_account")
        logger.warning("%s échoué pour %s : %s", action_name, user_id, exc)
        return error(str(exc), code="google_api_error")

    # ── Gmail : messages ─────────────────────────────────────────────────────

    @action("xauth.google.gmail.send")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "to": (str, ...), "subject": (str, ...),
            "body_text": (Optional[str], None), "body_html": (Optional[str], None),
            "cc": (Optional[str], None), "bcc": (Optional[str], None),
        },
        output={"message_id": (Optional[str], None)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_send(self, payload):
        try:
            result = await self._google_call(
                payload.user_id, "send_email",
                to=payload.to, subject=payload.subject,
                body_text=getattr(payload, "body_text", None),
                body_html=getattr(payload, "body_html", None),
                cc=getattr(payload, "cc", None), bcc=getattr(payload, "bcc", None),
            )
            return ok(message_id=(result or {}).get("id"))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.send", payload.user_id)

    @action("xauth.google.gmail.list_messages")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "query": (Optional[str], None),
            "label_ids": (Optional[list], None), "max_results": (int, 50), "page_token": (Optional[str], None),
        },
        output={"messages": (list, []), "next_page_token": (Optional[str], None), "result_size_estimate": (int, 0)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_list_messages(self, payload):
        try:
            data = await self._google_call(
                payload.user_id, "list_messages",
                query=getattr(payload, "query", None),
                label_ids=getattr(payload, "label_ids", None),
                max_results=getattr(payload, "max_results", 50) or 50,
                page_token=getattr(payload, "page_token", None),
            ) or {}
            return ok(
                messages=data.get("messages", []),
                next_page_token=data.get("nextPageToken"),
                result_size_estimate=data.get("resultSizeEstimate", 0),
            )
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.list_messages", payload.user_id)

    @action("xauth.google.gmail.get_message")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "message_id": (str, ...), "format": (str, "full")},
        output={"message": (Optional[dict], None)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_message(self, payload):
        try:
            msg = await self._google_call(
                payload.user_id, "get_message", payload.message_id,
                format=getattr(payload, "format", "full") or "full",
            )
            return ok(message=msg)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_message", payload.user_id)

    @action("xauth.google.gmail.trash_message")
    @schema(
        version="1.0", input={"user_id": (str, ...), "message_id": (str, ...)},
        output={"message": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_trash_message(self, payload):
        try:
            msg = await self._google_call(payload.user_id, "trash_message", payload.message_id)
            return ok(message=msg)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.trash_message", payload.user_id)

    @action("xauth.google.gmail.untrash_message")
    @schema(
        version="1.0", input={"user_id": (str, ...), "message_id": (str, ...)},
        output={"message": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_untrash_message(self, payload):
        try:
            msg = await self._google_call(payload.user_id, "untrash_message", payload.message_id)
            return ok(message=msg)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.untrash_message", payload.user_id)

    @action("xauth.google.gmail.delete_message")
    @schema(
        version="1.0", input={"user_id": (str, ...), "message_id": (str, ...)},
        output={"deleted": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_delete_message(self, payload):
        """Suppression PERMANENTE — nécessite le scope restreint
        https://mail.google.com/, non demandé par défaut (voir
        providers/google.py) : échouera avec google_api_error/403 tant que ce
        scope n'est pas explicitement accordé. Préférer trash_message."""
        try:
            await self._google_call(payload.user_id, "delete_message", payload.message_id)
            return ok(deleted=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.delete_message", payload.user_id)

    @action("xauth.google.gmail.modify_message_labels")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "message_id": (str, ...),
            "add_label_ids": (Optional[list], None), "remove_label_ids": (Optional[list], None),
        },
        output={"message": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_modify_message_labels(self, payload):
        try:
            msg = await self._google_call(
                payload.user_id, "modify_message_labels", payload.message_id,
                add_label_ids=getattr(payload, "add_label_ids", None),
                remove_label_ids=getattr(payload, "remove_label_ids", None),
            )
            return ok(message=msg)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.modify_message_labels", payload.user_id)

    @action("xauth.google.gmail.get_attachment")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "message_id": (str, ...), "attachment_id": (str, ...)},
        output={"size": (int, 0), "data": (Optional[str], None)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_attachment(self, payload):
        try:
            data = await self._google_call(
                payload.user_id, "get_attachment", payload.message_id, payload.attachment_id,
            ) or {}
            return ok(size=data.get("size", 0), data=data.get("data"))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_attachment", payload.user_id)

    # ── Gmail : threads ──────────────────────────────────────────────────────

    @action("xauth.google.gmail.list_threads")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "query": (Optional[str], None), "label_ids": (Optional[list], None),
            "max_results": (int, 50), "page_token": (Optional[str], None),
        },
        output={"threads": (list, []), "next_page_token": (Optional[str], None)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_list_threads(self, payload):
        try:
            data = await self._google_call(
                payload.user_id, "list_threads",
                query=getattr(payload, "query", None),
                label_ids=getattr(payload, "label_ids", None),
                max_results=getattr(payload, "max_results", 50) or 50,
                page_token=getattr(payload, "page_token", None),
            ) or {}
            return ok(threads=data.get("threads", []), next_page_token=data.get("nextPageToken"))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.list_threads", payload.user_id)

    @action("xauth.google.gmail.get_thread")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "thread_id": (str, ...), "format": (str, "full")},
        output={"thread": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_thread(self, payload):
        try:
            thread = await self._google_call(
                payload.user_id, "get_thread", payload.thread_id,
                format=getattr(payload, "format", "full") or "full",
            )
            return ok(thread=thread)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_thread", payload.user_id)

    @action("xauth.google.gmail.trash_thread")
    @schema(
        version="1.0", input={"user_id": (str, ...), "thread_id": (str, ...)},
        output={"thread": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_trash_thread(self, payload):
        try:
            thread = await self._google_call(payload.user_id, "trash_thread", payload.thread_id)
            return ok(thread=thread)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.trash_thread", payload.user_id)

    @action("xauth.google.gmail.modify_thread_labels")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "thread_id": (str, ...),
            "add_label_ids": (Optional[list], None), "remove_label_ids": (Optional[list], None),
        },
        output={"thread": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_modify_thread_labels(self, payload):
        try:
            thread = await self._google_call(
                payload.user_id, "modify_thread_labels", payload.thread_id,
                add_label_ids=getattr(payload, "add_label_ids", None),
                remove_label_ids=getattr(payload, "remove_label_ids", None),
            )
            return ok(thread=thread)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.modify_thread_labels", payload.user_id)

    # ── Gmail : labels ───────────────────────────────────────────────────────

    @action("xauth.google.gmail.list_labels")
    @schema(
        version="1.0", input={"user_id": (str, ...)},
        output={"labels": (list, [])}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_list_labels(self, payload):
        try:
            labels = await self._google_call(payload.user_id, "list_labels")
            return ok(labels=labels)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.list_labels", payload.user_id)

    @action("xauth.google.gmail.get_label")
    @schema(
        version="1.0", input={"user_id": (str, ...), "label_id": (str, ...)},
        output={"label": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_label(self, payload):
        try:
            label = await self._google_call(payload.user_id, "get_label", payload.label_id)
            return ok(label=label)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_label", payload.user_id)

    @action("xauth.google.gmail.create_label")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "name": (str, ...),
            "label_list_visibility": (str, "labelShow"),
            "message_list_visibility": (str, "show"),
        },
        output={"label": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_create_label(self, payload):
        try:
            label = await self._google_call(
                payload.user_id, "create_label", payload.name,
                label_list_visibility=getattr(payload, "label_list_visibility", "labelShow") or "labelShow",
                message_list_visibility=getattr(payload, "message_list_visibility", "show") or "show",
            )
            return ok(label=label)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.create_label", payload.user_id)

    @action("xauth.google.gmail.update_label")
    @schema(
        version="1.0", input={"user_id": (str, ...), "label_id": (str, ...), "patch": (dict, ...)},
        output={"label": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_update_label(self, payload):
        try:
            label = await self._google_call(payload.user_id, "update_label", payload.label_id, payload.patch)
            return ok(label=label)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.update_label", payload.user_id)

    @action("xauth.google.gmail.delete_label")
    @schema(
        version="1.0", input={"user_id": (str, ...), "label_id": (str, ...)},
        output={"deleted": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_delete_label(self, payload):
        try:
            await self._google_call(payload.user_id, "delete_label", payload.label_id)
            return ok(deleted=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.delete_label", payload.user_id)

    # ── Gmail : drafts ───────────────────────────────────────────────────────

    @action("xauth.google.gmail.list_drafts")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "max_results": (int, 50), "page_token": (Optional[str], None)},
        output={"drafts": (list, []), "next_page_token": (Optional[str], None)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_list_drafts(self, payload):
        try:
            data = await self._google_call(
                payload.user_id, "list_drafts",
                max_results=getattr(payload, "max_results", 50) or 50,
                page_token=getattr(payload, "page_token", None),
            ) or {}
            return ok(drafts=data.get("drafts", []), next_page_token=data.get("nextPageToken"))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.list_drafts", payload.user_id)

    @action("xauth.google.gmail.get_draft")
    @schema(
        version="1.0", input={"user_id": (str, ...), "draft_id": (str, ...)},
        output={"draft": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_draft(self, payload):
        try:
            draft = await self._google_call(payload.user_id, "get_draft", payload.draft_id)
            return ok(draft=draft)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_draft", payload.user_id)

    @action("xauth.google.gmail.create_draft")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "to": (str, ...), "subject": (str, ...),
            "body_text": (Optional[str], None), "body_html": (Optional[str], None),
        },
        output={"draft": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_create_draft(self, payload):
        try:
            draft = await self._google_call(
                payload.user_id, "create_draft", payload.to, payload.subject,
                body_text=getattr(payload, "body_text", None),
                body_html=getattr(payload, "body_html", None),
            )
            return ok(draft=draft)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.create_draft", payload.user_id)

    @action("xauth.google.gmail.update_draft")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "draft_id": (str, ...), "to": (str, ...), "subject": (str, ...),
            "body_text": (Optional[str], None), "body_html": (Optional[str], None),
        },
        output={"draft": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_update_draft(self, payload):
        try:
            draft = await self._google_call(
                payload.user_id, "update_draft", payload.draft_id, payload.to, payload.subject,
                body_text=getattr(payload, "body_text", None),
                body_html=getattr(payload, "body_html", None),
            )
            return ok(draft=draft)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.update_draft", payload.user_id)

    @action("xauth.google.gmail.send_draft")
    @schema(
        version="1.0", input={"user_id": (str, ...), "draft_id": (str, ...)},
        output={"message_id": (Optional[str], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_send_draft(self, payload):
        try:
            result = await self._google_call(payload.user_id, "send_draft", payload.draft_id)
            return ok(message_id=(result or {}).get("id"))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.send_draft", payload.user_id)

    @action("xauth.google.gmail.delete_draft")
    @schema(
        version="1.0", input={"user_id": (str, ...), "draft_id": (str, ...)},
        output={"deleted": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_gmail_delete_draft(self, payload):
        try:
            await self._google_call(payload.user_id, "delete_draft", payload.draft_id)
            return ok(deleted=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.delete_draft", payload.user_id)

    # ── Gmail : profil ───────────────────────────────────────────────────────

    @action("xauth.google.gmail.get_profile")
    @schema(
        version="1.0", input={"user_id": (str, ...)},
        output={"email_address": (Optional[str], None), "messages_total": (int, 0), "threads_total": (int, 0)},
        type_response="model", unset=False,
    )
    async def _ipc_google_gmail_get_profile(self, payload):
        try:
            profile = await self._google_call(payload.user_id, "get_profile") or {}
            return ok(
                email_address=profile.get("emailAddress"),
                messages_total=profile.get("messagesTotal", 0),
                threads_total=profile.get("threadsTotal", 0),
            )
        except Exception as exc:
            return self._google_error(exc, "xauth.google.gmail.get_profile", payload.user_id)

    # ── Calendar : calendarList ──────────────────────────────────────────────

    @action("xauth.google.calendar.list_calendar_list")
    @schema(
        version="1.0", input={"user_id": (str, ...), "min_access_role": (Optional[str], None)},
        output={"calendars": (list, [])}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_list_calendar_list(self, payload):
        try:
            items = await self._google_call(
                payload.user_id, "list_calendar_list",
                min_access_role=getattr(payload, "min_access_role", None),
            )
            return ok(calendars=items)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.list_calendar_list", payload.user_id)

    @action("xauth.google.calendar.get_calendar_list_entry")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, ...)},
        output={"calendar": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_get_calendar_list_entry(self, payload):
        try:
            entry = await self._google_call(
                payload.user_id, "get_calendar_list_entry", payload.calendar_id
            )
            return ok(calendar=entry)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.get_calendar_list_entry", payload.user_id)

    @action("xauth.google.calendar.subscribe_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, ...)},
        output={"calendar": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_subscribe_calendar(self, payload):
        try:
            entry = await self._google_call(payload.user_id, "subscribe_calendar", payload.calendar_id)
            return ok(calendar=entry)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.subscribe_calendar", payload.user_id)

    @action("xauth.google.calendar.unsubscribe_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, ...)},
        output={"unsubscribed": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_unsubscribe_calendar(self, payload):
        try:
            await self._google_call(payload.user_id, "unsubscribe_calendar", payload.calendar_id)
            return ok(unsubscribed=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.unsubscribe_calendar", payload.user_id)

    # ── Calendar : calendars ─────────────────────────────────────────────────

    @action("xauth.google.calendar.create_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "summary": (str, ...), "time_zone": (Optional[str], None)},
        output={"calendar": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_create_calendar(self, payload):
        try:
            cal = await self._google_call(
                payload.user_id, "create_calendar", payload.summary,
                time_zone=getattr(payload, "time_zone", None),
            )
            return ok(calendar=cal)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.create_calendar", payload.user_id)

    @action("xauth.google.calendar.get_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, "primary")},
        output={"calendar": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_get_calendar(self, payload):
        try:
            cal = await self._google_call(
                payload.user_id, "get_calendar", getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(calendar=cal)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.get_calendar", payload.user_id)

    @action("xauth.google.calendar.update_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, ...), "patch": (dict, ...)},
        output={"calendar": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_update_calendar(self, payload):
        try:
            cal = await self._google_call(
                payload.user_id, "update_calendar", payload.calendar_id, payload.patch
            )
            return ok(calendar=cal)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.update_calendar", payload.user_id)

    @action("xauth.google.calendar.delete_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, ...)},
        output={"deleted": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_delete_calendar(self, payload):
        try:
            await self._google_call(payload.user_id, "delete_calendar", payload.calendar_id)
            return ok(deleted=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.delete_calendar", payload.user_id)

    @action("xauth.google.calendar.clear_calendar")
    @schema(
        version="1.0", input={"user_id": (str, ...), "calendar_id": (str, "primary")},
        output={"cleared": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_clear_calendar(self, payload):
        try:
            await self._google_call(
                payload.user_id, "clear_calendar", getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(cleared=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.clear_calendar", payload.user_id)

    # ── Calendar : events ────────────────────────────────────────────────────

    @action("xauth.google.calendar.create_event")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "calendar_id": (str, "primary"), "event": (dict, ...),
            "send_updates": (Optional[str], None),
        },
        output={"event": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_create_event(self, payload):
        try:
            created = await self._google_call(
                payload.user_id, "create_event", payload.event,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
                send_updates=getattr(payload, "send_updates", None),
            )
            return ok(event=created)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.create_event", payload.user_id)

    @action("xauth.google.calendar.list_events")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "calendar_id": (str, "primary"),
            "time_min": (Optional[str], None), "time_max": (Optional[str], None), "query": (Optional[str], None),
            "max_results": (int, 50), "page_token": (Optional[str], None),
        },
        output={"events": (list, [])}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_list_events(self, payload):
        try:
            events = await self._google_call(
                payload.user_id, "list_events",
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
                time_min=getattr(payload, "time_min", None),
                time_max=getattr(payload, "time_max", None),
                query=getattr(payload, "query", None),
                max_results=getattr(payload, "max_results", 50) or 50,
                page_token=getattr(payload, "page_token", None),
            )
            return ok(events=events)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.list_events", payload.user_id)

    @action("xauth.google.calendar.get_event")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "event_id": (str, ...), "calendar_id": (str, "primary")},
        output={"event": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_get_event(self, payload):
        try:
            event = await self._google_call(
                payload.user_id, "get_event", payload.event_id,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(event=event)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.get_event", payload.user_id)

    @action("xauth.google.calendar.update_event")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "event_id": (str, ...), "event": (dict, ...),
            "calendar_id": (str, "primary"),
        },
        output={"event": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_update_event(self, payload):
        try:
            updated = await self._google_call(
                payload.user_id, "update_event", payload.event_id, payload.event,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(event=updated)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.update_event", payload.user_id)

    @action("xauth.google.calendar.delete_event")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "event_id": (str, ...), "calendar_id": (str, "primary")},
        output={"deleted": (bool, False)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_delete_event(self, payload):
        try:
            await self._google_call(
                payload.user_id, "delete_event", payload.event_id,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(deleted=True)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.delete_event", payload.user_id)

    @action("xauth.google.calendar.move_event")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "event_id": (str, ...), "destination_calendar_id": (str, ...),
            "calendar_id": (str, "primary"),
        },
        output={"event": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_move_event(self, payload):
        try:
            moved = await self._google_call(
                payload.user_id, "move_event", payload.event_id, payload.destination_calendar_id,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(event=moved)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.move_event", payload.user_id)

    @action("xauth.google.calendar.quick_add_event")
    @schema(
        version="1.0",
        input={"user_id": (str, ...), "text": (str, ...), "calendar_id": (str, "primary")},
        output={"event": (Optional[dict], None)}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_quick_add_event(self, payload):
        try:
            created = await self._google_call(
                payload.user_id, "quick_add_event", payload.text,
                calendar_id=getattr(payload, "calendar_id", "primary") or "primary",
            )
            return ok(event=created)
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.quick_add_event", payload.user_id)

    # ── Calendar : disponibilité ─────────────────────────────────────────────

    @action("xauth.google.calendar.query_freebusy")
    @schema(
        version="1.0",
        input={
            "user_id": (str, ...), "time_min": (str, ...), "time_max": (str, ...),
            "calendar_ids": (list, ...),
        },
        output={"calendars": (dict, {})}, type_response="model", unset=False,
    )
    async def _ipc_google_calendar_query_freebusy(self, payload):
        try:
            data = await self._google_call(
                payload.user_id, "query_freebusy", payload.time_min, payload.time_max, payload.calendar_ids,
            ) or {}
            return ok(calendars=data.get("calendars", {}))
        except Exception as exc:
            return self._google_error(exc, "xauth.google.calendar.query_freebusy", payload.user_id)

    # ── Rôles / permissions — IPC serveur-à-serveur ──────────────────────────
    #
    # Auparavant, assigner/lire un rôle ou des permissions n'existait qu'en
    # HTTP, gated par le JWT de l'utilisateur lui-même (routes/rbac.py) —
    # aucun autre plugin ne pouvait le faire pour son compte (ex. branch
    # attribuant un rôle au moment où il rattache un membre à une branche).
    # Ces actions exposent en IPC ce qui existait déjà comme service interne
    # (MemberRoleService/RoleService/PermissionService), sans nouvelle
    # logique métier — seulement une nouvelle façade serveur-à-serveur.

    @action("xauth.roles.list")
    @schema(
        version="1.0",
        input={"tenant_id": (str, ...)},
        output={"roles": (list, [])},
        type_response="model", unset=False,
    )
    async def _ipc_roles_list(self, payload):
        from .services.rbac.roles import RoleService

        async with self._db.session() as sess:
            roles = await RoleService(sess, self._cache).list_tenant_roles(payload.tenant_id)
            return ok(roles=[
                {
                    "id": r.id,
                    "name": r.name,
                    "description": r.description,
                    "permissions": [p.name for p in r.permissions if p.active],
                }
                for r in roles
            ])

    @action("xauth.member.assign_role")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...), "user_id": (str, ...), "role_id": (str, ...),
            "granted_by": (Optional[str], None),
            "scope_type": (Optional[str], None), "scope_id": (Optional[str], None),
        },
        output={"assigned": (bool, False), "role_id": (str, None)},
        type_response="model", unset=False,
    )
    async def _ipc_member_assign_role(self, payload):
        from .services.rbac.members import MemberRoleService

        try:
            async with self._db.session() as sess:
                svc = MemberRoleService(sess, self._cache)
                await svc.add_role_to_member(
                    user_id=payload.user_id, tenant_id=payload.tenant_id, role_id=payload.role_id,
                    granted_by=getattr(payload, "granted_by", None),
                    scope_type=getattr(payload, "scope_type", None),
                    scope_id=getattr(payload, "scope_id", None),
                )
                await sess.commit()
            return ok(assigned=True, role_id=payload.role_id)
        except ValueError as exc:
            return error(str(exc), code="assign_role_failed")

    @action("xauth.member.unassign_role")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...), "user_id": (str, ...), "role_id": (str, ...),
            "scope_type": (Optional[str], None), "scope_id": (Optional[str], None),
        },
        output={"removed": (bool, False)},
        type_response="model", unset=False,
    )
    async def _ipc_member_unassign_role(self, payload):
        from .services.rbac.members import MemberRoleService

        async with self._db.session() as sess:
            svc = MemberRoleService(sess, self._cache)
            removed = await svc.remove_role_from_member(
                user_id=payload.user_id, tenant_id=payload.tenant_id, role_id=payload.role_id,
                scope_type=getattr(payload, "scope_type", None),
                scope_id=getattr(payload, "scope_id", None),
            )
            await sess.commit()
            return ok(removed=removed)

    @action("xauth.member.list_roles")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...), "user_id": (str, ...),
            # scope_type absent (par défaut) = tous scopes confondus (usage
            # UI/résumé) ; fourni = uniquement les rôles de CE scope précis
            # (ex. pour révoquer les rôles liés à une branche donnée sans
            # toucher aux rôles globaux ou scopés ailleurs).
            "scope_type": (Optional[str], None), "scope_id": (Optional[str], None),
        },
        output={"role_ids": (list, [])},
        type_response="model", unset=False,
    )
    async def _ipc_member_list_roles(self, payload):
        from .services.rbac.members import MemberRoleService

        async with self._db.session() as sess:
            svc = MemberRoleService(sess, self._cache)
            scope_type = getattr(payload, "scope_type", None)
            if scope_type:
                role_ids = await svc.list_roles_in_scope(
                    payload.user_id, payload.tenant_id,
                    scope_type=scope_type, scope_id=getattr(payload, "scope_id", None),
                )
            else:
                role_ids = await svc.list_member_roles(payload.user_id, payload.tenant_id)
            return ok(role_ids=role_ids)

    @action("xauth.member.list_permissions")
    @schema(
        version="1.0",
        input={
            "tenant_id": (str, ...), "user_id": (str, ...),
            "scope_type": (Optional[str], None), "scope_id": (Optional[str], None),
        },
        output={"permissions": (list, [])},
        type_response="model", unset=False,
    )
    async def _ipc_member_list_permissions(self, payload):
        from .services.rbac.permissions import PermissionService

        async with self._db.session() as sess:
            svc = PermissionService(sess, self._cache)
            perms = await svc.get_permissions_for_user(
                payload.user_id, payload.tenant_id,
                scope_type=getattr(payload, "scope_type", None),
                scope_id=getattr(payload, "scope_id", None),
            )
            return ok(permissions=perms)