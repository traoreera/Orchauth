"""Actions IPC `xauth.iam.*` : la gestion des accès d'une organisation, appelée par le plugin `iam` (DocTypes Permission, Role, Member) POUR un utilisateur.

Chaque action reçoit `tenant_id` et `actor_id` (qui demande) EXPLICITEMENT : xauth juge (voir `services/iam.py`), jamais le plugin appelant. La réponse
est `{"status": "ok", …}` ou `{"status": "error", "code": …, "msg": …}` avec un code stable : `forbidden`, `not_found`, `invalid`, `error`. Un appelant doit
figurer dans `allowed_callers` du manifeste.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from xcore.sdk import action, error, get_logger, ok

from .services.iam import IamForbidden, IamInvalid, IamNotFound, IamService

logger = get_logger(__name__)

Op = Callable[[IamService, dict[str, Any]], Awaitable[dict[str, Any]]]


class IamCommands:
    """À mélanger au plugin (il fournit `self._db` et `self._cache`)."""

    async def _iam(self, payload: Any, op: Op, *, name: str) -> dict:
        data = payload if isinstance(payload, dict) else {}
        try:
            async with self._db.session() as session:  # type: ignore[attr-defined]
                result = await op(IamService(session, cache=self._cache), data)  # type: ignore[attr-defined]
                await session.commit()
            return ok(**result)
        except IamForbidden as e:
            return error(str(e), code="forbidden")
        except IamNotFound as e:
            return error(str(e), code="not_found")
        except (IamInvalid, ValueError) as e:  # les services rbac refusent par ValueError (« Rôle introuvable », « n'appartient pas à votre tenant »…)
            return error(str(e), code="invalid")
        except Exception:  # noqa: BLE001 - jamais le détail (SQL, chemins) vers un autre plugin
            logger.exception("xauth.iam action failed: %s", name)
            return error("Erreur interne d'xauth", code="error")

    @staticmethod
    def _who(p: dict[str, Any]) -> tuple[str, str]:
        return p.get("tenant_id"), p.get("actor_id")  # type: ignore[return-value]

    @action("xauth.iam.permissions")
    async def _iam_permissions(self, payload):
        return await self._iam(payload, lambda s, p: _wrap("items", s.permissions(*self._who(p))), name="permissions")

    @action("xauth.iam.roles")
    async def _iam_roles(self, payload):
        return await self._iam(payload, lambda s, p: _wrap("items", s.roles(*self._who(p))), name="roles")

    @action("xauth.iam.role.save")
    async def _iam_role_save(self, payload):
        return await self._iam(
            payload,
            lambda s, p: _wrap("role", s.role_save(*self._who(p), p.get("role_id"), p.get("name"), p.get("description"), p.get("permissions", []))),
            name="role.save",
        )

    @action("xauth.iam.role.delete")
    async def _iam_role_delete(self, payload):
        return await self._iam(payload, lambda s, p: _none(s.role_delete(*self._who(p), p.get("role_id"))), name="role.delete")

    @action("xauth.iam.members")
    async def _iam_members(self, payload):
        return await self._iam(payload, lambda s, p: _wrap("items", s.members(*self._who(p))), name="members")

    @action("xauth.iam.member")
    async def _iam_member(self, payload):
        return await self._iam(payload, lambda s, p: _wrap("member", s.member(*self._who(p), p.get("user_id"))), name="member")

    @action("xauth.iam.member.save")
    async def _iam_member_save(self, payload):
        return await self._iam(
            payload,
            lambda s, p: _wrap(
                "member",
                s.member_save(*self._who(p), p.get("user_id"), p.get("primary_role_id"), p.get("role_ids", []), p.get("permissions", []), p.get("is_active")),
            ),
            name="member.save",
        )

    @action("xauth.iam.member.remove")
    async def _iam_member_remove(self, payload):
        return await self._iam(payload, lambda s, p: _none(s.member_remove(*self._who(p), p.get("user_id"))), name="member.remove")

    @action("xauth.iam.user")
    async def _iam_user(self, payload):
        return await self._iam(payload, lambda s, p: _wrap("user", s.user_summary(*self._who(p), p.get("user_id"))), name="user")


async def _wrap(key: str, call: Awaitable[Any]) -> dict[str, Any]:
    return {key: await call}


async def _none(call: Awaitable[Any]) -> dict[str, Any]:
    await call
    return {}
