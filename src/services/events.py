from __future__ import annotations

from typing import Any

# ── Noms d'événements ─────────────────────────────────────────────────────────
# Convention : xauth.<domaine>.<action>
# Tous les autres plugins peuvent s'abonner via self.ctx.events.on("xauth.*")

# Auth
USER_REGISTERED = "xauth.auth.registered"
USER_LOGIN = "xauth.auth.login"
USER_LOGIN_FAILED = "xauth.auth.login_failed"
USER_LOGOUT = "xauth.auth.logout"
SESSION_REFRESHED = "xauth.auth.session_refreshed"

# Password
PASSWORD_RESET_REQUESTED = "xauth.password.reset_requested"
PASSWORD_RESET_COMPLETED = "xauth.password.reset_completed"
PASSWORD_CHANGED = "xauth.password.changed"
PASSWORD_SET = "xauth.password.set"

# OAuth
OAUTH_LOGIN = "xauth.oauth.login"
OAUTH_LINKED = "xauth.oauth.linked"
OAUTH_UNLINKED = "xauth.oauth.unlinked"

# Invitations
INVITE_CREATED = "xauth.invite.created"
INVITE_ACCEPTED = "xauth.invite.accepted"

# Tenants
TENANT_CREATED = "xauth.tenant.created"

# MFA
MFA_ENABLED = "xauth.mfa.enabled"
MFA_DISABLED = "xauth.mfa.disabled"


class XAuthEvents:
    """
    Émetteur d'événements xauth.

    Wraps l'EventBus Xcore avec des méthodes typées par domaine.
    Injecté dans les services via le constructeur.

    Depuis un autre plugin :
        @self.ctx.events.on("xauth.auth.login")
        async def on_login(event):
            user_id = event.data["user_id"]
    """

    def __init__(self, bus: Any) -> None:
        self._bus = bus

    async def emit(self, name: str, data: dict[str, Any]) -> None:
        if self._bus is None:
            return
        await self._bus.emit(name, data, source="xauth")

    def emit_sync(self, name: str, data: dict[str, Any]) -> None:
        if self._bus is None:
            return
        self._bus.emit_sync(name, data)

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def user_registered(
        self, user_id: str, email: str, tenant_id: str | None = None
    ) -> None:
        await self.emit(
            USER_REGISTERED,
            {"user_id": user_id, "email": email, "tenant_id": tenant_id},
        )

    async def user_login(
        self, user_id: str, email: str, ip: str | None, tenant_id: str | None = None
    ) -> None:
        await self.emit(
            USER_LOGIN,
            {"user_id": user_id, "email": email, "ip": ip, "tenant_id": tenant_id},
        )

    async def user_login_failed(self, email: str, ip: str | None, reason: str) -> None:
        await self.emit(USER_LOGIN_FAILED, {"email": email, "ip": ip, "reason": reason})

    async def user_logout(self, user_id: str) -> None:
        await self.emit(USER_LOGOUT, {"user_id": user_id})

    async def session_refreshed(
        self, user_id: str, tenant_id: str | None = None
    ) -> None:
        await self.emit(SESSION_REFRESHED, {"user_id": user_id, "tenant_id": tenant_id})

    # ── Password ──────────────────────────────────────────────────────────────

    async def password_reset_requested(self, email: str) -> None:
        await self.emit(PASSWORD_RESET_REQUESTED, {"email": email})

    async def password_reset_completed(self, email: str) -> None:
        await self.emit(PASSWORD_RESET_COMPLETED, {"email": email})

    async def password_changed(self, user_id: str) -> None:
        await self.emit(PASSWORD_CHANGED, {"user_id": user_id})

    async def password_set(self, user_id: str) -> None:
        await self.emit(PASSWORD_SET, {"user_id": user_id})

    # ── OAuth ─────────────────────────────────────────────────────────────────

    async def oauth_login(self, user_id: str, provider: str, is_new: bool) -> None:
        await self.emit(
            OAUTH_LOGIN,
            {"user_id": user_id, "provider": provider, "is_new_user": is_new},
        )

    async def oauth_linked(self, user_id: str, provider: str) -> None:
        await self.emit(OAUTH_LINKED, {"user_id": user_id, "provider": provider})

    async def oauth_unlinked(self, user_id: str, provider: str) -> None:
        await self.emit(OAUTH_UNLINKED, {"user_id": user_id, "provider": provider})

    # ── Invitations ───────────────────────────────────────────────────────────

    async def invite_created(
        self, invite_id: str, email: str, tenant_id: str, invited_by: str
    ) -> None:
        await self.emit(
            INVITE_CREATED,
            {
                "invite_id": invite_id,
                "email": email,
                "tenant_id": tenant_id,
                "invited_by": invited_by,
            },
        )

    async def invite_accepted(
        self, invite_id: str, user_id: str, tenant_id: str
    ) -> None:
        await self.emit(
            INVITE_ACCEPTED,
            {"invite_id": invite_id, "user_id": user_id, "tenant_id": tenant_id},
        )

    # ── Tenants ───────────────────────────────────────────────────────────────

    async def tenant_created(self, tenant_id: str, owner_id: str, slug: str) -> None:
        await self.emit(
            TENANT_CREATED, {"tenant_id": tenant_id, "owner_id": owner_id, "slug": slug}
        )

    # ── MFA ───────────────────────────────────────────────────────────────────

    async def mfa_enabled(self, user_id: str) -> None:
        await self.emit(MFA_ENABLED, {"user_id": user_id})

    async def mfa_disabled(self, user_id: str) -> None:
        await self.emit(MFA_DISABLED, {"user_id": user_id})
