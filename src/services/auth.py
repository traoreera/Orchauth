from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_logger = logging.getLogger(__name__)

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.kernel.api import AuthBackend

from ..models.session import Session
from ..models.user import TenantMember, User
from ..repositories.session import SessionRepository
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository, UserRepository
from .audit import AuditService
from .events import XAuthEvents
from .token import TokenService

_JTI_BLACKLIST_PREFIX = "xauth:jti_bl:"


def _get_password_context():
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
    except ImportError:
        pass
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["bcrypt"], deprecated="auto")
    except ImportError:
        raise RuntimeError("passlib is required. Install with: uv add passlib[argon2]")


_pwd_context = None


def get_pwd_context():
    global _pwd_context
    if _pwd_context is None:
        _pwd_context = _get_password_context()
    return _pwd_context


def _check_password_policy(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_digit: bool = True,
) -> None:
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long")
    if require_uppercase and not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if require_digit and not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        events: XAuthEvents | None = None,
        cache: Any = None,
        user_role_name: str = "user",
        admin_role_name: str = "admin",
    ) -> None:
        self._session = session
        self._token = token_service
        self._events = events
        self._cache = cache
        self._user_role_name = user_role_name
        self._admin_role_name = admin_role_name

    async def register(
        self,
        email: str,
        password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> User:
        _check_password_policy(
            password,
            min_length=min_length,
            require_uppercase=require_uppercase,
            require_digit=require_digit,
        )

        user_repo = UserRepository(self._session)
        existing = await user_repo.get_by_email(email)
        if existing is not None:
            raise ValueError("Email already registered")

        hashed = get_pwd_context().hash(password)
        user = User(email=email, hashed_password=hashed)
        await user_repo.save(user)

        audit = AuditService(self._session)
        await audit.log_event(
            action="user.registered",
            user_id=user.id,
            resource="user",
            resource_id=user.id,
        )

        if self._events:
            await self._events.user_registered(
                user_id=user.id,
                email=user.email,
                tenant_id=None,
            )

        return user

    async def refresh(
        self, refresh_token: str, ip_address: Optional[str] = None
    ) -> dict[str, Any]:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)

        if session is None:
            raise ValueError("Invalid or expired refresh token")

        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")

        # Rotate: revoke old, create new
        session.is_revoked = True
        await self._session.flush()

        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)

        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=session.tenant_id
        )

        new_session = Session(
            user_id=session.user_id,
            tenant_id=session.tenant_id,
            refresh_token=new_refresh_hashed,
            device_fingerprint=session.device_fingerprint,
            ip_address=ip_address or session.ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(new_session)

        if self._events:
            await self._events.session_refreshed(
                user_id=session.user_id, tenant_id=session.tenant_id
            )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
        }

    async def logout(self, refresh_token: str) -> None:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)
        if session:
            audit = AuditService(self._session)
            await audit.log_event(
                action="logout",
                user_id=session.user_id,
                tenant_id=session.tenant_id,
                resource="session",
                resource_id=session.id,
            )
            # Blacklister le dernier JTI émis pour invalider l'access token immédiatement
            if self._cache and session.last_jti:
                ttl = self._token._access_expire * 60 + 30
                await self._cache.set(
                    f"{_JTI_BLACKLIST_PREFIX}{session.last_jti}", "1", ttl=ttl
                )
            session.is_revoked = True
            await self._session.flush()
            if self._events:
                await self._events.user_logout(user_id=session.user_id)

    async def verify_token(self, token: str) -> dict[str, Any]:
        """Verify an access token and return its claims."""
        return self._token.verify_access_token(token)

    async def login(
        self,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> dict[str, Any]:
        """login method"""
        audit = AuditService(self._session)
        user_repo = UserRepository(self._session)
        user = await user_repo.get_by_email(email)
        if user is None or not get_pwd_context().verify(password, user.hashed_password):
            await audit.log_event(
                action="login.failed",
                ip_address=ip_address,
                metadata={"email": email, "reason": "invalid_credentials"},
            )
            if self._events:
                await self._events.user_login_failed(
                    email=email, ip=ip_address, reason="invalid_credentials"
                )
            raise ValueError("Invalid credentials")
        if not user.is_active:
            await audit.log_event(
                action="login.failed",
                user_id=user.id,
                ip_address=ip_address,
                metadata={"reason": "account_inactive"},
            )
            if self._events:
                await self._events.user_login_failed(
                    email=email, ip=ip_address, reason="account_inactive"
                )
            raise ValueError("Account is inactive")

        # ── Résolution du tenant ──────────────────────────────────────────────────
        member_repo = TenantMemberRepository(self._session)

        if not tenant_id:
            memberships = await member_repo.get_memberships_for_user(user.id)

            if not memberships:
                # Aucun tenant : créer une session sans tenant et demander au client
                # de créer ou rejoindre un tenant via /auth/setup/*
                access_token, jti = self._token.create_access_token(
                    user_id=user.id, tenant_id=None
                )
                refresh_token_plain = self._token.create_refresh_token()
                refresh_token_hashed = self._token.hash_token(refresh_token_plain)
                session_repo = SessionRepository(self._session)
                pending_session = Session(
                    user_id=user.id,
                    tenant_id=None,
                    refresh_token=refresh_token_hashed,
                    device_fingerprint=device_fingerprint,
                    ip_address=ip_address,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(days=self._token._refresh_expire),
                    last_jti=jti,
                )
                await session_repo.save(pending_session)
                await audit.log_event(
                    action="login.onboarding_required",
                    user_id=user.id,
                    ip_address=ip_address,
                    metadata={"reason": "no_membership"},
                )
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token_plain,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": None,
                    "mfa_required": False,
                    "onboarding_required": True,
                    "tenants": [],
                }

            if len(memberships) == 1:
                # Un seul tenant → on scope directement, flow normal
                tenant_id = memberships[0].tenant_id
            else:
                # Plusieurs tenants → on retourne la liste sans émettre d'access token
                # On crée quand même la session pour le refresh token
                refresh_token_plain = self._token.create_refresh_token()
                refresh_token_hashed = self._token.hash_token(refresh_token_plain)
                session_repo = SessionRepository(self._session)
                session = Session(
                    user_id=user.id,
                    tenant_id=None,
                    refresh_token=refresh_token_hashed,
                    device_fingerprint=device_fingerprint,
                    ip_address=ip_address,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(days=self._token._refresh_expire),
                )
                await session_repo.save(session)

                # Charger les infos tenant pour l'affichage
                from ..repositories.tenant import TenantRepository

                tenant_repo = TenantRepository(self._session)
                tenants = []
                for m in memberships:
                    t = await tenant_repo.get(m.tenant_id)
                    tenants.append(
                        {
                            "id": m.tenant_id,
                            "name": t.name if t else None,
                            "slug": t.slug if t else None,
                            "role_id": m.role_id,
                            "is_owner": m.is_owner,
                        }
                    )

                return {
                    "access_token": "",
                    "refresh_token": refresh_token_plain,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": None,
                    "mfa_required": user.mfa_enabled,
                    "tenants": tenants,
                }
        else:
            # tenant_id fourni → vérifier que le user en est bien membre
            membership = await member_repo.get_membership(user.id, tenant_id)
            if membership is None:
                raise ValueError("User is not a member of this tenant")

        # ── Flow normal : émission des tokens ─────────────────────────────────────
        refresh_token_plain = self._token.create_refresh_token()
        refresh_token_hashed = self._token.hash_token(refresh_token_plain)
        session_repo = SessionRepository(self._session)

        # Si MFA activé → émettre un challenge token court (5 min), pas de session réelle
        if user.mfa_enabled:
            mfa_token = self._token.create_mfa_challenge_token(
                user_id=user.id, tenant_id=tenant_id
            )
            return {
                "access_token": "",
                "refresh_token": "",
                "mfa_token": mfa_token,
                "token_type": "bearer",
                "user_id": user.id,
                "tenant_id": tenant_id,
                "mfa_required": True,
                "tenants": None,
            }

        access_token, jti = self._token.create_access_token(
            user_id=user.id, tenant_id=tenant_id, email=user.email
        )

        session = Session(
            user_id=user.id,
            tenant_id=tenant_id,
            refresh_token=refresh_token_hashed,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(session)

        await audit.log_event(
            action="login.success",
            user_id=user.id,
            tenant_id=tenant_id,
            ip_address=ip_address,
            resource="session",
            resource_id=session.id,
        )
        if self._events:
            await self._events.user_login(
                user_id=user.id, email=user.email, ip=ip_address, tenant_id=tenant_id
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    async def select_tenant(
        self,
        refresh_token: str,
        tenant_id: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Émet un access token scopé après sélection du tenant par l'utilisateur.
        Le refresh token doit être valide et non encore scopé (tenant_id = None).
        """
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)

        if session is None:
            raise ValueError("Invalid or expired refresh token")

        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")

        # Vérifier que le user appartient bien au tenant demandé
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(session.user_id, tenant_id)
        if membership is None:
            raise ValueError("User is not a member of this tenant")

        # Rotation du refresh token + access token scopé au tenant
        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=tenant_id
        )

        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)

        session.is_revoked = True
        await self._session.flush()

        new_session = Session(
            user_id=session.user_id,
            tenant_id=tenant_id,
            refresh_token=new_refresh_hashed,
            device_fingerprint=session.device_fingerprint,
            ip_address=ip_address or session.ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
            last_jti=jti,
        )
        session_repo = SessionRepository(self._session)
        await session_repo.save(new_session)

        if self._events:
            await self._events.user_login(
                user_id=session.user_id,
                email="",
                ip=ip_address,
                tenant_id=tenant_id,
            )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
            "user_id": session.user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    async def verify_mfa_and_issue_token(
        self,
        mfa_token: str,
        totp_code: str,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Deuxième étape du login MFA.
        Vérifie le challenge JWT (5 min) + code TOTP, puis crée la session réelle.
        """
        try:
            claims = self._token.verify_mfa_challenge_token(mfa_token)
        except ValueError as exc:
            raise ValueError(f"Challenge MFA invalide : {exc}") from exc

        user_id = claims["sub"]
        tenant_id = claims.get("tenant_id")

        from .mfa import MFAService

        mfa_svc = MFAService(self._session)
        valid = await mfa_svc.verify_totp(user_id, totp_code)
        if not valid:
            raise ValueError("Code MFA invalide ou expiré")

        refresh_plain = self._token.create_refresh_token()
        refresh_hashed = self._token.hash_token(refresh_plain)
        access_token, jti = self._token.create_access_token(
            user_id=user_id, tenant_id=tenant_id
        )

        session = Session(
            user_id=user_id,
            tenant_id=tenant_id,
            refresh_token=refresh_hashed,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
            last_jti=jti,
        )
        session_repo = SessionRepository(self._session)
        await session_repo.save(session)

        return {
            "access_token": access_token,
            "refresh_token": refresh_plain,
            "token_type": "bearer",
            "user_id": user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    # ── Tenant setup (après login sans membership) ────────────────────────────

    async def _resolve_pending_session(self, refresh_token: str):
        """Valide un refresh token et retourne la Session. Lève ValueError si invalide."""
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)
        if session is None or session.is_revoked:
            raise ValueError("Invalid or expired refresh token")
        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")
        return session

    async def setup_create_tenant(
        self,
        refresh_token: str,
        name: str,
        slug: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Crée un nouveau tenant et y rattache l'utilisateur comme owner (rôle admin).
        Réservé aux sessions en attente de setup (tenant_id = None, onboarding_required).
        """
        from ..models.tenant import Tenant
        from ..repositories.rbac import RoleRepository
        from ..repositories.tenant import TenantRepository

        session = await self._resolve_pending_session(refresh_token)

        tenant_repo = TenantRepository(self._session)
        if await tenant_repo.get_by_slug(slug) is not None:
            raise ValueError(f"Le slug '{slug}' est déjà utilisé")

        tenant = Tenant(name=name, slug=slug)
        await tenant_repo.save(tenant)

        role_repo = RoleRepository(self._session)
        global_roles = await role_repo.list_for_tenant(None)
        admin_role = next(
            (r for r in global_roles if r.name == self._admin_role_name), None
        )
        if admin_role is None:
            _logger.warning(
                "[xauth] Rôle admin '%s' introuvable — owner créé sans rôle pour le tenant %s",
                self._admin_role_name,
                slug,
            )

        member_repo = TenantMemberRepository(self._session)
        membership = TenantMember(
            user_id=session.user_id,
            tenant_id=tenant.id,
            role_id=admin_role.id if admin_role else None,
            is_owner=True,
        )
        await member_repo.save(membership)

        access_token, jti = self._token.create_access_token(
            user_id=session.user_id, tenant_id=tenant.id
        )
        session.tenant_id = tenant.id
        session.last_jti = jti
        await self._session.flush()

        audit = AuditService(self._session)
        await audit.log_event(
            action="tenant.created",
            user_id=session.user_id,
            tenant_id=tenant.id,
            resource="tenant",
            resource_id=tenant.id,
            ip_address=ip_address,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": session.user_id,
            "tenant_id": tenant.id,
            "mfa_required": False,
            "onboarding_required": False,
            "tenants": None,
        }

    async def setup_join_tenant(
        self,
        refresh_token: str,
        invite_token: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Rejoint un tenant existant via un token d'invitation.
        L'email de l'invitation doit correspondre à celui de l'utilisateur.
        """
        from ..repositories.invite import InviteRepository
        from ..repositories.user import UserRepository

        session = await self._resolve_pending_session(refresh_token)
        now = datetime.now(tz=timezone.utc)

        user_repo = UserRepository(self._session)
        user = await user_repo.get(session.user_id)
        if user is None:
            raise ValueError("Utilisateur introuvable")

        invite_repo = InviteRepository(self._session)
        invite = await invite_repo.get_by_token(invite_token)

        if invite is None or not invite.is_active or invite.used_at is not None:
            raise ValueError("Code d'invitation invalide ou déjà utilisé")

        invite_expires = invite.expires_at
        if invite_expires.tzinfo is None:
            invite_expires = invite_expires.replace(tzinfo=timezone.utc)
        if invite_expires < now:
            raise ValueError("Le code d'invitation a expiré")

        if invite.email.lower() != user.email.lower():
            raise ValueError(
                "Cette invitation n'est pas destinée à votre adresse email"
            )

        member_repo = TenantMemberRepository(self._session)
        if await member_repo.get_membership(user.id, invite.tenant_id) is not None:
            raise ValueError("Vous êtes déjà membre de ce tenant")

        membership = TenantMember(
            user_id=user.id,
            tenant_id=invite.tenant_id,
            role_id=invite.role_id,
        )
        await member_repo.save(membership)

        invite.used_at = now
        invite.is_active = False
        await self._session.flush()

        access_token, jti = self._token.create_access_token(
            user_id=user.id, tenant_id=invite.tenant_id
        )
        session.tenant_id = invite.tenant_id
        session.last_jti = jti
        await self._session.flush()

        audit = AuditService(self._session)
        await audit.log_event(
            action="tenant.joined",
            user_id=user.id,
            tenant_id=invite.tenant_id,
            resource="tenant",
            resource_id=invite.tenant_id,
            ip_address=ip_address,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": invite.tenant_id,
            "mfa_required": False,
            "onboarding_required": False,
            "tenants": None,
        }
