from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional



from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthAccount
from ..models.session import Session
from ..models.user import User
from ..providers.base import OAuthProvider, OAuthUserInfo
from ..repositories.oauth import OAuthAccountRepository
from ..repositories.session import SessionRepository
from ..repositories.user import UserRepository
from .token import TokenService

# TTL du state CSRF en secondes
_STATE_TTL = 600
_STATE_KEY_PREFIX = "xauth:oauth:state:"


class OAuthService:
    """
    Gère le flow OAuth2 complet : génération d'URL, callback, find-or-create user.
    Le state CSRF est stocké en cache Redis (TTL 10min).
    """

    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        cache: Any,
        providers: dict[str, OAuthProvider],
    ) -> None:
        self._session = session
        self._token = token_service
        self._cache = cache
        self._providers = providers

    # ── Providers registry ────────────────────────────────────────────────────

    def get_provider(self, name: str) -> OAuthProvider:
        provider = self._providers.get(name)
        if provider is None:
            available = ", ".join(self._providers.keys()) or "aucun"
            raise ValueError(f"Provider '{name}' inconnu. Disponibles : {available}")
        return provider

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    # ── Step 1 : générer l'URL d'autorisation ────────────────────────────────

    async def get_auth_url(
        self,
        provider_name: str,
        tenant_id: Optional[str] = None,
        post_login_redirect: Optional[str] = None,
        link_user_id: Optional[str] = None,
    ) -> str:
        provider = self.get_provider(provider_name)

        state = secrets.token_urlsafe(32)
        state_data = {
            "provider": provider_name,
            "tenant_id": tenant_id,
            "redirect": post_login_redirect,
            "link_user_id": link_user_id,
        }
        await self._cache.set(
            f"{_STATE_KEY_PREFIX}{state}",
            json.dumps(state_data),
            ttl=_STATE_TTL,
        )
        return provider.get_auth_url(state)

    # ── Step 2 : callback — échange le code, trouve ou crée le user ──────────

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        # Vérifier et consommer le state CSRF
        state_key = f"{_STATE_KEY_PREFIX}{state}"
        raw = await self._cache.get(state_key)
        if raw is None:
            raise ValueError("State OAuth invalide ou expiré.")
        await self._cache.delete(state_key)

        state_data = json.loads(raw)
        if state_data.get("provider") != provider_name:
            raise ValueError("State OAuth : provider mismatch.")

        # Mode liaison — compléter directement sans créer de session
        link_user_id = state_data.get("link_user_id")
        if link_user_id:
            provider = self.get_provider(provider_name)
            token_data = await provider.exchange_code(code)
            access_token_provider = token_data.get("access_token")
            if not access_token_provider:
                raise ValueError("Échange de code échoué.")
            user_info = await provider.get_user_info(access_token_provider)
            oauth_repo = OAuthAccountRepository(self._session)
            existing = await oauth_repo.get_by_provider(provider_name, user_info.provider_user_id)
            if existing and existing.user_id != link_user_id:
                raise ValueError(f"Ce compte {provider_name} est déjà lié à un autre utilisateur.")
            if not existing:
                account = OAuthAccount(
                    user_id=link_user_id,
                    provider=provider_name,
                    provider_user_id=user_info.provider_user_id,
                    provider_email=user_info.email,
                    provider_name=user_info.name,
                    provider_avatar=user_info.avatar_url,
                )
                await oauth_repo.save(account)
            return {
                "is_link": True,
                "provider": provider_name,
                "provider_email": user_info.email,
            }

        provider = self.get_provider(provider_name)

        # Échanger le code contre un access token
        token_data = await provider.exchange_code(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError(f"Le provider n'a pas retourné d'access_token : {token_data}")

        # Récupérer le profil utilisateur
        user_info = await provider.get_user_info(access_token)

        # Find-or-create
        user = await self._find_or_create_user(user_info)

        refresh_plain = self._token.create_refresh_token()
        refresh_hashed = self._token.hash_token(refresh_plain)
        session_repo = SessionRepository(self._session)

        # Vérifier les memberships — même logique que login()
        from ..repositories.user import TenantMemberRepository
        from ..repositories.tenant import TenantRepository

        member_repo = TenantMemberRepository(self._session)
        memberships = await member_repo.get_memberships_for_user(user.id)

        # tenant_id explicite fourni dans le state (ex: lien d'invite OAuth)
        forced_tenant_id: Optional[str] = state_data.get("tenant_id")
        is_new = getattr(user, "_is_new", False)

        if forced_tenant_id:
            tenant_id: Optional[str] = forced_tenant_id
        elif not memberships:
            # Aucun tenant — demander au client de créer ou rejoindre
            xauth_session = Session.build(
                user_id=user.id,
                refresh_token=refresh_hashed,
                ip_address=ip_address,
                expires_at=datetime.now(tz=timezone.utc)
                + timedelta(days=self._token.refresh_expire),
            )
            await session_repo.save(xauth_session)
            return {
                "access_token": "",
                "refresh_token": refresh_plain,
                "token_type": "bearer",
                "user_id": user.id,
                "tenant_id": None,
                "onboarding_required": True,
                "provider": provider_name,
                "is_new_user": is_new,
                "post_login_redirect": state_data.get("redirect"),
            }
        elif len(memberships) == 1:
            tenant_id = memberships[0].tenant_id
        else:
            # Plusieurs tenants — retourner la liste
            tenant_repo = TenantRepository(self._session)
            tenants = []
            for m in memberships:
                t = await tenant_repo.get(m.tenant_id)
                tenants.append({
                    "id": m.tenant_id,
                    "name": t.name if t else None,
                    "slug": t.slug if t else None,
                    "role_id": m.role_id,
                    "is_owner": m.is_owner,
                })
            xauth_session = Session.build(
                user_id=user.id,
                refresh_token=refresh_hashed,
                ip_address=ip_address,
                expires_at=datetime.now(tz=timezone.utc)
                + timedelta(days=self._token.refresh_expire),
            )
            await session_repo.save(xauth_session)
            return {
                "access_token": "",
                "refresh_token": refresh_plain,
                "token_type": "bearer",
                "user_id": user.id,
                "tenant_id": None,
                "tenants": tenants,
                "provider": provider_name,
                "is_new_user": is_new,
                "post_login_redirect": state_data.get("redirect"),
            }

        # 1 tenant résolu — émettre l'access token
        access_jwt, jti = self._token.create_access_token(
            user_id=user.id, tenant_id=tenant_id
        )
        xauth_session = Session.build(
            user_id=user.id,
            tenant_id=tenant_id,
            refresh_token=refresh_hashed,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token.refresh_expire),
            last_jti=jti,
        )
        await session_repo.save(xauth_session)

        return {
            "access_token": access_jwt,
            "refresh_token": refresh_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": tenant_id,
            "onboarding_required": False,
            "provider": provider_name,
            "is_new_user": is_new,
            "post_login_redirect": state_data.get("redirect"),
        }

    # ── Lier un provider à un user déjà authentifié ──────────────────────────

    async def link_provider(
        self,
        user_id: str,
        provider_name: str,
        code: str,
        state: str,
    ) -> OAuthAccount:
        # Vérifier le state
        state_key = f"{_STATE_KEY_PREFIX}{state}"
        raw = await self._cache.get(state_key)
        if raw is None:
            raise ValueError("State OAuth invalide ou expiré.")
        await self._cache.delete(state_key)

        provider = self.get_provider(provider_name)
        token_data = await provider.exchange_code(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Échange de code échoué.")

        user_info = await provider.get_user_info(access_token)

        oauth_repo = OAuthAccountRepository(self._session)

        # Vérifier que ce compte provider n'est pas déjà lié à un autre user
        existing = await oauth_repo.get_by_provider(provider_name, user_info.provider_user_id)
        if existing and existing.user_id != user_id:
            raise ValueError(
                f"Ce compte {provider_name} est déjà lié à un autre utilisateur."
            )

        if existing:
            return existing

        account = OAuthAccount(
            user_id=user_id,
            provider=provider_name,
            provider_user_id=user_info.provider_user_id,
            provider_email=user_info.email,
            provider_name=user_info.name,
            provider_avatar=user_info.avatar_url,
        )
        return await oauth_repo.save(account)

    # ── Délier un provider ────────────────────────────────────────────────────

    async def unlink_provider(self, user_id: str, provider_name: str) -> None:
        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_user_and_provider(user_id, provider_name)
        if account is None:
            raise ValueError(f"Aucun compte {provider_name} lié à cet utilisateur.")

        # Empêcher de délier si c'est le seul moyen de connexion (pas de password)
        user_repo = UserRepository(self._session)
        user = await user_repo.get(user_id)
        if user and not user.hashed_password:
            all_accounts = await oauth_repo.list_for_user(user_id)
            if len(all_accounts) <= 1:
                raise ValueError(
                    "Impossible de délier : ce compte n'a pas de mot de passe. "
                    "Définissez un mot de passe avant de délier ce provider."
                )

        await self._session.delete(account)
        await self._session.flush()

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _find_or_create_user(self, info: OAuthUserInfo) -> User:
        oauth_repo = OAuthAccountRepository(self._session)
        user_repo = UserRepository(self._session)

        # 1. Chercher par (provider, provider_user_id)
        account = await oauth_repo.get_by_provider(info.provider, info.provider_user_id)
        if account:
            user = await user_repo.get(account.user_id)
            if user:
                return user

        # 2. Chercher un user existant par email
        user = await user_repo.get_by_email(info.email)
        if user:
            # Lier ce provider au compte existant
            new_account = OAuthAccount(
                user_id=user.id,
                provider=info.provider,
                provider_user_id=info.provider_user_id,
                provider_email=info.email,
                provider_name=info.name,
                provider_avatar=info.avatar_url,
            )
            await oauth_repo.save(new_account)
            return user

        # 3. Créer un nouveau user
        user = User(email=info.email, hashed_password=None, is_active=True)
        user._is_new = True  # flag pour la réponse
        await user_repo.save(user)

        new_account = OAuthAccount(
            user_id=user.id,
            provider=info.provider,
            provider_user_id=info.provider_user_id,
            provider_email=info.email,
            provider_name=info.name,
            provider_avatar=info.avatar_url,
        )
        await oauth_repo.save(new_account)
        return user
