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
from .token_crypto import OAuthTokenCipher
from ..utils.deeplink import is_allowed_redirect_target

# TTL du state CSRF en secondes
_STATE_TTL = 600
_STATE_KEY_PREFIX = "xauth:oauth:state:"
_DEFAULT_REDIRECT = "erp://oauth-callback"
_DEFAULT_LINK_REDIRECT = "erp://oauth-link"


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
        token_cipher: Optional[OAuthTokenCipher] = None,
        web_origins: frozenset[str] = frozenset(),
    ) -> None:
        self._session = session
        self._token = token_service
        self._cache = cache
        self._providers = providers
        # Optionnel : sans clé configurée (XAUTH_OAUTH_TOKEN_KEY), les
        # access/refresh tokens Google (Gmail/Calendar) ne sont simplement
        # jamais stockés — jamais de repli en clair.
        self._token_cipher = token_cipher
        # Origines https autorisées à recevoir la redirection finale du
        # callback OAuth (frontend web) — vide par défaut : seul le deep-link
        # desktop `erp://` fonctionne tant qu'aucune origine n'est déclarée
        # (voir OAUTH_WEB_REDIRECT_ORIGINS). Le système ne redirigeait
        # auparavant QUE vers `erp://`, sans aucun moyen pour un client web
        # de récupérer sa propre session — un access_token/refresh_token
        # fraîchement émis partait toujours vers un schéma que seule l'app
        # desktop sait intercepter.
        self._web_origins = web_origins

    # ── Providers registry ────────────────────────────────────────────────────

    def get_provider(self, name: str) -> OAuthProvider:
        provider = self._providers.get(name)
        if provider is None:
            available = ", ".join(self._providers.keys()) or "aucun"
            raise ValueError(f"Provider '{name}' inconnu. Disponibles : {available}")
        return provider

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    # ── Jetons d'accès API tierce (Gmail/Calendar, etc.) ─────────────────────

    def _apply_token_fields(self, account: OAuthAccount, token_data: dict[str, Any]) -> None:
        """Chiffre et attache access/refresh token + expiration + scopes
        accordés sur un `OAuthAccount`, à partir de la réponse brute du
        provider (`exchange_code`/`refresh_access_token`). No-op si aucune
        clé de chiffrement n'est configurée (`self._token_cipher` absent) —
        le login reste fonctionnel, seul l'accès Gmail/Calendar est indisponible.
        """
        if self._token_cipher is None or not self._token_cipher.available:
            return
        access_token = token_data.get("access_token")
        if access_token:
            account.access_token_encrypted = self._token_cipher.encrypt(access_token)
        refresh_token = token_data.get("refresh_token")
        if refresh_token:
            # Google ne renvoie un refresh_token qu'au tout premier
            # consentement (`access_type=offline`+`prompt=consent`) — ne
            # jamais écraser un refresh_token existant par une valeur absente
            # lors d'un re-login ultérieur.
            account.refresh_token_encrypted = self._token_cipher.encrypt(refresh_token)
        expires_in = token_data.get("expires_in")
        if expires_in is not None:
            account.token_expires_at = datetime.now(tz=timezone.utc) + timedelta(seconds=int(expires_in))
        scope = token_data.get("scope")
        if scope:
            account.granted_scopes = scope

    async def get_valid_access_token(self, user_id: str, provider_name: str) -> Optional[str]:
        """
        Retourne un access_token en clair, prêt à l'emploi immédiat, pour
        appeler l'API du provider au nom de cet utilisateur — rafraîchi au
        besoin via le refresh_token stocké. Ne persiste jamais le jeton en
        clair : déchiffré en mémoire pour la durée de cet appel seulement.
        Retourne None si aucun compte lié, aucune clé de chiffrement
        configurée, ou aucun refresh_token disponible pour rafraîchir un
        jeton expiré.
        """
        if self._token_cipher is None or not self._token_cipher.available:
            return None
        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_user_and_provider(user_id, provider_name)
        if account is None or not account.access_token_encrypted:
            return None

        expires_at = account.token_expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        still_valid = expires_at is None or expires_at > datetime.now(tz=timezone.utc) + timedelta(seconds=30)
        if still_valid:
            return self._token_cipher.decrypt(account.access_token_encrypted)

        refresh_token = self._token_cipher.decrypt(account.refresh_token_encrypted)
        if not refresh_token:
            return None
        provider = self.get_provider(provider_name)
        token_data = await provider.refresh_access_token(refresh_token)
        self._apply_token_fields(account, token_data)
        await self._session.flush()
        return token_data.get("access_token")

    # ── Step 1 : générer l'URL d'autorisation ────────────────────────────────

    async def get_auth_url(
        self,
        provider_name: str,
        tenant_id: Optional[str] = None,
        post_login_redirect: Optional[str] = None,
        link_user_id: Optional[str] = None,
        app_state: Optional[str] = None,
    ) -> str:
        provider = self.get_provider(provider_name)

        # `post_login_redirect` est fourni par le CLIENT (query param de
        # /authorize), contrairement aux deep-links construits côté serveur
        # pour les emails — sans validation, un lien forgé
        # `?redirect=https://evil.com` renverrait un access_token/
        # refresh_token fraîchement émis droit vers un site tiers dès que ce
        # champ serait effectivement utilisé par le callback (voir
        # handle_callback). Rejeté ici, à l'émission de l'URL d'autorisation,
        # plutôt que découvert silencieusement au retour du provider.
        if post_login_redirect and not is_allowed_redirect_target(
            post_login_redirect, self._web_origins
        ):
            raise ValueError(
                f"redirect non autorisé : {post_login_redirect!r} — "
                "seul erp:// ou une origine déclarée dans "
                "OAUTH_WEB_REDIRECT_ORIGINS est accepté."
            )

        state = secrets.token_urlsafe(32)
        state_data = {
            "provider": provider_name,
            "tenant_id": tenant_id,
            "redirect": post_login_redirect,
            "link_user_id": link_user_id,
            # Nonce généré par l'app cliente avant l'ouverture du navigateur,
            # échoué tel quel dans la redirection finale erp://oauth-callback
            # pour que le client puisse vérifier que ce retour correspond bien
            # à une tentative de connexion qu'il a lui-même initiée (défense
            # contre un deep-link erp:// forgé et invoqué directement par un
            # tiers, hors de tout flow OAuth réel).
            "app_state": app_state,
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
            if existing:
                # Reliaison : capture d'éventuels nouveaux jetons (scopes
                # étendus, refresh_token renouvelé) sur le compte existant.
                self._apply_token_fields(existing, token_data)
                await self._session.flush()
            else:
                account = OAuthAccount(
                    user_id=link_user_id,
                    provider=provider_name,
                    provider_user_id=user_info.provider_user_id,
                    provider_email=user_info.email,
                    provider_name=user_info.name,
                    provider_avatar=user_info.avatar_url,
                )
                self._apply_token_fields(account, token_data)
                await oauth_repo.save(account)
            return {
                "is_link": True,
                "provider": provider_name,
                "provider_email": user_info.email,
                "app_state": state_data.get("app_state"),
                "post_login_redirect": state_data.get("redirect"),
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
        user = await self._find_or_create_user(user_info, token_data)

        # `authentication.py::login()` refuse un compte désactivé avant
        # d'émettre le moindre token — ce chemin OAuth ne le faisait jamais,
        # permettant à un compte suspendu (admin, ou désactivation
        # automatique à expiration de contrat côté xemployee) de continuer à
        # se connecter tant qu'un provider externe restait lié.
        if not user.is_active:
            raise ValueError("Account is inactive")

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
                "app_state": state_data.get("app_state"),
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
                "app_state": state_data.get("app_state"),
            }

        # 1 tenant résolu — émettre l'access token, sauf compte MFA (voir
        # authentication.py::login()/select_tenant(), même garde) : ce
        # chemin OAuth n'appelait jamais select_tenant() et avait sa propre
        # émission de tokens dupliquée, sans jamais vérifier
        # `user.mfa_enabled` — un compte protégé par MFA en mot de passe
        # restait entièrement ouvert via OAuth.
        if user.mfa_enabled:
            mfa_token = self._token.create_mfa_challenge_token(
                user_id=user.id, tenant_id=tenant_id
            )
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
                "refresh_token": "",
                "mfa_token": mfa_token,
                "token_type": "bearer",
                "user_id": user.id,
                "tenant_id": tenant_id,
                "mfa_required": True,
                "provider": provider_name,
                "is_new_user": is_new,
                "post_login_redirect": state_data.get("redirect"),
                "app_state": state_data.get("app_state"),
            }

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
            "app_state": state_data.get("app_state"),
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
            self._apply_token_fields(existing, token_data)
            await self._session.flush()
            return existing

        account = OAuthAccount(
            user_id=user_id,
            provider=provider_name,
            provider_user_id=user_info.provider_user_id,
            provider_email=user_info.email,
            provider_name=user_info.name,
            provider_avatar=user_info.avatar_url,
        )
        self._apply_token_fields(account, token_data)
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

    async def _find_or_create_user(
        self, info: OAuthUserInfo, token_data: Optional[dict[str, Any]] = None
    ) -> User:
        oauth_repo = OAuthAccountRepository(self._session)
        user_repo = UserRepository(self._session)

        # 1. Chercher par (provider, provider_user_id)
        account = await oauth_repo.get_by_provider(info.provider, info.provider_user_id)
        if account:
            user = await user_repo.get(account.user_id)
            if user:
                if token_data:
                    self._apply_token_fields(account, token_data)
                    await self._session.flush()
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
            if token_data:
                self._apply_token_fields(new_account, token_data)
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
        if token_data:
            self._apply_token_fields(new_account, token_data)
        await oauth_repo.save(new_account)
        return user
