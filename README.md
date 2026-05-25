# XAuth

Plugin d'authentification enterprise pour l'écosystème **xcore**. Multi-tenant, RBAC, MFA TOTP, OAuth 2.0, audit log, gestion de sessions, invitations par lien.

---

## Fonctionnalités

| Domaine | Fonctionnalités |
|---|---|
| Authentification | Inscription, connexion, refresh, logout, `/me` |
| Tokens | JWT RS256 — access token (15 min) + refresh token (7 jours), blacklist JTI |
| Sessions | Liste, révocation unitaire, révocation globale |
| MFA | TOTP (Google Authenticator / Authy), 8 codes de secours à usage unique |
| OAuth 2.0 | Google, GitHub, Discord, Microsoft — link/unlink |
| Multi-tenancy | Utilisateurs membres de plusieurs tenants, rôle différent par tenant |
| RBAC | Permissions granulaires (strings), rôles globaux et scoped par tenant |
| Invitations | Lien signé avec expiration, email HTML via Jinja2 |
| Audit log | Chaque action sensible horodatée (IP, user agent, metadata JSON) |
| Administration | Routes admin protégées — list/read/update/delete utilisateurs |
| Rate limiting | Middleware Redis sliding-window, configurable par route dans `plugin.yaml` |
| Seed au démarrage | Tenant par défaut, rôles admin/user, permissions — tout configuré dans `plugin.yaml` |

---

## Architecture

```
plugin.yaml              ← source de config (seed, jwt, app, rate_limit)
src/
  main.py                ← lifecycle : on_load, on_unload, get_router, get_middlewares
  backend.py             ← XAuthBackend — decode_token, vérification JTI blacklist
  ipc.py                 ← commandes IPC inter-plugins
  middleware/
    rate_limit.py        ← RateLimitMiddleware (Redis sliding-window)
  routes/
    auth.py              ← register, login, refresh, logout, me (inline dans main.py)
    sessions.py          ← verify-mfa, sessions list/revoke
    mfa.py               ← setup, enable, verify, disable, backup-codes
    oauth.py             ← authorize, callback, link, unlink, me/accounts
    password.py          ← forgot, reset, change, set
    tenants.py           ← CRUD tenants + membres
    rbac.py              ← rôles, permissions, assignments
    invites.py           ← create, list, accept
    audit.py             ← lecture logs
    admin.py             ← admin users (list, read, patch, delete)
  services/
    auth.py              ← AuthService — login, register, logout, refresh, verify_mfa
    token.py             ← TokenService — create_access_token, create_refresh_token
    mfa.py               ← MFAService — setup TOTP, verify, backup codes
    email/               ← EmailTransport + Jinja2 (data/templates/)
    seed.py              ← seed au démarrage (permissions, rôles, tenant, admin)
    audit.py             ← AuditService — log_event
    events.py            ← XAuthEvents — EventBus typé
  repositories/          ← couche d'accès aux données (SQLAlchemy async)
  models/                ← User, Session, Tenant, Role, Permission, Invite, AuditLog
  providers/             ← GoogleProvider, GitHubProvider, DiscordProvider, MicrosoftProvider
data/
  templates/             ← templates email HTML (Jinja2)
    welcome.html
    oauth_linked.html
    invitation.html
    password_reset.html
    password_changed.html
migrations/              ← fichiers Alembic
```

---

## Installation

### 1. Clés RS256

```bash
mkdir -p conf
openssl genrsa -out conf/private.pem 2048
openssl rsa -in conf/private.pem -pubout -out conf/public.pem
```

### 2. Dépendances

```bash
uv add jinja2 python-jose pyotp passlib
```

### 3. Configuration — `plugin.yaml`

Toute la configuration se fait dans `plugin.yaml`. Les sections `app`, `seed`, `jwt`, `rate_limit` sont lues via `self.ctx.config`. La section `env` est réservée aux secrets (OAuth, SMTP) qui ne doivent pas apparaître en clair.

```yaml
app:
  name: "MonApp"
  base_url: "https://api.monapp.com"

seed:
  admin_email: "admin@monapp.com"
  admin_password: "ChangeMeNow!"
  admin_tenant_slug: "default"
  admin_tenant_name: "Default"
  admin_role_name: "admin"
  user_role_name: "user"

jwt:
  private_key_path: "conf/private.pem"
  public_key_path: "conf/public.pem"
  access_expire_minutes: 15
  refresh_expire_days: 7

rate_limit:
  enabled: true
  routes: {}        # optionnel — override des limites par défaut

env:
  OAUTH_GOOGLE_CLIENT_ID: "${XAUTH_OAUTH_GOOGLE_CLIENT_ID}"
  OAUTH_GOOGLE_CLIENT_SECRET: "${XAUTH_OAUTH_GOOGLE_CLIENT_SECRET}"
  # ... autres secrets OAuth / SMTP
```

Les valeurs de `seed` et `jwt` peuvent être surchargées par variable d'environnement (`ADMIN_EMAIL`, `ADMIN_PASSWORD`, `JWT_PRIVATE_KEY_PATH`, etc.) sans modifier le fichier YAML.

### 4. Variables d'environnement (`.env`)

Seuls les secrets nécessitent un `.env`. Copier `example.env` :

```bash
cp example.env .env
# Remplir uniquement les secrets OAuth et SMTP
```

---

## Endpoints

Tous les endpoints sont préfixés `/xauth` par xcore.

### Authentification — `/xauth/auth`

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/register` | — | Créer un compte |
| POST | `/login` | — | Connexion — retourne access + refresh tokens |
| POST | `/verify-mfa` | — | Étape 2 MFA — échange code TOTP contre access token |
| POST | `/refresh` | — | Rotation des tokens via refresh token |
| POST | `/logout` | — | Révoque la session + blackliste le JTI |
| GET | `/me` | Bearer | Profil de l'utilisateur courant |
| GET | `/sessions` | Bearer | Liste les sessions actives |
| DELETE | `/sessions/{id}` | Bearer | Révoque une session |
| DELETE | `/sessions` | Bearer | Révoque toutes les sessions |

### MFA — `/xauth/mfa`

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/setup` | Bearer | Génère secret TOTP + QR code URI + 8 codes de secours |
| POST | `/enable` | Bearer | Active le MFA après vérification du premier code |
| POST | `/verify` | Bearer | Vérifie un code TOTP (hors login) |
| DELETE | `/` | Bearer | Désactive le MFA |
| POST | `/backup-codes/regenerate` | Bearer | Régénère les codes de secours |

### OAuth — `/xauth/oauth`

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/providers` | — | Liste les providers activés |
| GET | `/{provider}/authorize` | — | Redirige vers le provider |
| GET | `/{provider}/callback` | — | Callback OAuth — retourne les tokens |
| POST | `/{provider}/link` | Bearer | Lie un compte OAuth au compte existant |
| DELETE | `/{provider}/unlink` | Bearer | Délier un compte OAuth |
| GET | `/me/accounts` | Bearer | Liste les comptes OAuth liés |

### Mot de passe — `/xauth/password`

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/forgot` | — | Envoie un email de réinitialisation |
| POST | `/reset` | — | Réinitialise le mot de passe via token |
| POST | `/change` | Bearer | Change le mot de passe (ancien requis) |
| POST | `/set` | Bearer | Définit un mot de passe (compte OAuth sans mdp) |

### Tenants — `/xauth/tenants`

| Méthode | Endpoint | Permission | Description |
|---|---|---|---|
| POST | `/` | `tenants:write` | Créer un tenant |
| GET | `/` | `tenants:read` | Lister tous les tenants |
| GET | `/{id}` | `tenants:read` | Détail d'un tenant |
| PATCH | `/{id}` | `tenants:write` | Modifier un tenant |
| DELETE | `/{id}` | `tenants:delete` | Supprimer un tenant |
| GET | `/{id}/members` | `tenants:read` | Membres d'un tenant |

### RBAC — `/xauth/rbac`

| Méthode | Endpoint | Permission | Description |
|---|---|---|---|
| POST | `/roles` | `rbac:write` | Créer un rôle |
| GET | `/roles` | `rbac:read` | Lister les rôles |
| GET | `/roles/{id}` | `rbac:read` | Détail d'un rôle |
| POST | `/roles/{id}/permissions` | `rbac:write` | Assigner une permission à un rôle |
| DELETE | `/roles/{id}/permissions/{perm_id}` | `rbac:write` | Retirer une permission |
| POST | `/tenants/{tid}/members/{uid}/role` | `rbac:write` | Assigner un rôle à un membre |
| GET | `/permissions` | `rbac:read` | Lister toutes les permissions |

### Invitations — `/xauth/invites`

| Méthode | Endpoint | Permission | Description |
|---|---|---|---|
| POST | `/` | `invite:create` | Créer une invitation |
| GET | `/{tenant_id}` | `tenants:read` | Lister les invitations d'un tenant |
| GET | `/token/{token}` | — | Détail d'une invitation (public) |
| POST | `/accept` | — | Accepter une invitation |

### Audit — `/xauth/audit`

| Méthode | Endpoint | Permission | Description |
|---|---|---|---|
| GET | `/tenants/{id}` | `audit:read` | Logs d'un tenant |
| GET | `/users/{id}` | `audit:read` | Logs d'un utilisateur |

### Administration — `/xauth/admin`

| Méthode | Endpoint | Permission | Description |
|---|---|---|---|
| GET | `/users` | `user:list` | Liste paginée des utilisateurs |
| GET | `/users/{id}` | `user:read` | Détail d'un utilisateur |
| PATCH | `/users/{id}` | `user:update` | Activer / désactiver un compte |
| DELETE | `/users/{id}` | `user:delete` | Supprimer définitivement un utilisateur |

---

## Flux de connexion

Les flux complets (séquences, états des tokens, OAuth, réinitialisation de mot de passe) sont documentés dans [docs/flows.md](docs/flows.md).

---

## Flow MFA

Quand `mfa_enabled = true` sur l'utilisateur, le login se fait en deux étapes :

```
# Étape 1
POST /xauth/auth/login
{ "email": "...", "password": "..." }
→ { "access_token": "", "refresh_token": "abc...", "mfa_required": true }

# Étape 2
POST /xauth/auth/verify-mfa
{ "refresh_token": "abc...", "code": "123456" }
→ { "access_token": "eyJ...", "refresh_token": "xyz...", "mfa_required": false }
```

Le code peut être un code TOTP à 6 chiffres ou un code de secours (10 caractères hex, usage unique).

---

## IPC — Intégration inter-plugins

Les autres plugins xcore peuvent appeler XAuth sans dépendance directe :

```python
# Vérifier un token
result = await ctx.caller("xauth", "verify_token", {"token": access_token})
# → {"valid": true, "user_id": "...", "tenant_id": "...", "permissions": [...]}

# Vérifier une permission
result = await ctx.caller("xauth", "has_permission", {
    "user_id": "...", "tenant_id": "...", "permission": "plugin:publish"
})
# → {"has_permission": true}

# Récupérer un utilisateur
result = await ctx.caller("xauth", "get_user", {"user_id": "..."})
# → {"id": "...", "email": "...", "is_active": true, ...}

# Créer une invitation
result = await ctx.caller("xauth", "create_invite", {
    "tenant_id": "...", "email": "...", "invited_by": "...", "expires_hours": 48
})
# → {"token": "...", "accept_url": "https://..."}

# Écrire dans l'audit log
await ctx.caller("xauth", "log_event", {
    "tenant_id": "...", "user_id": "...", "action": "plugin.published",
    "resource": "plugin", "resource_id": "...", "ip_address": "..."
})
```

---

## Utiliser XAuth dans un plugin xcore

```python
from xcore.kernel.api import get_current_user, require_permission
from fastapi import Depends

# Route authentifiée
@router.get("/data")
async def get_data(user = Depends(get_current_user)):
    return {"user_id": user["sub"]}

# Route avec permission
@router.post("/publish")
async def publish(_ = Depends(require_permission("plugin:create"))):
    return {"status": "published"}
```

---

## Rate Limiting

Limites par défaut (par IP) :

| Route | Requêtes max | Fenêtre |
|---|---|---|
| `/xauth/auth/login` | 10 | 60 s |
| `/xauth/auth/register` | 5 | 60 s |
| `/xauth/auth/verify-mfa` | 5 | 60 s |
| `/xauth/password/forgot` | 3 | 5 min |
| `/xauth/password/reset` | 5 | 5 min |
| `/xauth/oauth/*` | 30 | 60 s |
| Toutes autres routes `/xauth/*` | 300 | 60 s |

Pour surcharger dans `plugin.yaml` :

```yaml
rate_limit:
  enabled: true
  routes:
    "/xauth/auth/login": [5, 60]
    "/xauth/auth/register": [3, 60]
```

Pour désactiver en développement :

```yaml
rate_limit:
  enabled: false
```

---

## Schéma de base de données

```
User
  id, email, hashed_password, is_active
  mfa_enabled, mfa_secret, mfa_backup_codes (JSON hashes)
  created_at

TenantMember          (User ↔ Tenant)
  user_id, tenant_id, role_id, is_owner, joined_at

Tenant
  id, name, slug, settings (JSON), created_at

Role
  id, name, tenant_id (NULL = global), description
  permissions (M2M)

Permission
  id, name (unique), description

Session
  id, user_id, tenant_id, refresh_token
  ip_address, device_fingerprint, last_seen, expires_at
  is_revoked, last_jti

OAuthAccount
  id, user_id, provider, provider_user_id, provider_email
  access_token, refresh_token, expires_at

Invite
  id, tenant_id, role_id, invited_by, email
  token (UUID unique), expires_at, used_at, is_active

AuditLog
  id, tenant_id, user_id, action, resource, resource_id
  ip_address, user_agent, meta (JSON), created_at
```
