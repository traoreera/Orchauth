# XAuth — Guide d'intégration xcore

## Rate Limiting Middleware

### Comment ça marche

Le middleware `RateLimitMiddleware` est implémenté dans [src/middleware/rate_limit.py](src/middleware/rate_limit.py).

Il utilise le **cache Redis xcore** (sliding-window via `get`/`set`) pour compter les requêtes par IP. En cas d'indisponibilité du cache, il laisse passer (fail-open) pour ne pas bloquer le service.

Limites par défaut :

| Route | Max requêtes | Fenêtre |
|---|---|---|
| `/xauth/auth/login` | 10 | 60s |
| `/xauth/auth/register` | 5 | 60s |
| `/xauth/auth/verify-mfa` | 5 | 60s |
| `/xauth/password/forgot` | 3 | 5min |
| `/xauth/password/reset` | 5 | 5min |
| `/xauth/oauth/*` | 30 | 60s |
| Toutes autres routes xauth | 300 | 60s |

### Enregistrement dans xcore

xcore gere le systeme de middleware au boot de l'app
la configuration du middleware se fait dans le fichier de configuration principal de xcore

```yaml
middleware:
    - name: RateLimite
      module: xauth.src.middleware.rate_limit.RateLimitMiddleware
      config:
        - name: cache
          type: internal
          value: cache
```

### Personnaliser les limites

Passez un dict `route_limits` au middleware :

```yaml
middleware:
    - name: RateLimite
      module: xauth.src.middleware.rate_limit.RateLimitMiddleware
      config:
        - name: cache
          type: internal
          value: cache
        - name: route_limits
          type: external
          value:
            "/xauth/auth/login":    (5, 60)
            "/xauth/auth/register": (5, 60)
            "/xauth/auth/verify-mfa": (5, 60)
```

Pour désactiver en développement :

```yaml
middleware:
    - name: RateLimite
      module: xauth.src.middleware.rate_limit.RateLimitMiddleware
      config:
        - name: cache
          type: internal
          value: cache
        - name: route_limits
          type: external
          value:
            "/xauth/auth/login":    (5, 60)
        - name: enabled
          type: external
          value: false
```

---

## Flow MFA (deux étapes)

Quand un utilisateur a activé le MFA, le login se fait en deux appels :

**Étape 1 — Login**
```
POST /xauth/auth/login
{ "email": "...", "password": "..." }

→ { "access_token": "", "refresh_token": "...", "mfa_required": true }
```

**Étape 2 — Vérification TOTP**
```
POST /xauth/auth/verify-mfa
{ "refresh_token": "...", "code": "123456" }

→ { "access_token": "eyJ...", "refresh_token": "...", "mfa_required": false }
```

Le code peut être un code TOTP (6 chiffres) **ou** un backup code (10 caractères hex, usage unique).

---

## Blacklist de tokens (logout immédiat)

À chaque logout, le JTI du dernier access token émis est blacklisté dans Redis (TTL = durée de vie de l'access token). Le backend vérifie la blacklist à chaque requête dans `decode_token()`.

Cela garantit qu'un access token volé est invalidé immédiatement après logout, sans attendre son expiration naturelle.

---

## Gestion des sessions

| Endpoint | Description |
|---|---|
| `GET /xauth/auth/sessions` | Liste les sessions actives de l'utilisateur |
| `DELETE /xauth/auth/sessions/{id}` | Révoque une session (un appareil) |
| `DELETE /xauth/auth/sessions` | Révoque toutes les sessions (tous les appareils) |

La révocation d'une session blackliste aussi son JTI immédiatement.

---

## Administration des utilisateurs

Routes nécessitant les permissions `user:list`, `user:read`, `user:update`, `user:delete` :

| Endpoint | Permission | Description |
|---|---|---|
| `GET /xauth/admin/users` | `user:list` | Liste paginée des utilisateurs |
| `GET /xauth/admin/users/{id}` | `user:read` | Détail d'un utilisateur |
| `PATCH /xauth/admin/users/{id}` | `user:update` | Activer / désactiver un compte |
| `DELETE /xauth/admin/users/{id}` | `user:delete` | Suppression définitive |

Désactiver un compte (`is_active: false`) révoque également toutes ses sessions actives et blackliste leurs JTI.

---

## Variables d'environnement requises

Toutes les variables sont préfixées `XAUTH_` dans `.env` et injectées via `self.ctx.env` :

```env
XAUTH_JWT_PRIVATE_KEY_PATH=conf/private.pem
XAUTH_JWT_PUBLIC_KEY_PATH=conf/public.pem
XAUTH_JWT_ACCESS_EXPIRE_MINUTES=15
XAUTH_JWT_REFRESH_EXPIRE_DAYS=7

ADMIN_EMAIL=contact@example.com
ADMIN_PASSWORD=ChangeMe123!
ADMIN_TENANT_SLUG=default
ADMIN_TENANT_NAME=Default
ADMIN_ROLE_NAME=admin
USER_ROLE_NAME=user
```

Générer les clés RS256 :
```bash
openssl genrsa -out conf/private.pem 2048
openssl rsa -in conf/private.pem -pubout -out conf/public.pem
```
