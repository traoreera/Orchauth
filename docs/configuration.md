# Configuration — `plugin.yaml`

XAuth centralise toute sa configuration dans `plugin.yaml`. Les sections personnalisées sont exposées au plugin via `self.ctx.config` (le bloc `extra` du manifeste xcore).

---

## Sections

### `app`

Informations générales de l'application.

```yaml
app:
  name: "MonApp"          # Affiché dans les emails (défaut: "XAuth")
  base_url: "https://api.monapp.com"  # Utilisé dans les redirects OAuth et liens email
```

Surchargeable via env : `APP_NAME`, `APP_BASE_URL` (préfixe `XAUTH_`).

---

### `seed`

Données créées automatiquement au premier démarrage (idempotent — ignorées si déjà présentes).

```yaml
seed:
  admin_email: "admin@monapp.com"    # Email du compte administrateur
  admin_password: "ChangeMeNow!"    # Mot de passe (hashé avant stockage)
  admin_tenant_slug: "default"      # Slug du tenant par défaut
  admin_tenant_name: "Default"      # Nom affiché du tenant par défaut
  admin_role_name: "admin"          # Nom du rôle administrateur global
  user_role_name: "user"            # Nom du rôle standard (assigné aux nouveaux inscrits)
```

> Tous les champs sont **obligatoires**. Si l'un d'eux est absent du YAML et de l'env, le plugin refuse de démarrer avec un message d'erreur explicite.

Chaque champ peut être surchargé par sa variable d'environnement correspondante :

| Champ YAML | Variable d'env |
|---|---|
| `admin_email` | `ADMIN_EMAIL` |
| `admin_password` | `ADMIN_PASSWORD` |
| `admin_tenant_slug` | `ADMIN_TENANT_SLUG` |
| `admin_tenant_name` | `ADMIN_TENANT_NAME` |
| `admin_role_name` | `ADMIN_ROLE_NAME` |
| `user_role_name` | `USER_ROLE_NAME` |

**Priorité :** variable d'env > valeur `plugin.yaml` > erreur au démarrage.

---

### `jwt`

Configuration des tokens JWT RS256.

```yaml
jwt:
  private_key_path: "conf/private.pem"   # Chemin relatif à la racine du plugin
  public_key_path: "conf/public.pem"
  access_expire_minutes: 15              # Durée de vie de l'access token
  refresh_expire_days: 7                 # Durée de vie du refresh token
```

Générer les clés :

```bash
openssl genrsa -out conf/private.pem 2048
openssl rsa -in conf/private.pem -pubout -out conf/public.pem
```

Surchargeable via env : `XAUTH_JWT_PRIVATE_KEY_PATH`, `XAUTH_JWT_PUBLIC_KEY_PATH`, `XAUTH_JWT_ACCESS_EXPIRE_MINUTES`, `XAUTH_JWT_REFRESH_EXPIRE_DAYS`.

---

### `rate_limit`

Configuration du middleware de rate limiting (voir [Rate Limiting](security/rate-limiting.md)).

```yaml
rate_limit:
  enabled: true   # false pour désactiver (dev/test)
  routes: {}      # Override des limites par route (optionnel)
```

Exemple avec limites personnalisées :

```yaml
rate_limit:
  enabled: true
  routes:
    "/xauth/auth/login": [5, 60]      # 5 req / 60 s
    "/xauth/auth/register": [2, 60]
    "/xauth/password/forgot": [2, 300]
```

---

## Section `env` — Secrets uniquement

La section `env` est réservée aux valeurs qui ne doivent **jamais** apparaître en clair dans le fichier de configuration.

```yaml
env:
  # Surcharges optionnelles (plugin.yaml seed/jwt prend le dessus si absent)
  ADMIN_EMAIL: "${ADMIN_EMAIL}"
  ADMIN_PASSWORD: "${ADMIN_PASSWORD}"
  JWT_PRIVATE_KEY_PATH: "${XAUTH_JWT_PRIVATE_KEY_PATH}"

  # SMTP — toujours via env
  SMTP_HOST: "${XAUTH_SMTP_HOST}"
  SMTP_PORT: "${XAUTH_SMTP_PORT}"
  SMTP_USER: "${XAUTH_SMTP_USER}"
  SMTP_PASSWORD: "${XAUTH_SMTP_PASSWORD}"
  SMTP_FROM: "${XAUTH_SMTP_FROM}"
  SMTP_FROM_NAME: "${XAUTH_SMTP_FROM_NAME}"
  SMTP_USE_TLS: "${XAUTH_SMTP_USE_TLS}"

  # OAuth providers — activer en remplissant les deux clés
  OAUTH_GOOGLE_CLIENT_ID: "${XAUTH_OAUTH_GOOGLE_CLIENT_ID}"
  OAUTH_GOOGLE_CLIENT_SECRET: "${XAUTH_OAUTH_GOOGLE_CLIENT_SECRET}"
  OAUTH_GITHUB_CLIENT_ID: "${XAUTH_OAUTH_GITHUB_CLIENT_ID}"
  OAUTH_GITHUB_CLIENT_SECRET: "${XAUTH_OAUTH_GITHUB_CLIENT_SECRET}"
  OAUTH_DISCORD_CLIENT_ID: "${XAUTH_OAUTH_DISCORD_CLIENT_ID}"
  OAUTH_DISCORD_CLIENT_SECRET: "${XAUTH_OAUTH_DISCORD_CLIENT_SECRET}"
  OAUTH_MICROSOFT_CLIENT_ID: "${XAUTH_OAUTH_MICROSOFT_CLIENT_ID}"
  OAUTH_MICROSOFT_CLIENT_SECRET: "${XAUTH_OAUTH_MICROSOFT_CLIENT_SECRET}"
```

Les valeurs non renseignées (variable d'env absente) restent vides — un provider OAuth est désactivé automatiquement si son `client_id` ou `client_secret` est vide.

---

## Résolution de la configuration

```
plugin.yaml (seed / jwt / app)
        ↓ surchargé par
variables d'environnement (ADMIN_*, XAUTH_*)
        ↓ erreur si toujours absent (pour les champs obligatoires)
RuntimeError au démarrage
```

Cette priorité permet de définir les valeurs par défaut dans le dépôt (plugin.yaml) et de les surcharger en production via des secrets injectés (Kubernetes Secrets, Vault, etc.) sans modifier le fichier.
