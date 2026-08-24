# Flux de connexion

Cette page décrit les différents flux d'authentification de bout en bout.

---

## 1. Inscription + Connexion standard

```
Client                          XAuth
  │                               │
  │  POST /auth/register          │
  │  { email, password }          │
  │ ────────────────────────────► │  Crée l'utilisateur
  │                               │  Rattache au tenant "default" (rôle user)
  │  201 { id, email, ... }       │  Envoie email de bienvenue (file)
  │ ◄──────────────────────────── │
  │                               │
  │  POST /auth/login             │
  │  { email, password }          │
  │ ────────────────────────────► │  Vérifie le mot de passe
  │                               │  Crée une Session (refresh_token)
  │                               │  Génère access_token (JWT RS256, jti=uuid)
  │                               │  Stocke last_jti sur la Session
  │  200 {                        │
  │    access_token: "eyJ...",    │
  │    refresh_token: "uuid...",  │
  │    mfa_required: false        │
  │  }                            │
  │ ◄──────────────────────────── │
  │                               │
  │  GET /me                      │
  │  Authorization: Bearer eyJ... │
  │ ────────────────────────────► │  Vérifie signature JWT
  │                               │  Vérifie JTI blacklist (Redis)
  │  200 { id, email, ... }       │  Charge l'utilisateur depuis DB
  │ ◄──────────────────────────── │
```

---

## 2. Connexion avec MFA activé

```
Client                          XAuth
  │                               │
  │  POST /auth/login             │
  │  { email, password }          │
  │ ────────────────────────────► │  Vérifie le mot de passe ✓
  │                               │  Détecte mfa_enabled = true
  │                               │  Crée Session (refresh_token)
  │                               │  NE génère PAS d'access_token valide
  │  200 {                        │
  │    access_token: "",          │
  │    refresh_token: "uuid...",  │
  │    mfa_required: true         │
  │  }                            │
  │ ◄──────────────────────────── │
  │                               │
  │  POST /auth/verify-mfa        │
  │  { refresh_token, code }      │
  │ ────────────────────────────► │  Valide le refresh_token → Session
  │                               │  Vérifie code TOTP ou code de secours
  │                               │  Si code de secours → usage unique, supprimé
  │                               │  Génère access_token (JWT RS256, jti=uuid)
  │                               │  Met à jour last_jti sur la Session
  │  200 {                        │
  │    access_token: "eyJ...",    │
  │    refresh_token: "uuid...",  │
  │    mfa_required: false        │
  │  }                            │
  │ ◄──────────────────────────── │
```

---

## 3. Rotation des tokens (Refresh)

L'access token expire au bout de 15 minutes (configurable). Le client utilise le refresh token pour en obtenir un nouveau sans redemander les credentials.

```
Client                          XAuth
  │                               │
  │  POST /auth/refresh           │
  │  { refresh_token: "uuid..." } │
  │ ────────────────────────────► │  Trouve la Session via refresh_token
  │                               │  Vérifie Session non révoquée, non expirée
  │                               │  Révoque l'ancienne Session (is_revoked=true)
  │                               │  Crée une nouvelle Session
  │                               │  Génère nouvel access_token (nouveau jti)
  │                               │  Met à jour last_jti
  │  200 {                        │
  │    access_token: "eyJ...",    │  ← nouveau token
  │    refresh_token: "uuid2...", │  ← nouveau refresh token
  │    mfa_required: false        │
  │  }                            │
  │ ◄──────────────────────────── │
```

> Après un refresh, l'ancien refresh token est invalide. Le stocker côté client avant d'écraser.

---

## 4. Déconnexion

```
Client                          XAuth                        Redis
  │                               │                             │
  │  POST /auth/logout            │                             │
  │  { refresh_token: "uuid..." } │                             │
  │ ────────────────────────────► │  Trouve la Session          │
  │                               │  Récupère last_jti          │
  │                               │  SET xauth:jti_bl:{jti} ──► │  TTL = expire_minutes*60+30
  │                               │  Révoque la Session         │
  │  204 No Content               │                             │
  │ ◄──────────────────────────── │                             │
  │                               │                             │
  │  GET /me                      │                             │
  │  Authorization: Bearer eyJ... │                             │
  │ ────────────────────────────► │  Vérifie signature JWT ✓    │
  │                               │  GET xauth:jti_bl:{jti} ──► │
  │                               │  ◄── "1" (blacklisté)       │
  │  401 Unauthorized             │                             │
  │ ◄──────────────────────────── │                             │
```

L'access token est rejeté immédiatement même s'il n'a pas encore expiré.

---

## 5. Connexion OAuth

```
Navigateur               XAuth                    Provider OAuth
  │                        │                            │
  │  GET /oauth/google/authorize
  │ ──────────────────────► │                            │
  │                        │  Construit l'URL OAuth      │
  │  302 Redirect ─────────────────────────────────────► │
  │                                                      │
  │  L'utilisateur se connecte chez le provider          │
  │                                                      │
  │  Callback : GET /oauth/google/callback?code=abc      │
  │ ──────────────────────► │                            │
  │                        │  Échange le code ──────────► │
  │                        │  ◄── { access_token, email } │
  │                        │                            │
  │                        │  Cherche un User par email
  │                        │  ┌─ Trouvé : connecte
  │                        │  └─ Inconnu : crée compte
  │                        │       + rattache tenant "default" (rôle user)
  │                        │       + enregistre OAuthAccount
  │                        │
  │                        │  Crée Session, génère JWT
  │  200 {                 │
  │    access_token: "eyJ...",
  │    refresh_token: "...",
  │    mfa_required: false │
  │  }                     │
  │ ◄────────────────────── │
```

---

## 6. Réinitialisation du mot de passe

```
Client                          XAuth                        Email
  │                               │                             │
  │  POST /password/forgot        │                             │
  │  { email: "user@..." }        │                             │
  │ ────────────────────────────► │  Génère un token signé      │
  │                               │  Stocke en DB (TTL 15 min)  │
  │                               │  Envoie email ────────────► │
  │  202 Accepted                 │                             │
  │ ◄──────────────────────────── │                             │
  │                               │                             │
  │         (l'utilisateur clique sur le lien dans l'email)
  │                               │
  │  POST /password/reset         │
  │  { token: "...",              │
  │    new_password: "..." }      │
  │ ────────────────────────────► │  Valide le token (non expiré, non utilisé)
  │                               │  Hash le nouveau mot de passe
  │                               │  Révoque toutes les sessions actives
  │                               │  Blackliste tous les last_jti
  │                               │  Envoie email de confirmation
  │  200 OK                       │
  │ ◄──────────────────────────── │
```

---

## 7. Connexion multi-tenant

Le comportement de `/auth/login` dépend du nombre de tenants de l'utilisateur et de si le `tenant_id` est fourni ou non dans la requête.

### Arbre de décision au login

```
POST /auth/login { email, password, tenant_id? }
        │
        ├─ tenant_id fourni ?
        │       ├─ oui → vérifie membership → flow normal (→ cas A ou B)
        │       └─ non → compte les memberships
        │                   ├─ 0 → 401 "No tenant membership found"
        │                   ├─ 1 → scope direct → flow normal (→ cas A ou B)
        │                   └─ 2+ → retourne liste tenants (→ cas C ou D)
        │
        ├─ Cas A : 1 tenant résolu, MFA désactivé
        │       → access_token + refresh_token, mfa_required: false
        │
        ├─ Cas B : 1 tenant résolu, MFA activé
        │       → access_token: "", refresh_token, mfa_required: true
        │       → continuer avec /auth/verify-mfa (flux 2)
        │
        ├─ Cas C : plusieurs tenants, MFA désactivé
        │       → access_token: "", refresh_token, tenants: [...], mfa_required: false
        │       → continuer avec /auth/select-tenant
        │
        └─ Cas D : plusieurs tenants, MFA activé
                → access_token: "", refresh_token, tenants: [...], mfa_required: true
                → continuer avec /auth/select-tenant PUIS /auth/verify-mfa
```

---

### Cas C — Plusieurs tenants, sans MFA

```
Client                                    XAuth
  │                                         │
  │  POST /auth/login                       │
  │  { email, password }                    │
  │ ──────────────────────────────────────► │  Credentials OK
  │                                         │  Trouve 2 memberships (tenant A, tenant B)
  │                                         │  Crée Session (tenant_id = null)
  │  200 {                                  │
  │    access_token: "",                    │
  │    refresh_token: "uuid...",            │
  │    mfa_required: false,                 │
  │    tenants: [                           │
  │      { id: "uuid-A", name: "Acme",      │
  │        slug: "acme", role_id: "...",    │
  │        is_owner: true },               │
  │      { id: "uuid-B", name: "Beta",      │
  │        slug: "beta", role_id: "...",    │
  │        is_owner: false }               │
  │    ]                                    │
  │  }                                      │
  │ ◄──────────────────────────────────── │
  │                                         │
  │  [Le client affiche le sélecteur]       │
  │  [L'utilisateur choisit "Acme"]         │
  │                                         │
  │  POST /auth/select-tenant               │
  │  { refresh_token: "uuid...",            │
  │    tenant_id: "uuid-A" }               │
  │ ──────────────────────────────────────► │  Vérifie refresh_token → Session
  │                                         │  Vérifie membership user ↔ tenant A
  │                                         │  Génère access_token (tid=uuid-A)
  │                                         │  Met à jour Session.tenant_id = uuid-A
  │                                         │  Met à jour Session.last_jti
  │  200 {                                  │
  │    access_token: <JWT scopé tid=uuid-A>,│
  │    refresh_token: "uuid...",            │  ← même refresh token, pas de rotation
  │    tenant_id: "uuid-A",                 │
  │    mfa_required: false                  │
  │  }                                      │
  │ ◄──────────────────────────────────── │
```

---

### Cas D — Plusieurs tenants, avec MFA

```
Client                                    XAuth
  │                                         │
  │  POST /auth/login                       │
  │  { email, password }                    │
  │ ──────────────────────────────────────► │  Credentials OK, mfa_enabled = true
  │                                         │  Trouve 2 memberships
  │                                         │  Crée Session (tenant_id = null)
  │  200 {                                  │
  │    access_token: "",                    │
  │    refresh_token: "uuid...",            │
  │    mfa_required: true,                  │  ← MFA requis
  │    tenants: [                           │
  │      { id: "uuid-A", name: "Acme", ... },
  │      { id: "uuid-B", name: "Beta", ... }
  │    ]                                    │
  │  }                                      │
  │ ◄──────────────────────────────────── │
  │                                         │
  │  [Le client affiche d'abord le sélecteur de tenant]
  │  [L'utilisateur choisit "Acme"]         │
  │                                         │
  │  POST /auth/select-tenant               │
  │  { refresh_token: "uuid...",            │
  │    tenant_id: "uuid-A" }               │
  │ ──────────────────────────────────────► │  Vérifie membership ✓
  │                                         │  Scope Session.tenant_id = uuid-A
  │                                         │  Génère access_token (tid=uuid-A)
  │  200 { access_token: "eyJ...", ... }    │
  │ ◄──────────────────────────────────── │
  │                                         │
  │  [Le client affiche ensuite le formulaire MFA]
  │                                         │
  │  POST /auth/verify-mfa                  │
  │  { refresh_token: "uuid...",            │
  │    code: "123456" }                     │
  │ ──────────────────────────────────────► │  Session.tenant_id = uuid-A déjà scopé
  │                                         │  Vérifie code TOTP
  │                                         │  Génère access_token final (tid=uuid-A)
  │                                         │  Met à jour last_jti
  │  200 { access_token: <JWT final>,       │
  │         mfa_required: false }           │
  │ ◄──────────────────────────────────── │
```

> Dans le cas D, `select-tenant` émet un premier access_token intermédiaire, mais le client ne doit l'utiliser qu'après avoir complété le MFA via `verify-mfa`. L'access_token final de `verify-mfa` est celui à conserver — il porte le bon `tid` et le bon `jti` lié à la session MFA vérifiée.

---

### Réponse login — champs

| Champ | 1 tenant, pas MFA | 1 tenant, MFA | Multi-tenant |
|---|---|---|---|
| `access_token` | JWT valide | `""` | `""` |
| `refresh_token` | UUID | UUID | UUID |
| `mfa_required` | `false` | `true` | `false` ou `true` |
| `tenants` | `null` | `null` | `[{id, name, slug, role_id, is_owner}]` |
| `tenant_id` | UUID résolu | UUID résolu | `null` |

---

## Cycle de vie d'un token

```
              ┌─────────────────────────────────────────────┐
              │              ACCESS TOKEN                    │
              │  jti=abc123  │  tid=tenant1  │  exp=+15min   │
              └─────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
    Expiré         Logout        Révocation
    (exp < now)    (blacklist)   session/compte
        │              │              │
        └──────────────┴──────────────┘
                       │
                  Token rejeté
                  → 401 Unauthorized
```
