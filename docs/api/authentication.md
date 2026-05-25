# API — Authentification

Tous les endpoints sont préfixés `/xauth/auth`.

---

## POST `/register`

Créer un compte utilisateur.

**Corps :**
```json
{
  "email": "user@example.com",
  "password": "MonMotDePasse123!",
  "tenant_slug": "default"
}
```

`tenant_slug` est optionnel. Si absent, l'utilisateur est rattaché au tenant `default`.

**Réponse 201 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "is_active": true,
  "mfa_enabled": false,
  "created_at": "2026-01-01T00:00:00Z"
}
```

Un email de bienvenue est envoyé en file (non bloquant).

---

## POST `/login`

Authentification par email/mot de passe.

**Corps :**
```json
{
  "email": "user@example.com",
  "password": "...",
  "tenant_id": "uuid-optionnel"
}
```

**Réponse 200 — sans MFA :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "uuid...",
  "token_type": "bearer",
  "mfa_required": false
}
```

**Réponse 200 — avec MFA activé :**
```json
{
  "access_token": "",
  "refresh_token": "uuid...",
  "token_type": "bearer",
  "mfa_required": true
}
```

Dans ce cas, utiliser `/verify-mfa` pour compléter l'authentification.

---

## POST `/verify-mfa`

Étape 2 du login MFA. Échange le refresh token + code TOTP contre un access token.

**Corps :**
```json
{
  "refresh_token": "uuid...",
  "code": "123456"
}
```

Le `code` peut être un code TOTP à 6 chiffres ou un code de secours (10 caractères hex).

**Réponse 200 :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "uuid-nouveau...",
  "token_type": "bearer",
  "mfa_required": false
}
```

---

## POST `/refresh`

Rotation des tokens. L'ancien refresh token est révoqué, un nouveau est émis.

**Corps :**
```json
{
  "refresh_token": "uuid..."
}
```

**Réponse 200 :** même structure que `/login`.

---

## POST `/logout`

Révoque la session. Le JTI de l'access token courant est blacklisté immédiatement.

**Corps :**
```json
{
  "refresh_token": "uuid..."
}
```

**Réponse : 204 No Content**

---

## GET `/me`

Retourne le profil de l'utilisateur authentifié.

**Header :** `Authorization: Bearer <access_token>`

**Réponse 200 :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "is_active": true,
  "mfa_enabled": true,
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

## GET `/sessions`

Liste les sessions actives de l'utilisateur courant.

**Header :** `Authorization: Bearer <access_token>`

**Réponse 200 :**
```json
[
  {
    "id": "uuid",
    "ip_address": "82.x.x.x",
    "device_fingerprint": null,
    "last_seen": "2026-01-15T10:30:00Z",
    "expires_at": "2026-01-22T10:30:00Z",
    "is_revoked": false
  }
]
```

---

## DELETE `/sessions/{session_id}`

Révoque une session spécifique (un appareil). Le JTI associé est blacklisté.

**Header :** `Authorization: Bearer <access_token>`

**Réponse : 204 No Content**

---

## DELETE `/sessions`

Révoque toutes les sessions actives de l'utilisateur. Tous les JTI sont blacklistés.

**Header :** `Authorization: Bearer <access_token>`

**Réponse : 204 No Content**
