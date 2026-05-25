# API — OAuth 2.0

XAuth supporte Google, GitHub, Discord, Microsoft. Un provider est activé uniquement si `client_id` et `client_secret` sont tous les deux présents dans les variables d'environnement.

Préfixe : `/xauth/oauth`.

---

## Configuration des providers

Dans `.env` (via la section `env:` de `plugin.yaml`) :

```bash
# Google
XAUTH_OAUTH_GOOGLE_CLIENT_ID=...
XAUTH_OAUTH_GOOGLE_CLIENT_SECRET=...

# GitHub
XAUTH_OAUTH_GITHUB_CLIENT_ID=...
XAUTH_OAUTH_GITHUB_CLIENT_SECRET=...

# Discord
XAUTH_OAUTH_DISCORD_CLIENT_ID=...
XAUTH_OAUTH_DISCORD_CLIENT_SECRET=...

# Microsoft / Azure AD
XAUTH_OAUTH_MICROSOFT_CLIENT_ID=...
XAUTH_OAUTH_MICROSOFT_CLIENT_SECRET=...
```

**Redirect URI à enregistrer chez le provider :**
```
{APP_BASE_URL}/xauth/oauth/{provider}/callback
```

Exemple : `https://api.monapp.com/xauth/oauth/google/callback`

---

## Endpoints

### GET `/providers`

Retourne la liste des providers activés.

```json
["google", "github"]
```

---

### GET `/{provider}/authorize`

Redirige le navigateur vers la page d'autorisation du provider.

```
GET /xauth/oauth/google/authorize
→ 302 Redirect → https://accounts.google.com/o/oauth2/auth?...
```

---

### GET `/{provider}/callback`

Callback appelé par le provider après autorisation. Crée ou connecte l'utilisateur, retourne les tokens.

Les nouveaux utilisateurs créés via OAuth sont automatiquement rattachés au tenant `default` avec le rôle `user`.

**Réponse 200 :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "uuid...",
  "token_type": "bearer",
  "mfa_required": false
}
```

---

### POST `/{provider}/link`

Lie un compte OAuth à un compte existant (utilisateur déjà authentifié).

**Header :** `Authorization: Bearer <access_token>`

**Corps :**
```json
{
  "code": "authorization_code_from_provider",
  "redirect_uri": "https://..."
}
```

**Réponse 200 :**
```json
{
  "provider": "google",
  "provider_email": "user@gmail.com",
  "linked": true
}
```

Un email de confirmation `oauth_linked` est envoyé.

---

### DELETE `/{provider}/unlink`

Supprime le lien entre le compte et le provider OAuth.

**Header :** `Authorization: Bearer <access_token>`

**Contrainte :** impossible si le compte n'a pas de mot de passe défini et que c'est le seul provider lié (évite le blocage du compte).

---

### GET `/me/accounts`

Liste les comptes OAuth liés à l'utilisateur courant.

**Header :** `Authorization: Bearer <access_token>`

```json
[
  {
    "provider": "google",
    "provider_email": "user@gmail.com",
    "provider_user_id": "1234567890"
  }
]
```

---

## Comportement à la connexion OAuth

1. Si l'email du provider correspond à un utilisateur existant → connexion directe (ou création du lien OAuth)
2. Si l'email est inconnu → création d'un nouveau compte sans mot de passe + rattachement au tenant `default`
3. Si le provider retourne une erreur → `400 Bad Request` avec le message du provider
