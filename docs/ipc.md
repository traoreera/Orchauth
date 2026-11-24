# IPC — Intégration inter-plugins

Les autres plugins xcore peuvent interagir avec XAuth via le système d'appels IPC sans dépendance directe. Toutes les actions sont disponibles via `ctx.caller("xauth", action, payload)`.

---

## `verify_token`

Valide un access token JWT et retourne le contexte utilisateur.

```python
result = await ctx.caller("xauth", "verify_token", {
    "token": "eyJ..."
})
```

**Réponse :**
```json
{
  "valid": true,
  "user_id": "uuid",
  "tenant_id": "uuid",
  "email": "user@example.com",
  "permissions": ["plugin:read", "submissions:create"]
}
```

Si le token est invalide, expiré ou blacklisté :
```json
{ "valid": false, "error": "Token invalide ou expiré" }
```

---

## `has_permission`

Vérifie si un utilisateur possède une permission dans un tenant.

```python
result = await ctx.caller("xauth", "has_permission", {
    "user_id": "uuid",
    "tenant_id": "uuid",
    "permission": "plugin:publish"
})
```

**Réponse :**
```json
{ "has_permission": true }
```

---

## `get_user`

Récupère le profil d'un utilisateur.

```python
result = await ctx.caller("xauth", "get_user", {
    "user_id": "uuid"
})
```

**Réponse :**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "is_active": true,
  "mfa_enabled": false,
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

## `get_tenant`

Récupère les informations d'un tenant.

```python
result = await ctx.caller("xauth", "get_tenant", {
    "tenant_id": "uuid"
})
```

**Réponse :**
```json
{
  "id": "uuid",
  "name": "Default",
  "slug": "default",
  "created_at": "2026-01-01T00:00:00Z"
}
```

---

## `create_invite`

Crée une invitation pour un tenant et retourne l'URL d'acceptation.

```python
result = await ctx.caller("xauth", "create_invite", {
    "tenant_id": "uuid",
    "email": "nouveau@example.com",
    "invited_by": "uuid-user",
    "role_id": "uuid-optionnel",
    "expires_hours": 48
})
```

**Réponse :**
```json
{
  "id": "uuid",
  "token": "uuid-token",
  "accept_url": "https://api.monapp.com/xauth/invites/accept?token=...",
  "expires_at": "2026-01-17T10:30:00Z"
}
```

---

## `log_event`

Enregistre une entrée dans l'audit log. Utilisé par les autres plugins pour tracer leurs actions sensibles.

```python
await ctx.caller("xauth", "log_event", {
    "tenant_id": "uuid",          # optionnel
    "user_id": "uuid",            # optionnel
    "action": "plugin.published", # obligatoire
    "resource": "plugin",         # optionnel
    "resource_id": "uuid",        # optionnel
    "ip_address": "82.x.x.x",    # optionnel
    "user_agent": "...",          # optionnel
    "meta": {                     # optionnel — dict JSON
        "plugin_name": "xpayment",
        "version": "1.2.0"
    }
})
```

**Réponse :** `{ "logged": true }`

---

## `xauth.iam.member.provision`

Crée le compte d'un futur membre et l'inscrit dans l'organisation, avec un **mot de passe provisoire**. Pour un employeur qui
ouvre un accès à un salarié sans attendre qu'il réponde à une invitation.

**Charge :** `{ "tenant_id": "...", "actor_id": "...", "email": "...", "role_id": null, "password": null }`

`password` (facultatif) : un mot de passe provisoire FOURNI par l'appelant — un hôte qui le dérive de son service de clés —,
de 12 à 128 caractères, avec une majuscule et un chiffre. Absent, xauth le tire lui-même. Dans les deux cas il est rendu dans
la réponse et le compte doit en changer avant toute session.

**Réponse :** `{ "status": "ok", "member": { "user_id": "...", "email": "...", "temporary_password": "...", "must_change_password": true } }`

- `actor_id` doit **administrer** l'organisation (propriétaire, rôle `tenant_admin`, ou administrateur de la plateforme) :
  xauth le juge, pas le plugin appelant. Sinon `code: forbidden`.
- Seulement pour une adresse qu'xauth **ne connaît pas**. Un compte qui existe ne reçoit jamais un mot de passe par cette
  porte (`code: invalid`) : il s'invite (`xauth.create_invite`).
- Le mot de passe provisoire est rendu **une seule fois**, dans cette réponse. Il n'est ni journalisé ni émis en événement.
- Le compte naît `must_change_password`. Tant que son titulaire n'a pas choisi son mot de passe, `POST /login` ne rend
  **aucun jeton** et n'ouvre aucune session : la réponse porte `password_change_required: true` et un
  `password_change_token` à usage unique (30 min), à présenter à `POST /password/reset` avec le nouveau mot de passe —
  qui doit différer du provisoire. Il se connecte ensuite normalement.

---

## Utiliser les dépendances FastAPI de xcore

Pour les routes FastAPI dans un plugin, il est plus simple d'utiliser les dépendances xcore directement plutôt que l'IPC :

```python
from xcore.kernel.api import get_current_user, require_permission
from fastapi import Depends

@router.get("/protected")
async def route(user = Depends(get_current_user)):
    # user["sub"]         → user_id
    # user["tid"]         → tenant_id
    # user["permissions"] → liste des permissions
    return {"user_id": user["sub"]}

@router.post("/admin-only")
async def admin_route(_ = Depends(require_permission("admin:*"))):
    return {"ok": True}
```

Ces dépendances vérifient automatiquement le token Bearer, la blacklist JTI, et les permissions — sans aucun appel IPC.
