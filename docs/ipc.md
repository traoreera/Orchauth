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
