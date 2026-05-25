# API — RBAC

Gestion des rôles et permissions. Préfixe : `/xauth/rbac`.

---

## Modèle de permissions

Les permissions sont des chaînes au format `resource:action`, par exemple `plugin:read`, `submissions:write`, `admin:*`.

Les rôles sont des collections de permissions. Un rôle peut être **global** (`tenant_id = null`) ou **scoped** à un tenant.

Un utilisateur hérite des permissions de son rôle dans le tenant actif (inclus dans le JWT comme `tid`).

---

## Permissions disponibles au démarrage (seed)

| Catégorie | Permissions |
|---|---|
| Plugins | `plugin:list` `plugin:read` `plugin:create` `plugin:update` `plugin:delete` `plugin:approve` `plugin:reject` `plugin:feature` |
| Soumissions | `submissions:list` `submissions:read` `submissions:create` `submissions:review` `submissions:approve` `submissions:reject` `submissions:delete` `submissions:write` |
| Évaluations | `rating:create` `rating:delete` |
| Utilisateurs | `user:list` `user:read` `user:update` `user:delete` `user:ban` |
| Tenants | `tenant:list` `tenant:read` `tenant:create` `tenant:update` `tenant:delete` `tenants:read` `tenants:write` `tenants:delete` |
| RBAC | `role:list` `role:create` `role:update` `role:delete` `permission:list` `permission:assign` `rbac:read` `rbac:write` |
| Audit | `audit:read` |
| Invitations | `invite:create` `invite:revoke` |
| Admin | `admin:*` |
| xpulse | `xpulse:publish` `xpulse:broadcast` |

Le rôle `admin` global reçoit toutes les permissions. Le rôle `user` global reçoit : `plugin:list`, `plugin:read`, `submissions:list/read/create/write`, `rating:create`, `user:read`.

---

## Endpoints

### POST `/roles` — Créer un rôle

Permission : `rbac:write`

```json
{
  "name": "moderator",
  "tenant_id": null,
  "description": "Modération des soumissions"
}
```

`tenant_id: null` crée un rôle global.

---

### GET `/roles` — Lister les rôles

Permission : `rbac:read`

```json
[
  {
    "id": "uuid",
    "name": "admin",
    "tenant_id": null,
    "description": "...",
    "permissions": [{"id": "...", "name": "plugin:read"}, ...]
  }
]
```

---

### GET `/roles/{role_id}` — Détail d'un rôle

Permission : `rbac:read`

---

### POST `/roles/{role_id}/permissions` — Assigner une permission

Permission : `rbac:write`

```json
{
  "permission_id": "uuid"
}
```

---

### DELETE `/roles/{role_id}/permissions/{permission_id}` — Retirer une permission

Permission : `rbac:write`

---

### POST `/tenants/{tenant_id}/members/{user_id}/role` — Assigner un rôle à un membre

Permission : `rbac:write`

```json
{
  "role_id": "uuid"
}
```

---

### GET `/permissions` — Lister toutes les permissions

Permission : `rbac:read`

---

## Utiliser les permissions dans un plugin

```python
from xcore.kernel.api import require_permission
from fastapi import Depends

@router.post("/publish")
async def publish(_ = Depends(require_permission("plugin:create"))):
    ...
```

`require_permission` vérifie que la permission est présente dans le JWT du token Bearer de la requête.
