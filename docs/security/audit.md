# Audit Log

Chaque action sensible est enregistrée dans la table `AuditLog` avec le contexte complet.

---

## Structure d'un log

| Champ | Type | Description |
|---|---|---|
| `id` | UUID | Identifiant unique |
| `tenant_id` | UUID / null | Tenant concerné |
| `user_id` | UUID / null | Utilisateur qui a effectué l'action |
| `action` | string | Type d'action (voir liste ci-dessous) |
| `resource` | string / null | Type de ressource ciblée |
| `resource_id` | UUID / null | Identifiant de la ressource |
| `ip_address` | string / null | Adresse IP |
| `user_agent` | string / null | User-Agent HTTP |
| `meta` | JSON / null | Données contextuelles supplémentaires |
| `created_at` | datetime | Horodatage UTC |

---

## Actions enregistrées par XAuth

| Action | Déclencheur |
|---|---|
| `login.success` | Connexion réussie |
| `login.failed` | Echec de connexion (mauvais mdp) |
| `logout` | Déconnexion |
| `user.registered` | Inscription |
| `user.disabled` | Désactivation admin |
| `user.deleted` | Suppression admin |

---

## Lecture des logs

```
GET /xauth/audit/tenants/{tenant_id}
Permission requise : audit:read

→ [
    {
      "id": "...",
      "action": "login.success",
      "user_id": "...",
      "ip_address": "82.x.x.x",
      "created_at": "2026-01-15T10:30:00Z",
      "meta": null
    },
    ...
  ]

GET /xauth/audit/users/{user_id}
Permission requise : audit:read
```

---

## Écrire dans l'audit depuis un autre plugin

Via IPC :

```python
await ctx.caller("xauth", "log_event", {
    "tenant_id": "...",
    "user_id": "...",
    "action": "plugin.published",
    "resource": "plugin",
    "resource_id": "...",
    "ip_address": "82.x.x.x",
    "meta": {"plugin_name": "xpayment", "version": "1.2.0"}
})
```

Tous les champs sauf `action` sont optionnels.

---

## Immutabilité

Les logs d'audit ne sont jamais modifiés ni supprimés par l'API. Il n'existe pas d'endpoint de suppression. La rétention est gérée au niveau base de données (politique de purge externe si nécessaire).
