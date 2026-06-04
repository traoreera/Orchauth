# RBAC — Guide d'intégration Frontend

Guide pour construire l'UI de gestion des accès de l'ERP (multi-tenant, tout-plugin).
Toutes les routes RBAC sont sous le préfixe **`/app/auth/rbac`**.

---

## 1. Modèle mental

Trois niveaux à ne jamais confondre :

1. **Authentification** — qui es-tu ? (login → JWT).
2. **Entitlement** — à quels plugins/modules le *tenant* a droit (ce qu'il a payé) → licences (`/app/xlicense`).
3. **Autorisation (RBAC)** — quels modules *cet utilisateur* peut utiliser dans le tenant.

Concepts RBAC :

| Concept | Définition | D'où ça vient |
|---|---|---|
| **Permission** | autorisation atomique (`stock:read`) | **agrégée automatiquement** depuis les plugins installés — jamais codée en dur |
| **Rôle** | paquet de permissions (`Magasinier`) | global (admin) ou propre au tenant (owner) |
| **Rôles d'un membre** | un user peut cumuler **plusieurs** rôles | assignés par le owner |
| **Permissions directes** | exceptions accordées à un membre précis | toggles owner |

**Règle de résolution** (calculée serveur, à chaque requête) :

```
droits effectifs(user, tenant) =
      ⋃ permissions de TOUS ses rôles   (rôle primaire + rôles cumulés)
    ∪ ses permissions directes
    → permissions ACTIVES uniquement
```

---

## 2. Authentification

Toutes les requêtes authentifiées : header `Authorization: Bearer <access_token>`.

| Étape | Appel | Notes |
|---|---|---|
| Login | `POST /app/auth/login` `{email, password}` | → `access_token`, `refresh_token` |
| Refresh | `POST /app/auth/refresh` `{refresh_token}` | sur 401 |
| Profil | `GET /app/auth/me` | infos user |
| Licence tenant | `GET /app/xlicense/me` | statut `active`, `features`, `quotas` |

Multi-tenant : si l'utilisateur appartient à plusieurs tenants, prévoir un écran de **sélection de tenant** (le `tenant_id` courant est porté par le JWT).

---

## 3. Gating de l'UI (afficher/masquer selon les droits)

Au bootstrap, récupère les droits de l'utilisateur **courant** :

```
GET /app/auth/rbac/me/permissions   → ["stock:read", "xpay:billing:read", ...]
GET /app/auth/rbac/me/roles         → ["role_id1", "role_id2"]
```

Ces deux routes sont **authentifiées sans droit RBAC requis** (chacun lit ses propres accès).
Si aucun tenant n'est sélectionné → renvoie `[]`.

```js
const perms = new Set(await fetch("/app/auth/rbac/me/permissions", { headers }).then(r => r.json()));
const can = (p) => perms.has(p);

// usage
can("stock:write") ? <BtnEditerStock/> : null
```

Recharge après : changement de tenant, ou modification des accès par le owner.

> ⚠️ Le masquage UI n'est qu'un confort. Le serveur revalide toujours (403). Ne jamais s'y fier seul pour la sécurité.

---

## 4. Écrans d'administration (OWNER)

Accessibles au **owner du tenant** (ou admin plateforme). `{tid}` = tenant courant.

### 4.1 Permissions disponibles (palette)

```
GET /app/auth/rbac/tenants/{tid}/grantable
```
```json
[
  { "name": "stock:read", "description": "Consulter le stock",
    "group": "Stock", "source_plugin": "stock",
    "tenant_grantable": true, "active": true }
]
```
→ grouper l'UI par `group` (ou `source_plugin`). C'est l'ensemble des droits délégables.

### 4.2 Rôles du tenant

| Action | Appel | Payload |
|---|---|---|
| Lister | `GET /tenants/{tid}/roles` | — |
| Créer | `POST /tenants/{tid}/roles` | `{ "name": "Magasinier", "description": "...", "permissions": ["stock:read","stock:write"] }` |
| Ajouter une perm | `POST /tenants/{tid}/roles/{rid}/permissions` | `{ "permission_name": "stock:write" }` |
| Retirer une perm | `DELETE /tenants/{tid}/roles/{rid}/permissions/{name}` | — |
| Supprimer | `DELETE /tenants/{tid}/roles/{rid}` | — |

Réponse rôle :
```json
{ "id": "...", "name": "Magasinier", "tenant_id": "...", "description": "...",
  "permissions": [ { "name": "stock:read", "group": "Stock", "description": "..." } ] }
```

### 4.3 Membres

| Action | Appel | Payload |
|---|---|---|
| Lister | `GET /tenants/{tid}/members` | — |
| Droits effectifs | `GET /tenants/{tid}/members/{uid}/permissions` | → `["stock:read", ...]` |
| Rôles du membre | `GET /tenants/{tid}/members/{uid}/roles` | → `["role_id", ...]` |
| Définir rôle primaire | `POST /tenants/{tid}/members/{uid}/role` | `{ "role_id": "..." }` |
| **Ajouter** un rôle (cumul) | `POST /tenants/{tid}/members/{uid}/roles` | `{ "role_id": "..." }` |
| Retirer un rôle | `DELETE /tenants/{tid}/members/{uid}/roles/{rid}` | — |
| Donner une perm directe | `POST /tenants/{tid}/members/{uid}/permissions` | `{ "permission_name": "xpay:billing:read" }` |
| Retirer une perm directe | `DELETE /tenants/{tid}/members/{uid}/permissions/{name}` | — |

Réponse `GET /members` :
```json
[ { "user_id": "...", "email": "marie@ex.com",
    "primary_role_id": "...", "role_ids": ["...","..."], "is_owner": false } ]
```

**UX recommandée pour la fiche membre :**
- toggles de **rôles** (multi-sélection) → POST/DELETE `.../roles`
- section **permissions supplémentaires** (toggles depuis `grantable`) → POST/DELETE `.../permissions`
- panneau read-only **droits effectifs** → `GET .../permissions`

---

## 5. Parcours type du owner

1. `GET /grantable` → voir ce qu'il peut distribuer.
2. `POST /tenants/{tid}/roles` → créer `Magasinier`.
3. `POST /tenants/{tid}/roles/{rid}/permissions` → le garnir.
4. `POST /tenants/{tid}/members/{uid}/roles` → l'assigner à un employé.
5. (option) `POST /tenants/{tid}/members/{uid}/permissions` → exception individuelle.
6. `GET /tenants/{tid}/members/{uid}/permissions` → vérifier le résultat.

---

## 6. Gestion des erreurs

| Code | Sens | Réaction UI |
|---|---|---|
| `401` | token absent/expiré | refresh puis relogin |
| `402` | licence tenant non active | écran « abonnement requis » (→ billing) |
| `403` | pas le droit (pas owner / pas la perm) | masquer l'action / message |
| `400` | requête invalide (perm non délégable, rôle hors tenant…) | toast avec le `detail` |
| `404` | rôle/membre introuvable | rafraîchir la liste |

---

## 7. Facturation (rappel, pour compléter l'ERP)

- `GET /app/xpay/billing/overview?tenant_id=...` → licence + abonnement + plans (avec `available_modes`).
- `POST /app/xpay/billing/checkout` `{ plan_id, tenant_id, billing_mode, customer_email, success_path, cancel_path }` → renvoie `{ url }` Stripe (rediriger dessus).
- `billing_mode` ∈ `available_modes` du plan (sinon 409).
- App desktop : `success_path` peut être un deep-link `erp://...` (emballé automatiquement par le serveur).

---

## 8. Règles d'or frontend

1. **Jamais de liste de permissions en dur** → toujours `GET /grantable` (elles changent avec les plugins installés).
2. **Gâter l'UI sur les permissions, pas les rôles** (un rôle n'est qu'un paquet modifiable).
3. **Le serveur reste juge** — le masquage n'est qu'un confort.
4. **Recharger les droits** après chaque modification (le cache serveur est déjà invalidé).
