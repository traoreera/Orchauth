# Tokens JWT et Sécurité des Sessions

## Architecture JWT RS256

XAuth utilise des tokens JWT signés avec RS256 (RSA + SHA-256). La clé privée signe les tokens, la clé publique les vérifie. Les autres plugins xcore n'ont besoin que de la clé publique pour valider indépendamment sans appel réseau.

```
Access Token  — TTL configurable (défaut 15 min)
Refresh Token — TTL configurable (défaut 7 jours)
```

### Payload de l'access token

```json
{
  "sub": "<user_id>",
  "tid": "<tenant_id>",
  "jti": "<uuid4>",
  "exp": 1234567890,
  "iat": 1234567890,
  "permissions": ["plugin:read", "submissions:create"]
}
```

- `sub` : identifiant de l'utilisateur
- `tid` : tenant actif au moment de la connexion
- `jti` : identifiant unique du token — utilisé pour la blacklist
- `permissions` : liste des permissions du rôle dans le tenant actif

---

## Blacklist JTI

Chaque access token possède un `jti` (JWT ID) unique. À la révocation (logout, révocation de session, désactivation d'un compte), ce `jti` est placé dans Redis avec un TTL égal à la durée de vie restante de l'access token.

```
Clé Redis : xauth:jti_bl:{jti}
TTL       : access_expire_minutes * 60 + 30 secondes
```

`XAuthBackend.decode_token()` vérifie la blacklist à chaque requête après validation de la signature. Si le `jti` est en liste noire, le token est rejeté immédiatement, même s'il n'est pas encore expiré.

**Cas déclencheurs :**

| Action | Effet sur la blacklist |
|---|---|
| `POST /auth/logout` | Blacklist du `last_jti` de la session |
| `DELETE /auth/sessions/{id}` | Blacklist du `last_jti` de la session révoquée |
| `DELETE /auth/sessions` | Blacklist de tous les `last_jti` actifs |
| `PATCH /admin/users/{id}` avec `is_active: false` | Blacklist de tous les `last_jti` de l'utilisateur |

---

## Refresh Token et Rotation

Le refresh token est un UUID opaque stocké en base (table `Session`). À chaque appel à `/auth/refresh` :

1. La session existante est révoquée (`is_revoked = true`)
2. Une nouvelle session est créée avec un nouveau refresh token
3. Un nouvel access token est généré (nouveau `jti`)
4. Le `last_jti` de la nouvelle session est mis à jour

---

## Sessions

La table `Session` stocke :

| Champ | Description |
|---|---|
| `refresh_token` | UUID opaque (non devinable) |
| `last_jti` | JTI du dernier access token émis pour cette session |
| `ip_address` | IP de création |
| `device_fingerprint` | Empreinte optionnelle du client |
| `expires_at` | Date d'expiration du refresh token |
| `is_revoked` | Révocation manuelle |

Un utilisateur peut avoir plusieurs sessions simultanées (multi-appareils). La liste est consultable via `GET /auth/sessions`.

---

## Fail-Open vs Fail-Closed

La vérification de la blacklist JTI est **fail-closed** : si le cache Redis est indisponible, la vérification est ignorée (le token est considéré valide). Ce choix évite une indisponibilité totale du service en cas de panne Redis, au prix d'un risque limité pendant la durée de l'indisponibilité.

Le rate limiting est lui **fail-open** par conception identique.
