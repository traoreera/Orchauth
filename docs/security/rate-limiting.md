# Rate Limiting

XAuth inclut un middleware de rate limiting par IP basé sur le cache Redis xcore.

---

## Fonctionnement

Stratégie : **sliding-window approximée** via des opérations `get`/`set` sur le cache. Compatible avec l'API cache xcore qui n'expose pas `INCR`/`EXPIRE` atomiques.

Pour chaque requête vers une route `/xauth/*` :

1. Construction d'une clé `xauth:rl:{ip}:{route_prefix}` (les deux premiers segments après `/xauth`)
2. Lecture du compteur courant dans Redis
3. Si le compteur dépasse la limite → réponse `429 Too Many Requests` avec header `Retry-After`
4. Sinon → incrémentation du compteur et passage de la requête

En cas d'indisponibilité du cache, le middleware laisse passer (fail-open) pour ne pas bloquer le service.

---

## Limites par défaut

| Route | Max requêtes | Fenêtre |
|---|---|---|
| `/xauth/auth/login` | 10 | 60 s |
| `/xauth/auth/register` | 5 | 60 s |
| `/xauth/auth/verify-mfa` | 5 | 60 s |
| `/xauth/password/forgot` | 3 | 5 min |
| `/xauth/password/reset` | 5 | 5 min |
| `/xauth/oauth/*` | 30 | 60 s |
| Toutes autres routes `/xauth/*` | 300 | 60 s |

---

## Configuration dans `plugin.yaml`

Le middleware lit sa configuration depuis la section `rate_limit` de `plugin.yaml` via `self.ctx.config`.

### Désactiver en développement

```yaml
rate_limit:
  enabled: false
```

### Surcharger les limites par route

```yaml
rate_limit:
  enabled: true
  routes:
    "/xauth/auth/login": [5, 60]       # 5 requêtes par 60 secondes
    "/xauth/auth/register": [2, 60]
    "/xauth/password/forgot": [2, 300]
```

Le format est `[max_requetes, fenetre_secondes]`. Les routes non listées conservent les limites par défaut du middleware.

### Enregistrement dans xcore

Le middleware est monté par xcore via `get_middlewares()` dans `main.py`. Aucune configuration supplémentaire n'est nécessaire dans `integration.yaml`.

Pour une configuration avancée côté xcore (montage manuel) :

```yaml
middleware:
  - name: XAuthRateLimit
    module: xauth.src.middleware.rate_limit.RateLimitMiddleware
    config:
      - name: cache
        type: internal
        value: cache
```

---

## Réponse en cas de dépassement

```
HTTP/1.1 429 Too Many Requests
Retry-After: 45

{
  "detail": "Too many requests. Please try again later."
}
```

Le header `Retry-After` indique le nombre de secondes avant que la fenêtre se réinitialise.
