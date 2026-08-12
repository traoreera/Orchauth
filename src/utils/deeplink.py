from __future__ import annotations

from urllib.parse import urlencode, urlsplit

# Schémas de deep-link autorisés pour le rebond (anti open-redirect) — même
# liste que /app/xpay/billing/return dans xpayproxy.
ALLOWED_BRIDGE_SCHEMES = {"erp", "http", "https"}

BRIDGE_PATH = "/app/auth/redirect"

# Schéma desktop implicite : toujours autorisé, jamais configuré (une
# app.identifier de schéma custom ne peut pas être détournée par un site
# tiers de la même façon qu'une origine https arbitraire — contrairement à
# `web_origins`, ce n'est pas un vecteur d'open-redirect).
DESKTOP_SCHEME = "erp"


def is_allowed_redirect_target(target: str, web_origins: frozenset[str]) -> bool:
    """
    Un `redirect`/`post_login_redirect` fourni par le CLIENT (pas construit
    côté serveur, contrairement aux liens d'email) doit être validé avant
    d'être stocké puis réutilisé dans la redirection finale du callback OAuth
    — sans ça, `?redirect=https://evil.com` renverrait un access_token/
    refresh_token fraîchement émis droit vers un site tiers (open-redirect
    avec exfiltration de jeton, pas juste une redirection cosmétique).

    - schéma `erp` (deep-link desktop) → toujours autorisé.
    - schéma `https` → autorisé seulement si l'origine (scheme+host+port)
      est dans `web_origins` (liste blanche explicite, vide par défaut tant
      qu'aucun frontend web n'est déployé — voir OAUTH_WEB_REDIRECT_ORIGINS).
    - tout le reste (http en clair, autre schéma custom, cible malformée)
      → refusé.
    """
    try:
        parts = urlsplit(target)
    except ValueError:
        return False
    if parts.scheme == DESKTOP_SCHEME:
        return True
    if parts.scheme == "https" and parts.netloc:
        origin = f"{parts.scheme}://{parts.netloc}"
        return origin in web_origins
    return False


def wrap_bridge(app_base_url: str, target: str) -> str:
    """Emballe un deep-link (schéma non http) dans la page de rebond https.

    Symétrique à `_wrap_deeplink` dans xpayproxy : un destinataire qui n'a pas
    encore l'app installée voit une page https normale plutôt qu'un lien mort
    que son système ne sait pas ouvrir. Un chemin déjà http(s) est renvoyé tel
    quel (rien à envelopper).
    """
    scheme = urlsplit(target).scheme
    if scheme and scheme not in ("http", "https"):
        return f"{app_base_url.rstrip('/')}{BRIDGE_PATH}?{urlencode({'target': target})}"
    return target
