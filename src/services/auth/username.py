"""Le nom d'utilisateur d'xauth : une seconde façon de s'identifier à la connexion, à côté de l'adresse e-mail.

Fichier AUTONOME (aucun import relatif) : les tests le chargent tel quel. Règle : 3 à 32 caractères, minuscules, chiffres, `.`, `_`, `-`, commençant par une
lettre ou un chiffre. Jamais de `@` : c'est ce qui permet à la connexion de savoir, sans ambiguïté, si ce qu'on lui donne est une adresse ou un nom.
La casse ne compte pas (`Alice` = `alice`) : on range et on compare en minuscules.
"""

from __future__ import annotations

import re

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
RULES = "3 à 32 caractères : lettres minuscules, chiffres, « . », « _ » ou « - », en commençant par une lettre ou un chiffre."


def normalize_username(raw: str) -> str:
    """Le nom tel qu'on le range (minuscules, sans espaces autour) ; `ValueError` avec la règle si ce n'est pas un nom valide."""
    name = (raw or "").strip().lower()
    if not USERNAME_RE.fullmatch(name):
        raise ValueError(f"Nom d'utilisateur invalide : {RULES}")
    return name


def derive_username(email: str) -> str | None:
    """Un nom proposé depuis une adresse (`jean.dupont@acme.test` -> `jean.dupont`) ; `None` si rien de valide n'en sort."""
    local = (email or "").split("@", 1)[0].strip().lower()
    local = re.sub(r"[^a-z0-9._-]+", "-", local).strip("._-")[:32]
    return local if USERNAME_RE.fullmatch(local) else None


def is_email(identifier: str) -> bool:
    """Ce qui contient `@` est une adresse, le reste un nom d'utilisateur."""
    return "@" in identifier
