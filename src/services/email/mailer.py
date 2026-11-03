"""Repli d'e-mail d'xauth : `LogMailer`, quand l'hôte ne fournit pas l'extension `ext.email` (`extensions/xmailler`, configurée dans `integration.yaml`).

xauth envoie des e-mails (invitation, réinitialisation et changement de mot de passe, bienvenue) par `ext.email`. Un hôte qui ne la déclare pas ne doit pas empêcher xauth
de démarrer : on JOURNALISE alors le message (destinataire, objet, texte et liens), jamais envoyé : c'est ce qu'on veut en développement. Même contrat que l'extension
(`send`, `queue`, `status`).
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("xcore.auth.mail")

_TAGS = re.compile(r"<[^>]+>")
_LINK = re.compile(r'href="([^"]+)"')


def _text_of(html: str) -> str:
    """Le texte d'un e-mail HTML, avec ses liens écrits en toutes lettres (un journal ne peut pas cliquer)."""
    links = _LINK.findall(html)
    plain = re.sub(r"\s+", " ", _TAGS.sub(" ", html)).strip()
    return plain + ("".join(f"\n  lien : {u}" for u in dict.fromkeys(links)))


class LogMailer:
    """Journalise au lieu d'envoyer (développement)."""

    simulated = True

    def status(self) -> dict[str, Any]:
        return {"name": "log", "status": "degraded", "configured": False, "simulated": True, "smtp_host": "", "smtp_port": 0, "from": "", "sent": 0, "failed": 0, "queued": 0}

    async def send(self, to: str, subject: str, body: str, is_html: bool = True) -> bool:
        logger.warning("e-mail NON ENVOYÉ (aucun SMTP configuré)\n  à : %s\n  objet : %s\n  %s", to, subject, _text_of(body) if is_html else body)
        return True

    def queue(self, to: str, subject: str, body: str, is_html: bool = True) -> bool:
        logger.warning("e-mail NON ENVOYÉ (aucun SMTP configuré)\n  à : %s\n  objet : %s\n  %s", to, subject, _text_of(body) if is_html else body)
        return True
