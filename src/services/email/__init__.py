from __future__ import annotations

from typing import Any

from .base import EmailTransport
from .senders.auth import AuthEmailSender
from .senders.invite import InviteEmailSender
from .senders.password import PasswordEmailSender


class AuthEmailService:
    """
    Façade email de xauth.

    Regroupe les trois senders par domaine :
        .auth     → welcome, oauth_linked
        .invite   → send_invitation
        .password → reset, changed

    Les templates HTML sont définis dans l'extension Xcore (extensions/mail/).
    Pour remplacer un template :
        email_ext.add_template("welcome", "<html>...</html>")
    """

    def __init__(self, email_ext: Any, app_base_url: str, app_name: str) -> None:
        self._ext = email_ext
        self.auth = AuthEmailSender(email_ext, app_base_url, app_name)
        self.invite = InviteEmailSender(email_ext, app_base_url, app_name)
        self.password = PasswordEmailSender(email_ext, app_base_url, app_name)
