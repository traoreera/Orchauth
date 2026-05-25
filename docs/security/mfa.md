# MFA — Authentification à deux facteurs

XAuth implémente le MFA via TOTP (Time-based One-Time Password, RFC 6238), compatible avec Google Authenticator, Authy, et tout client TOTP standard.

---

## Activation du MFA

### Étape 1 — Setup

```
POST /xauth/mfa/setup
Authorization: Bearer <access_token>

→ {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_uri": "otpauth://totp/MonApp:user@example.com?secret=...&issuer=MonApp",
    "backup_codes": ["A1B2C3D4E5", "F6G7H8I9J0", ...]
  }
```

Le secret TOTP et les 8 codes de secours sont générés mais le MFA n'est pas encore actif. Les codes de secours sont retournés **une seule fois** — l'utilisateur doit les conserver en lieu sûr.

En base, les codes de secours sont stockés sous forme de hashes SHA-256, jamais en clair.

### Étape 2 — Enable

```
POST /xauth/mfa/enable
Authorization: Bearer <access_token>
{ "code": "123456" }

→ 200 OK  (mfa_enabled = true)
```

Valide le premier code TOTP pour confirmer que l'utilisateur a bien scanné le QR code. Active le MFA sur le compte.

---

## Login avec MFA activé

Le login se fait en deux appels :

```
# Appel 1 — Credentials
POST /xauth/auth/login
{ "email": "user@example.com", "password": "..." }

→ {
    "access_token": "",
    "refresh_token": "abc...",
    "mfa_required": true
  }

# Appel 2 — Code TOTP
POST /xauth/auth/verify-mfa
{ "refresh_token": "abc...", "code": "123456" }

→ {
    "access_token": "eyJ...",
    "refresh_token": "xyz...",
    "mfa_required": false
  }
```

Tant que l'étape 2 n'est pas complétée, l'`access_token` de l'étape 1 est vide — il ne permet aucun accès aux ressources.

---

## Codes de secours

Lors du setup, 8 codes de secours hexadécimaux (10 caractères) sont générés. Ils peuvent être utilisés à la place d'un code TOTP si l'utilisateur perd l'accès à son application d'authentification.

- Chaque code est à **usage unique** — il est supprimé de la liste après utilisation
- Stockés sous forme de hashes SHA-256 (pas de récupération possible du code original)
- Régénérables via `POST /xauth/mfa/backup-codes/regenerate`

```
POST /xauth/mfa/backup-codes/regenerate
Authorization: Bearer <access_token>

→ { "backup_codes": ["X1Y2Z3A4B5", ...] }
```

---

## Désactivation

```
DELETE /xauth/mfa
Authorization: Bearer <access_token>

→ 204 No Content
```

Supprime le secret TOTP et les codes de secours. Le MFA est désactivé sur le compte.

---

## Implémentation technique

- Librairie : `pyotp`
- Algorithme : TOTP-SHA1, fenêtre de 30 secondes, tolérance d'1 pas (±30 s)
- Codes de secours : `secrets.token_hex(5).upper()` (10 caractères hex)
- Stockage : `user.mfa_backup_codes` — JSON list de hashes SHA-256

```python
# Vérification — MFAService.verify_totp()
# 1. Vérifie le code TOTP standard
totp = pyotp.TOTP(user.mfa_secret)
if totp.verify(code):
    return True

# 2. Sinon essaie les codes de secours
code_hash = hashlib.sha256(code.upper().encode()).hexdigest()
if code_hash in backup_codes:
    backup_codes.remove(code_hash)  # usage unique
    user.mfa_backup_codes = json.dumps(backup_codes)
    return True
```
