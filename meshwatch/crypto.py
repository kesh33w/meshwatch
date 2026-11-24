"""Encryption of stored secrets (repeater passwords, MQTT/ntfy credentials).

The key comes from MW_SECRET_KEY (env, never stored in the database). Losing
it makes stored secrets unreadable; they must then be re-entered.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Box:
    def __init__(self, secret_key: str):
        if len(secret_key) < 32:
            raise ValueError("MW_SECRET_KEY must be at least 32 characters")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"meshwatch",
                   info=b"secrets-v1").derive(secret_key.encode())
        self._f = Fernet(base64.urlsafe_b64encode(key))

    def seal(self, plaintext: str | None) -> str | None:
        if plaintext is None or plaintext == "":
            return None
        return self._f.encrypt(plaintext.encode()).decode()

    def open(self, token: str | None) -> str | None:
        if not token:
            return None
        try:
            return self._f.decrypt(token.encode()).decode()
        except InvalidToken:
            return None


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
