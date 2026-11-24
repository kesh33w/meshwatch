"""Single-owner authentication: passkeys (WebAuthn), session cookies and
API tokens (for the future iPhone app / scripts).

First run: when no passkey exists, a one-time setup token is written to
<data>/setup-token.txt and logged; /setup?token=... registers the first
passkey. Further passkeys are added from Settings while logged in.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time

from fastapi import HTTPException, Request
from webauthn import (base64url_to_bytes, generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .crypto import new_token, token_hash

log = logging.getLogger(__name__)
SESSION_COOKIE = "mw_session"
SESSION_DAYS = 30
CHALLENGE_TTL = 300
USER_ID = b"meshwatch-owner"


class Auth:
    def __init__(self, db, env):
        self.db, self.env = db, env
        self.challenges: dict[str, tuple[bytes, float, str]] = {}
        self.setup_token: str | None = None
        self.ensure_setup_token()

    # first-run setup ----------------------------------------------------------
    def has_credentials(self) -> bool:
        return self.db.one("SELECT 1 FROM credentials LIMIT 1") is not None

    def ensure_setup_token(self) -> None:
        path = self.env.data_dir / "setup-token.txt"
        if self.has_credentials():
            self.setup_token = None
            path.unlink(missing_ok=True)
            return
        self.setup_token = os.environ.get("MW_SETUP_TOKEN") or new_token(24)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.setup_token + "\n")
        log.warning("No passkey registered yet. Open %s/setup?token=%s to register one "
                    "(token also in %s)", self.env.origin, self.setup_token, path)

    def check_setup_token(self, token: str | None) -> bool:
        return bool(self.setup_token and token and secrets.compare_digest(token, self.setup_token))

    # challenges -------------------------------------------------------------
    def _put_challenge(self, challenge: bytes, kind: str) -> str:
        now = time.time()
        for k in [k for k, v in self.challenges.items() if v[1] < now]:
            del self.challenges[k]
        cid = new_token(16)
        self.challenges[cid] = (challenge, now + CHALLENGE_TTL, kind)
        return cid

    def _take_challenge(self, cid: str | None, kind: str) -> bytes:
        item = self.challenges.pop(cid or "", None)
        if not item or item[1] < time.time() or item[2] != kind:
            raise HTTPException(400, "Challenge expired, try again")
        return item[0]

    # registration -------------------------------------------------------------
    def registration_options(self) -> tuple[str, str]:
        existing = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["id"]))
                    for r in self.db.q("SELECT id FROM credentials")]
        opts = generate_registration_options(
            rp_id=self.env.rp_id, rp_name="meshwatch", user_id=USER_ID, user_name="owner",
            user_display_name="meshwatch owner", exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED))
        return self._put_challenge(opts.challenge, "reg"), options_to_json(opts)

    def register(self, cid: str, credential: dict, label: str) -> None:
        challenge = self._take_challenge(cid, "reg")
        try:
            v = verify_registration_response(credential=credential, expected_challenge=challenge,
                                             expected_rp_id=self.env.rp_id, expected_origin=self.env.origin,
                                             require_user_verification=True)
        except Exception as exc:  # noqa: BLE001 - library raises several types
            raise HTTPException(400, f"Passkey registration failed: {exc}") from None
        from webauthn.helpers import bytes_to_base64url
        transports = credential.get("response", {}).get("transports") or []
        self.db.x("INSERT INTO credentials(id,public_key,sign_count,label,transports,created) VALUES(?,?,?,?,?,?)",
                  (bytes_to_base64url(v.credential_id), v.credential_public_key, v.sign_count,
                   label[:60] or "passkey", json.dumps(transports), time.time()))
        self.ensure_setup_token()

    # authentication -----------------------------------------------------------
    def authentication_options(self) -> tuple[str, str]:
        opts = generate_authentication_options(rp_id=self.env.rp_id,
                                               user_verification=UserVerificationRequirement.REQUIRED)
        return self._put_challenge(opts.challenge, "auth"), options_to_json(opts)

    def authenticate(self, cid: str, credential: dict) -> None:
        challenge = self._take_challenge(cid, "auth")
        row = self.db.one("SELECT * FROM credentials WHERE id=?", (credential.get("id", ""),))
        if not row:
            raise HTTPException(401, "Unknown passkey")
        try:
            v = verify_authentication_response(credential=credential, expected_challenge=challenge,
                                               expected_rp_id=self.env.rp_id, expected_origin=self.env.origin,
                                               credential_public_key=row["public_key"],
                                               credential_current_sign_count=row["sign_count"],
                                               require_user_verification=True)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(401, f"Passkey check failed: {exc}") from None
        self.db.x("UPDATE credentials SET sign_count=?, last_used=? WHERE id=?",
                  (v.new_sign_count, time.time(), row["id"]))

    # sessions ---------------------------------------------------------------
    def new_session(self, client: str) -> str:
        token = new_token()
        now = time.time()
        self.db.x("DELETE FROM sessions WHERE expires<?", (now,))
        self.db.x("INSERT INTO sessions(token_hash,created,expires,client) VALUES(?,?,?,?)",
                  (token_hash(token), now, now + SESSION_DAYS * 86400, client[:200]))
        return token

    def end_session(self, token: str | None) -> None:
        if token:
            self.db.x("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))

    def new_api_token(self, label: str) -> str:
        token = "mw_" + new_token()
        self.db.x("INSERT INTO api_tokens(token_hash,label,created) VALUES(?,?,?)",
                  (token_hash(token), label[:60] or "token", time.time()))
        return token

    def identify(self, request: Request) -> str | None:
        """'session' | 'token' | None."""
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            h = token_hash(header[7:].strip())
            if self.db.one("SELECT 1 FROM api_tokens WHERE token_hash=?", (h,)):
                self.db.x("UPDATE api_tokens SET last_used=? WHERE token_hash=?", (time.time(), h))
                return "token"
            return None
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie and self.db.one("SELECT 1 FROM sessions WHERE token_hash=? AND expires>?",
                                  (token_hash(cookie), time.time())):
            return "session"
        return None

    def same_origin(self, request: Request) -> bool:
        origin = request.headers.get("origin")
        if origin:
            return origin.rstrip("/") == self.env.origin
        return request.headers.get("sec-fetch-site") in ("same-origin", None) and \
            request.headers.get("referer", "").startswith(self.env.origin + "/")
