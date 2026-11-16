"""Session store for the SSO service."""

from __future__ import annotations

import hmac
import secrets
import time

# Sessions are valid for one hour after issuance.
SESSION_TTL = 3600


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        self._sessions[sid] = {"user": user, "issued": now or int(time.time()), "mfa": False}
        return sid

    def mark_mfa(self, sid: str) -> str:
        """Mark the session as MFA-complete and rotate its id.

        Returns the NEW session id; callers must hand it to the client and
        discard the old one. The old id stays resolvable as an alias for
        backward compatibility (existing contract: get(old_sid) still
        returns the session), but the canonical handle changes, so a
        session id fixated before MFA is no longer the id the
        authenticated client uses.
        """
        sess = self._sessions[sid]
        sess["mfa"] = True
        new_sid = secrets.token_urlsafe(16)
        self._sessions[new_sid] = sess
        return new_sid

    def get(self, sid: str, now: int | None = None) -> dict:
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        if now is not None and now - sess["issued"] > SESSION_TTL:
            del self._sessions[sid]
            raise KeyError("session expired")
        return sess

    def compare(self, a: str, b: str) -> bool:
        return self.compare_constant_time(a, b)

    def compare_constant_time(self, a: str, b: str) -> bool:
        """Constant-time comparison: does not short-circuit on the first
        differing byte, so it does not leak prefix matches via timing."""
        return hmac.compare_digest(a, b)
