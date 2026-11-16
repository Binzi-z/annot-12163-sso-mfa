"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


# Codes already accepted, mapped to the last counter step at which they are
# still inside the verification window. A code in this map is a replay.
_used_codes: dict[tuple[bytes, str], int] = {}


def _reset_used_codes() -> None:
    """Clear the replay cache (test isolation hook)."""
    _used_codes.clear()


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one.

    A code that was already accepted once is rejected as a replay.
    """
    now = int((at or time.time()) // step)
    # prune entries that have fallen out of the acceptance window
    for key, last_valid in list(_used_codes.items()):
        if last_valid < now - 1:
            del _used_codes[key]
    for counter in (now - 1, now):
        if hmac.compare_digest(hotp(secret, counter), code):
            key = (secret, code)
            if key in _used_codes:
                return False  # same code presented again: replay
            _used_codes[key] = counter
            return True
    return False
