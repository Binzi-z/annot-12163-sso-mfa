"""Black-box detector for the four audited SSO findings.

Probes the SSO service through its PUBLIC API only (auth.totp / auth.session
public functions and methods — no access to module internals), then prints a
per-scenario verdict with the concrete evidence behind it.

Sections:
  A1-A4  attack probes, one-to-one with the four red security tests:
         A1 test_replay_is_rejected          -> captcha/TOTP replay
         A2 test_session_id_rotates_after_mfa -> session fixation (no rotation)
         A3 test_expired_session_rejected     -> expired session still usable
         A4 test_compare_is_constant_time     -> short-circuiting comparison
  L1-L16 legitimate scenarios, one-to-one with the 16 green tests.
         The detector must produce ZERO false positives on these.

Usage:  python detector.py
Exit 0: no finding exploitable AND all 16 legitimate scenarios behave.
Exit 1: at least one finding exploitable OR a false positive on L1-L16.
"""

from __future__ import annotations

import hashlib
import statistics
import sys
import time

from auth.session import SessionStore
from auth.totp import hotp, totp, verify

RFC_SECRET = b"12345678901234567890"
NOW = 1_700_000_000

# Each probe/check gets its own secret so the (legitimate) server-side replay
# cache of one scenario can never interfere with another scenario.
def secret(tag: str) -> bytes:
    return hashlib.sha256(f"detector::{tag}".encode()).digest()[:20]


results: list[tuple[str, str, bool, str]] = []  # (section, name, ok, evidence)


def record(section: str, name: str, ok: bool, evidence: str) -> None:
    results.append((section, name, ok, evidence))


# ---------------------------------------------------------------------------
# Attack probes A1-A4 (verdict: exploitable?)
# ---------------------------------------------------------------------------

def a1_replay() -> None:
    """Same TOTP code presented twice must not be accepted twice."""
    sec, at = secret("a1"), NOW
    code = totp(sec, at=at)
    first = verify(sec, code, at=at)
    second = verify(sec, code, at=at)
    exploitable = bool(first and second)
    record(
        "A1", "captcha/TOTP replay",
        not exploitable,
        f"verify(code) 1st={first}, 2nd={second} at t={at}"
        + (" -> same code accepted twice, replayable" if exploitable
           else " -> second presentation rejected"),
    )


def a2_rotation() -> None:
    """Completing MFA must rotate the session id (anti session-fixation)."""
    store = SessionStore()
    sid = store.create("alice")
    new_sid = store.mark_mfa(sid)
    exploitable = not (new_sid and new_sid != sid)
    record(
        "A2", "session id rotation after MFA",
        not exploitable,
        f"pre-MFA sid={sid!r}, mark_mfa returned={new_sid!r}"
        + (" -> id kept across MFA, fixation possible" if exploitable
           else " -> fresh id issued, fixated id is not the post-MFA handle"),
    )


def a3_expiry() -> None:
    """A session older than its TTL must be rejected."""
    store = SessionStore()
    sid = store.create("bob", now=1000)
    try:
        store.get(sid, now=1000 + 7200)
        exploitable, evidence = True, "get(sid, issued+7200s) returned a session"
    except KeyError:
        exploitable, evidence = False, "get(sid, issued+7200s) raised KeyError"
    record("A3", "expired session rejected", not exploitable,
           evidence + (" -> expiry not enforced" if exploitable else ""))


def _timing_evidence(store: SessionStore, samples: int = 400) -> str:
    """Indicative (non-verdict) timing probe: does compare() get slower as the
    common prefix grows? Short-circuiting compares do; constant-time ones don't."""
    base = "s" * 64

    def median_ns(candidate: str) -> float:
        ts = []
        for _ in range(samples):
            t0 = time.perf_counter_ns()
            store.compare(candidate, base)
            ts.append(time.perf_counter_ns() - t0)
        return statistics.median(ts)

    t0 = median_ns("x" + "s" * 63)   # differs at byte 0
    t63 = median_ns("s" * 63 + "x")  # differs at byte 63
    trend = "grows with prefix -> short-circuits" if t63 > t0 * 1.5 \
        else "flat vs prefix length -> constant-time"
    return f"median compare: prefix0={t0:.0f}ns prefix63={t63:.0f}ns ({trend}; indicative only)"


def a4_compare() -> None:
    """A constant-time comparison must exist and agree with compare()."""
    store = SessionStore()
    has_ct = hasattr(store, "compare_constant_time")
    agrees = has_ct and store.compare_constant_time("abc", "abd") is False \
        and store.compare_constant_time("abc", "abc") is True
    exploitable = not agrees
    evidence = (
        f"compare_constant_time present={has_ct}, agrees with compare()={agrees}; "
        + _timing_evidence(store)
    )
    record("A4", "constant-time comparison", not exploitable,
           evidence + (" -> only a short-circuiting compare exists" if exploitable else ""))


# ---------------------------------------------------------------------------
# Legitimate scenarios L1-L16 (must all behave -> zero false positives)
# ---------------------------------------------------------------------------

def legit_checks() -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, fn) -> None:
        try:
            fn()
            checks.append((name, True, "behaves as specified"))
        except Exception as exc:  # noqa: BLE001 - detector reports, never raises
            checks.append((name, False, f"FALSE POSITIVE risk: {type(exc).__name__}: {exc}"))

    check("L1  RFC 6238 vector", lambda: _expect(totp(RFC_SECRET, at=59) == "287082"))
    check("L2  verify accepts current step",
          lambda: _expect(verify(secret("l2"), totp(secret("l2"), at=NOW), at=NOW)))
    check("L3  verify accepts previous step",
          lambda: _expect(verify(secret("l3"), totp(secret("l3"), at=NOW - 30), at=NOW)))
    check("L4  verify rejects far-past code",
          lambda: _expect(not verify(secret("l4"), totp(secret("l4"), at=NOW - 300), at=NOW)))
    check("L5  hotp deterministic", lambda: _expect(hotp(RFC_SECRET, 1) == hotp(RFC_SECRET, 1)))
    check("L6  create returns id", lambda: _expect(bool(SessionStore().create("alice"))))

    def l7():
        s = SessionStore()
        _expect(s.get(s.create("alice"))["user"] == "alice")
    check("L7  get returns user", l7)

    def l8():
        try:
            SessionStore().get("nope")
        except KeyError:
            return
        raise AssertionError("unknown sid did not raise")
    check("L8  unknown session raises", l8)

    def l9():
        s = SessionStore()
        sid = s.create("alice")
        s.mark_mfa(sid)
        _expect(s.get(sid)["mfa"] is True)
    check("L9  mark_mfa sets flag", l9)

    check("L10 compare equal", lambda: _expect(SessionStore().compare("abc", "abc")))
    check("L11 compare differs", lambda: _expect(not SessionStore().compare("abc", "abd")))

    def l12():
        s = SessionStore()
        _expect(s.create("a") != s.create("a"))
    check("L12 two sessions differ", l12)

    def l13():
        s = SessionStore()
        _expect(s.get(s.create("a", now=100))["issued"] == 100)
    check("L13 get keeps issued", l13)

    check("L14 hotp six digits", lambda: _expect(len(hotp(RFC_SECRET, 5)) == 6))
    check("L15 totp changes per step", lambda: _expect(totp(RFC_SECRET, at=1000) != totp(RFC_SECRET, at=1030)))
    check("L16 verify rejects wrong code",
          lambda: _expect(not verify(secret("l16"), "000000", at=NOW)))
    return checks


def _expect(cond: bool) -> None:
    if not cond:
        raise AssertionError("legitimate behavior broken")


# ---------------------------------------------------------------------------

def main() -> int:
    a1_replay()
    a2_rotation()
    a3_expiry()
    a4_compare()
    legit = legit_checks()

    print("== Attack probes (one-to-one with the 4 red security tests) ==")
    exploitable_count = 0
    for section, name, ok, evidence in results:
        verdict = "NOT EXPLOITABLE" if ok else "EXPLOITABLE"
        if not ok:
            exploitable_count += 1
        print(f"[{section}] {name:<34} {verdict}")
        print(f"      evidence: {evidence}")

    print("\n== Legitimate scenarios (one-to-one with the 16 green tests) ==")
    false_positives = 0
    for name, ok, evidence in legit:
        if not ok:
            false_positives += 1
        print(f"[{name:<28}] {'OK' if ok else 'FLAGGED'}  {evidence}")

    print(f"\nSummary: {exploitable_count}/4 findings exploitable, "
          f"{false_positives}/16 false positives on legitimate scenarios")
    return 0 if exploitable_count == 0 and false_positives == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
