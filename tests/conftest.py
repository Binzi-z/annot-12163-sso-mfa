import pytest

from auth import totp


@pytest.fixture(autouse=True)
def _fresh_replay_cache():
    """Isolate tests from the module-level TOTP replay cache."""
    totp._reset_used_codes()
    yield
    totp._reset_used_codes()
