"""Minimal feature-flag helpers for the security rollout.

The security fix plan (see ``security-fix-plan.md``) gates each potentially
disruptive change behind a flag so it can be enabled per-environment and
rolled back without a code change. This module provides the read-side; flags
are configured via environment variables, following the same pattern the app
already uses for ``SECRET_KEY`` etc.

Design goals:

* **No new dependencies.** Pure stdlib + ``os.getenv``.
* **Fail-safe defaults.** Every flag defaults to the *current* (pre-hardening)
  behaviour, so importing this module changes nothing on its own.
* **Single source of truth.** Each flag has a constant name and a documented
  default, so the rollout plan and the code can't drift.
* **Testable.** ``override_flag`` lets tests flip a flag without touching
  ``os.environ`` directly.

Usage in app code::

    from pwd_manager.feature_flags import is_enabled

    if is_enabled("ENABLE_KEY_WRAPPING"):
        ...  # new wrapped-DEK login path
    else:
        ...  # legacy plaintext-DEK path

Usage in tests::

    from pwd_manager.feature_flags import override_flag

    with override_flag("ENABLE_KEY_WRAPPING", True):
        ...  # exercise the new path
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

# ---- Flag registry ---------------------------------------------------
# Each entry: (env var name, default value as a string).
# Defaults are deliberately chosen so that *not* setting the flag preserves
# the app's current behaviour. This means a fresh checkout or an existing
# .env file continues to work unchanged after the code lands.

_FLAGS: dict[str, str] = {
    # Phase 1 — fail-closed on weak SECRET_KEY (H1). Default: off (warn only).
    "STRICT_SECRET_KEY": "0",
    # Phase 1 — global CSRF protection (C3). Default: off until every form
    # has been updated and tested.
    "ENABLE_CSRF": "0",
    # Phase 1 — sanitise the markdown filter with bleach (C4). Default: off
    # until the baseline tests in tests/test_markdown.py have been updated.
    "ENABLE_MARKDOWN_SANITIZE": "0",
    # Phase 1 — security headers (M2). Default: off until CSP has been
    # validated against the app's CDN usage.
    "ENABLE_SECURITY_HEADERS": "0",
    # Phase 1 — generic error messages instead of raw exception strings (M1).
    "HIDE_INTERNAL_ERRORS": "0",
    # Phase 2 — key wrapping migration (C1/C2). Default: off.
    "ENABLE_KEY_WRAPPING": "0",
    # Phase 3 — drop the legacy plaintext encryption_key column. Default: off
    # until monitoring shows all users have migrated.
    "DROP_LEGACY_ENCRYPTION_KEY": "0",
}


_TRUE_STRINGS = frozenset({"1", "true", "yes", "on"})
_FALSE_STRINGS = frozenset({"0", "false", "no", "off", ""})


def _coerce(raw: str) -> bool:
    """Coerce a raw env string to bool. Empty/unset => False."""
    if raw is None:
        return False
    val = raw.strip().lower()
    if val in _TRUE_STRINGS:
        return True
    if val in _FALSE_STRINGS:
        return False
    # Unknown value: be conservative and treat as False, but log once.
    # We don't import the app logger here to avoid circular imports.
    import warnings

    warnings.warn(
        f"feature_flags: unrecognized value {raw!r} for a flag; treating as False",
        RuntimeWarning,
        stacklevel=2,
    )
    return False


def is_enabled(flag_name: str) -> bool:
    """Return True if the named feature flag is enabled.

    Reads the value from ``os.environ`` first, falling back to the registered
    default. Unknown flag names raise ``KeyError`` so typos in code are
    caught early instead of silently returning False.
    """
    if flag_name not in _FLAGS:
        raise KeyError(
            f"Unknown feature flag: {flag_name!r}. "
            f"Known flags: {sorted(_FLAGS)}"
        )
    raw = os.environ.get(flag_name, _FLAGS[flag_name])
    return _coerce(raw)


def default_for(flag_name: str) -> bool:
    """Return the registered default for a flag (without consulting env)."""
    if flag_name not in _FLAGS:
        raise KeyError(f"Unknown feature flag: {flag_name!r}")
    return _coerce(_FLAGS[flag_name])


def known_flags() -> dict[str, bool]:
    """Return a snapshot of all flags and their current effective values.

    Useful for a ``/health`` or ``/debug/flags`` endpoint (admin-only) so
    operators can see which rollout phase is active.
    """
    return {name: is_enabled(name) for name in _FLAGS}


@contextmanager
def override_flag(flag_name: str, value: bool) -> Iterator[None]:
    """Temporarily set a flag for the duration of a ``with`` block.

    This sets ``os.environ[flag_name]`` so that ``is_enabled`` sees the
    override, then restores the previous value (or removes it if it wasn't
    set) on exit. Intended for tests; not safe to use in production code
    because it mutates process-global state.
    """
    if flag_name not in _FLAGS:
        raise KeyError(f"Unknown feature flag: {flag_name!r}")
    sentinel = object()
    previous = os.environ.get(flag_name, sentinel)
    os.environ[flag_name] = "1" if value else "0"
    try:
        yield
    finally:
        if previous is sentinel:
            os.environ.pop(flag_name, None)
        else:
            os.environ[flag_name] = previous
