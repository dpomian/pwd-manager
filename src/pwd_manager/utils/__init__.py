"""Shared utility helpers for pwd_manager."""

import logging

from pwd_manager.feature_flags import is_enabled

logger = logging.getLogger(__name__)


def escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters (``%`` and ``_``) in user input.

    Used before interpolating user-supplied search/filter strings into
    ``ilike(f"%{value}%")`` queries so that a search for ``%`` doesn't match
    every row and ``_`` doesn't act as a single-char wildcard.

    The backslash itself is also escaped so the escape character is literal.
    The matching ``ilike`` call must pass ``escape="\\\\"`` (a literal
    backslash in the SQL string).
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def safe_error_message(detail: str, generic: str = "Internal error") -> str:
    """Return a user-facing error message that hides internal details.

    When ``HIDE_INTERNAL_ERRORS`` is enabled (the secure default for
    production), only the generic message is returned to the client and the
    full detail is logged server-side. When the flag is off (the legacy
    behaviour), the detail is returned verbatim so existing tests that
    assert on exception strings continue to pass.

    Args:
        detail: The full exception/error string (logged server-side).
        generic: The message to return to the client when hiding is on.

    Returns:
        Either ``generic`` (flag on) or ``detail`` (flag off).
    """
    if is_enabled("HIDE_INTERNAL_ERRORS"):
        # logger.exception() captures the active exception's traceback
        # automatically. This function is always called from within an
        # ``except`` block, so there is always an active exception.
        logger.exception("Internal error detail: %s", detail)
        return generic
    return detail
