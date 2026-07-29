"""Tests for the ``markdown`` Jinja template filter.

These tests cover both the legacy (unsanitised) and the sanitised behaviour
of the filter defined in ``pwd_manager/__init__.py:register_template_filters``.

The sanitised path is gated behind the ``ENABLE_MARKDOWN_SANITIZE`` feature
flag. When the flag is off (the default), raw HTML passes through unchanged
— this is the original C4 vulnerability, preserved for backward compatibility.
When the flag is on, ``bleach.clean`` strips dangerous tags and attributes
before the output is wrapped in ``Markup(...)``.
"""

import unittest

from pwd_manager import create_app
from pwd_manager.feature_flags import override_flag


class TestMarkdownFilterLegacy(unittest.TestCase):
    """Behaviour when ENABLE_MARKDOWN_SANITIZE is off (the default)."""

    def setUp(self):
        self.app = create_app("testing")
        self.markdown = self.app.jinja_env.filters["markdown"]
        # Force the flag off AFTER create_app (which calls load_dotenv with
        # override=True and would clobber any pre-existing env var). The
        # filter reads the flag at call time, so this works.
        self._flag_ctx = override_flag("ENABLE_MARKDOWN_SANITIZE", False)
        self._flag_ctx.__enter__()

    def tearDown(self):
        self._flag_ctx.__exit__(None, None, None)

    def test_empty_input_returns_empty_string(self):
        self.assertEqual(self.markdown(""), "")
        self.assertEqual(self.markdown(None), "")

    def test_plain_text_wrapped_in_paragraph(self):
        result = self.markdown("hello world")
        self.assertIn("<p>", result)
        self.assertIn("hello world", result)

    def test_bold(self):
        self.assertIn("<strong>bold</strong>", self.markdown("**bold**"))

    def test_italic(self):
        self.assertIn("<em>italic</em>", self.markdown("*italic*"))

    def test_fenced_code_block(self):
        result = self.markdown("```\ncode here\n```")
        self.assertIn("<code>", result)
        self.assertIn("code here", result)

    def test_table_extension(self):
        self.assertIn("<table>", self.markdown("| a | b |\n|---|---|\n| 1 | 2 |"))

    def test_nl2br_extension(self):
        self.assertIn("<br", self.markdown("line1\nline2"))

    def test_link(self):
        self.assertIn(
            '<a href="https://example.com">label</a>',
            self.markdown("[label](https://example.com)"),
        )

    # ---- legacy: dangerous HTML passes through (C4) -----------------

    def test_legacy_passes_through_raw_script_tag(self):
        """C4 legacy: raw <script> is NOT stripped when the flag is off."""
        result = self.markdown("<script>alert(1)</script>")
        self.assertIn("<script>alert(1)</script>", result)

    def test_legacy_passes_through_img_onerror(self):
        """C4 legacy: inline event handlers survive when the flag is off."""
        result = self.markdown('<img src=x onerror="alert(1)">')
        self.assertIn('onerror="alert(1)"', result)

    def test_legacy_passes_through_javascript_link(self):
        """C4 legacy: javascript: URLs survive when the flag is off."""
        result = self.markdown("[click](javascript:alert(1))")
        self.assertIn("javascript:alert(1)", result)

    def test_legacy_passes_through_iframe(self):
        """C4 legacy: <iframe> is NOT stripped when the flag is off."""
        result = self.markdown('<iframe src="https://evil"></iframe>')
        self.assertIn("<iframe", result)


class TestMarkdownFilterSanitised(unittest.TestCase):
    """Behaviour when ENABLE_MARKDOWN_SANITIZE is on (C4 fix)."""

    def setUp(self):
        self.app = create_app("testing")
        self.markdown = self.app.jinja_env.filters["markdown"]
        # Set the flag AFTER create_app (which calls load_dotenv with
        # override=True). The filter reads the flag at call time.
        self._ctx = override_flag("ENABLE_MARKDOWN_SANITIZE", True)
        self._ctx.__enter__()

    def tearDown(self):
        self._ctx.__exit__(None, None, None)

    def test_sanitised_strips_script_tag(self):
        """C4 fix: <script> is stripped when the flag is on.

        Bleach removes the tag but may leave the text content (``alert(1)``)
        as plain text — that's safe because it's no longer inside a
        ``<script>`` element and won't execute.
        """
        result = self.markdown("<script>alert(1)</script>")
        self.assertNotIn("<script", result)
        self.assertNotIn("</script>", result)

    def test_sanitised_strips_img_onerror(self):
        """C4 fix: inline event handlers are stripped when the flag is on."""
        result = self.markdown('<img src=x onerror="alert(1)">')
        self.assertNotIn("onerror", result)
        # <img> is not in the allowlist either, so it's fully stripped
        self.assertNotIn("<img", result)

    def test_sanitised_strips_javascript_link(self):
        """C4 fix: javascript: URLs are blocked when the flag is on."""
        result = self.markdown("[click](javascript:alert(1))")
        self.assertNotIn("javascript:alert(1)", result)

    def test_sanitised_strips_iframe(self):
        """C4 fix: <iframe> is stripped when the flag is on."""
        result = self.markdown('<iframe src="https://evil"></iframe>')
        self.assertNotIn("<iframe", result)

    def test_sanitised_preserves_safe_markdown(self):
        """Safe markdown (bold, code, tables, links) still renders."""
        self.assertIn("<strong>bold</strong>", self.markdown("**bold**"))
        self.assertIn("<table>", self.markdown("| a | b |\n|---|---|\n| 1 | 2 |"))
        result = self.markdown("[label](https://example.com)")
        self.assertIn("https://example.com", result)
        self.assertIn("label", result)

    def test_sanitised_preserves_http_link(self):
        """http/https links are kept by the protocol allowlist."""
        result = self.markdown("[safe](https://example.com)")
        self.assertIn('href="https://example.com"', result)

    def test_sanitised_strips_disallowed_tag_attributes(self):
        """Attributes other than href on <a> are removed."""
        result = self.markdown('<a href="https://x.com" onclick="evil">x</a>')
        self.assertIn('href="https://x.com"', result)
        self.assertNotIn("onclick", result)


if __name__ == "__main__":
    unittest.main()
