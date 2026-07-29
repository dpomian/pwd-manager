"""Tests for CSRF protection (C3).

These tests verify that when ``ENABLE_CSRF`` is on, Flask-WTF's
CSRFProtect rejects unsafe requests (POST/PUT/DELETE) that don't carry
a valid CSRF token, while safe requests (GET) and properly tokened
requests succeed.

The existing Phase 0 regression tests run with CSRF disabled (the
default), so they continue to exercise the application's business logic
without token plumbing. This file covers the CSRF behaviour itself.
"""

import unittest

from pwd_manager import create_app, db
from pwd_manager.feature_flags import override_flag


class CSRFTestCase(unittest.TestCase):
    """Base class that boots the app with ENABLE_CSRF=1."""

    def setUp(self):
        self._flag_ctx = override_flag("ENABLE_CSRF", True)
        self._flag_ctx.__enter__()
        self.app = create_app("testing")
        # Force CSRF on even in testing config (create_app disables it for
        # config_name == "testing").
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self._flag_ctx.__exit__(None, None, None)

    def _get_csrf_token(self, path="/auth/login"):
        """GET a page with a form, extract the csrf_token from the HTML."""
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode()
        # The token is rendered as: value="TOKEN_HERE"
        import re

        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        self.assertIsNotNone(match, "CSRF token not found in form HTML")
        return match.group(1)


class TestCSRFProtection(CSRFTestCase):
    def test_get_requests_succeed_without_token(self):
        """Safe methods (GET) must work without a CSRF token."""
        resp = self.client.get("/auth/login")
        self.assertEqual(resp.status_code, 200)

    def test_post_without_token_is_rejected(self):
        """POST without a csrf_token field must be rejected (400)."""
        resp = self.client.post(
            "/auth/login",
            data={"username": "x", "password": "y"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_post_with_valid_token_succeeds(self):
        """POST with a valid csrf_token from the form must succeed."""
        token = self._get_csrf_token("/auth/login")
        resp = self.client.post(
            "/auth/login",
            data={
                "username": "x",
                "password": "y",
                "csrf_token": token,
            },
        )
        # Invalid credentials → 200 with error flash (not 400 CSRF reject)
        self.assertEqual(resp.status_code, 200)

    def test_post_with_wrong_token_is_rejected(self):
        """POST with a bogus csrf_token must be rejected (400)."""
        resp = self.client.post(
            "/auth/login",
            data={
                "username": "x",
                "password": "y",
                "csrf_token": "bogus-token",
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_json_post_without_header_is_rejected(self):
        """JSON POST without X-CSRFToken header must be rejected."""
        resp = self.client.post(
            "/auth/login",
            json={"username": "x", "password": "y"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_json_post_with_valid_header_succeeds(self):
        """JSON POST with a valid X-CSRFToken header must pass CSRF."""
        token = self._get_csrf_token("/auth/login")
        resp = self.client.post(
            "/auth/login",
            json={"username": "x", "password": "y"},
            headers={"X-CSRFToken": token},
        )
        # Invalid credentials → 200 with error flash (not 400 CSRF reject)
        self.assertEqual(resp.status_code, 200)


class TestCSRFDisabled(unittest.TestCase):
    """When ENABLE_CSRF is off, no CSRF checks happen (legacy behaviour)."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_post_without_token_succeeds_when_disabled(self):
        """POST without csrf_token must work when CSRF is disabled."""
        resp = self.client.post(
            "/auth/login",
            data={"username": "x", "password": "y"},
        )
        # 200 = form re-rendered with error flash (not 400 CSRF reject)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
