"""Shared test infrastructure for the pwd-manager test suite.

This module provides a :class:`BaseTestCase` that the Phase 0 regression
tests build on. It intentionally mirrors the setUp/tearDown pattern already
used by ``tests/test_auth.py``, ``tests/test_routes.py`` and
``tests/test_library.py`` so existing tests remain unaffected, while new
tests get a consistent, lower-boilerplate base.

Nothing here uses autouse fixtures, so existing ``unittest.TestCase`` tests
continue to work unchanged.
"""

import shutil
import tempfile
import unittest

from pwd_manager import create_app, db
from pwd_manager.models import User


class BaseTestCase(unittest.TestCase):
    """Base class for integration tests against the in-memory test app.

    Subclasses get:
      * a fresh in-memory SQLite app/client per test
      * two pre-created users (``self.user``, ``self.other_user``)
      * an isolated temp directory for attachment storage
      * ``self.login()`` / ``self.login_other()`` helpers
      * ``self.key`` — the primary user's encryption key (for direct DB setup)
    """

    USERNAME = "testuser"
    PASSWORD = "testpass123"
    OTHER_USERNAME = "otheruser"
    OTHER_PASSWORD = "otherpass"

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.user = User(username=self.USERNAME)
        self.user.set_password(self.PASSWORD)
        db.session.add(self.user)

        self.other_user = User(username=self.OTHER_USERNAME)
        self.other_user.set_password(self.OTHER_PASSWORD)
        db.session.add(self.other_user)

        db.session.commit()

        # Isolate attachment storage per test so on-disk files don't leak
        # between tests or into the repo.
        self.attachments_dir = tempfile.mkdtemp(prefix="pwdmgr_test_att_")
        self.app.config["ATTACHMENTS_DIR"] = self.attachments_dir
        self.key = self.user.get_dek(self.PASSWORD).encode()
        self.other_key = self.other_user.get_dek(self.OTHER_PASSWORD).encode()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        shutil.rmtree(self.attachments_dir, ignore_errors=True)
        self.app_context.pop()

    # ---- auth helpers -------------------------------------------------

    def login(self, username=None, password=None):
        return self.client.post(
            "/auth/login",
            data={"username": username or self.USERNAME, "password": password or self.PASSWORD},
            follow_redirects=True,
        )

    def login_other(self):
        return self.login(self.OTHER_USERNAME, self.OTHER_PASSWORD)

    def logout(self):
        return self.client.get("/auth/logout", follow_redirects=True)
