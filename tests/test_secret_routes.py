"""Regression tests for the main secret-entry routes.

These pin the *current* behaviour of:
  * ``GET/POST /edit/<id>``
  * ``GET /copy_password/<id>``
  * ``GET /qr_code/<id>``
  * ``GET /`` (search + tag filter)
  * cross-user access denial for view / edit / delete / copy_password / qr_code

They are the safety net for the Phase 1+ security changes (CSRF, session
regeneration, key-wrapping, etc.). If any of these tests start failing after
a security change, the change has altered user-visible behaviour and needs
review.
"""


from pwd_manager.models import SecretEntry
from pwd_manager.utils.crypto import encrypt_data
from tests.conftest import BaseTestCase


class TestSecretRoutes(BaseTestCase):
    # ---- helpers ------------------------------------------------------

    def _make_entry(self, owner=None, title="Test Entry", **kwargs):
        owner = owner or self.user
        defaults = {
            "user_id": owner.id,
            "title": title,
            "has_login_info": True,
            "website": "example.com",
            "username": "user1",
            "encrypted_password": encrypt_data(
                (owner or self.user).encryption_key.encode(), "s3cret-pass"
            ),
            "tags": "work,banking",
        }
        defaults.update(kwargs)
        entry = SecretEntry(**defaults)
        from pwd_manager import db

        db.session.add(entry)
        db.session.commit()
        return entry

    # ---- edit ---------------------------------------------------------

    def test_edit_secret_get_displays_decrypted_values(self):
        self.login()
        entry = self._make_entry(notes=None)
        # notes is None here; create one with notes
        from pwd_manager import db

        entry.notes = encrypt_data(self.key, "my notes")
        db.session.commit()

        response = self.client.get(f"/edit/{entry.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"s3cret-pass", response.data)
        self.assertIn(b"my notes", response.data)

    def test_edit_secret_post_updates_entry(self):
        self.login()
        entry = self._make_entry()

        response = self.client.post(
            f"/edit/{entry.id}",
            data={
                "title": "Updated Title",
                "has_login_info": "1",
                "website": "newsite.com",
                "username": "newuser",
                "password": "new-password",
                "tags": "updated",
                "notes": "updated notes",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        from pwd_manager import db

        db.session.refresh(entry)
        self.assertEqual(entry.title, "Updated Title")
        self.assertEqual(entry.website, "newsite.com")
        self.assertEqual(entry.username, "newuser")
        self.assertEqual(entry.tags, "updated")
        # password is re-encrypted; ciphertext is non-deterministic so we
        # decrypt and compare to the plaintext instead.
        from pwd_manager.utils.crypto import decrypt_data

        self.assertEqual(
            decrypt_data(self.key, entry.encrypted_password), "new-password"
        )
        self.assertEqual(decrypt_data(self.key, entry.notes), "updated notes")

    def test_edit_secret_post_disables_login_info_clears_fields(self):
        self.login()
        entry = self._make_entry()

        response = self.client.post(
            f"/edit/{entry.id}",
            data={"title": "No Login", "has_login_info": "", "tags": "", "notes": ""},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        from pwd_manager import db

        db.session.refresh(entry)
        self.assertFalse(entry.has_login_info)
        self.assertIsNone(entry.website)
        self.assertIsNone(entry.username)
        self.assertIsNone(entry.encrypted_password)

    def test_edit_secret_other_user_denied(self):
        self.login()
        entry = self._make_entry()  # owned by self.user
        self.logout()
        self.login_other()

        response = self.client.get(f"/edit/{entry.id}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"permission", response.data.lower())

        response = self.client.post(
            f"/edit/{entry.id}",
            data={"title": "Hijacked", "has_login_info": "", "tags": "", "notes": ""},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"permission", response.data.lower())
        # title unchanged
        from pwd_manager import db

        db.session.refresh(entry)
        self.assertEqual(entry.title, "Test Entry")

    # ---- copy_password ------------------------------------------------

    def test_copy_password_returns_plaintext(self):
        self.login()
        entry = self._make_entry()
        response = self.client.get(f"/copy_password/{entry.id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["password"], "s3cret-pass")

    def test_copy_password_requires_login(self):
        entry = self._make_entry()
        response = self.client.get(f"/copy_password/{entry.id}")
        self.assertEqual(response.status_code, 401)

    def test_copy_password_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        self.logout()
        self.login_other()
        response = self.client.get(f"/copy_password/{entry.id}")
        self.assertEqual(response.status_code, 403)

    def test_copy_password_no_password_for_entry(self):
        self.login()
        entry = self._make_entry(has_login_info=False, encrypted_password=None)
        response = self.client.get(f"/copy_password/{entry.id}")
        self.assertEqual(response.status_code, 400)

    # ---- qr_code ------------------------------------------------------

    def test_qr_code_returns_base64_png(self):
        self.login()
        entry = self._make_entry()
        response = self.client.get(f"/qr_code/{entry.id}")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("qr_code", data)
        # base64-decodable to a PNG signature
        import base64

        raw = base64.b64decode(data["qr_code"])
        self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_qr_code_requires_login(self):
        entry = self._make_entry()
        response = self.client.get(f"/qr_code/{entry.id}")
        self.assertEqual(response.status_code, 401)

    def test_qr_code_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        self.logout()
        self.login_other()
        response = self.client.get(f"/qr_code/{entry.id}")
        self.assertEqual(response.status_code, 401)

    # ---- view ---------------------------------------------------------

    def test_view_secret_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        self.logout()
        self.login_other()
        response = self.client.get(f"/view/{entry.id}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"unauthorized", response.data.lower())

    # ---- delete -------------------------------------------------------

    def test_delete_secret_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        self.logout()
        self.login_other()
        response = self.client.post(f"/delete/{entry.id}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"unauthorized", response.data.lower())
        from pwd_manager import db

        self.assertIsNotNone(db.session.get(SecretEntry, entry.id))

    # ---- search / filter ----------------------------------------------

    def test_index_search_filters_by_title(self):
        self.login()
        self._make_entry(title="GitHub Credentials")
        self._make_entry(title="Banking Login", tags="banking")
        response = self.client.get("/?search=github")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"GitHub Credentials", response.data)
        self.assertNotIn(b"Banking Login", response.data)

    def test_index_tag_filter(self):
        self.login()
        self._make_entry(title="Personal Note", tags="personal")
        self._make_entry(title="Work Note", tags="work")
        response = self.client.get("/?tag=work")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Work Note", response.data)
        self.assertNotIn(b"Personal Note", response.data)

    def test_index_other_user_entries_not_listed(self):
        # entry owned by other user
        self._make_entry(owner=self.other_user, title="Other User Secret")
        self.login()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Other User Secret", response.data)

    # ---- unauthenticated access --------------------------------------

    def test_index_requires_login(self):
        response = self.client.get("/", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        # redirected to login
        self.assertIn(b"login", response.data.lower())

    def test_add_requires_login(self):
        response = self.client.get("/add", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"login", response.data.lower())
