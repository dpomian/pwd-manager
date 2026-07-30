"""Regression tests for the secret-entry attachment routes.

Covers the full lifecycle that ``tests/test_library.py`` already covers for
*library* attachments, but for the secret-entry attachment endpoints which
were previously untested:

  * ``POST /attachment/upload/<entry_id>``
  * ``POST /attachment/upload-clipboard/<entry_id>``
  * ``GET  /attachment/list/<entry_id>``
  * ``GET  /attachment/download/<attachment_id>``
  * ``GET  /attachment/preview/<attachment_id>``
  * ``POST /attachment/delete/<attachment_id>``

Plus auth/ownership checks and the file-type / size limits.
"""

import base64
import io
from pathlib import Path

from conftest import BaseTestCase

from pwd_manager import db
from pwd_manager.models import Attachment, SecretEntry
from pwd_manager.utils.crypto import decrypt_binary


class TestSecretAttachments(BaseTestCase):
    # ---- helpers ------------------------------------------------------

    def _make_entry(self, owner=None, title="With Attachments"):
        owner = owner or self.user
        entry = SecretEntry(
            user_id=owner.id,
            title=title,
            has_login_info=False,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def _upload(self, entry_id, filename="test.txt", content=b"hello world"):
        return self.client.post(
            f"/attachment/upload/{entry_id}",
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    # ---- upload / list / download / preview / delete -----------------

    def test_upload_then_list_download_preview_delete(self):
        self.login()
        entry = self._make_entry()

        upload = self._upload(entry.id, filename="hello.txt", content=b"hello world")
        self.assertEqual(upload.status_code, 200)
        body = upload.get_json()
        self.assertTrue(body["success"])
        attachment_id = body["attachment"]["id"]
        self.assertEqual(body["attachment"]["filename"], "hello.txt")
        self.assertEqual(body["attachment"]["size"], len(b"hello world"))

        # stored on disk as <uuid>.enc
        files = list(Path(self.attachments_dir).iterdir())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].name.endswith(".enc"))

        # list
        listed = self.client.get(f"/attachment/list/{entry.id}").get_json()
        self.assertEqual(len(listed["attachments"]), 1)
        self.assertEqual(listed["attachments"][0]["filename"], "hello.txt")

        # download returns original bytes
        dl = self.client.get(f"/attachment/download/{attachment_id}")
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.data, b"hello world")

        # preview returns base64 JSON for text
        prev = self.client.get(f"/attachment/preview/{attachment_id}")
        self.assertEqual(prev.status_code, 200)
        prev_data = prev.get_json()
        self.assertTrue(prev_data["success"])
        self.assertEqual(
            base64.b64decode(prev_data["content"]).decode(), "hello world"
        )

        # delete
        dele = self.client.post(f"/attachment/delete/{attachment_id}")
        self.assertEqual(dele.status_code, 200)
        self.assertTrue(dele.get_json()["success"])
        self.assertIsNone(db.session.get(Attachment, attachment_id))
        self.assertEqual(list(Path(self.attachments_dir).iterdir()), [])

    def test_preview_pdf_served_inline(self):
        self.login()
        entry = self._make_entry()
        # minimal valid PDF bytes
        pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]>>endobj\nxref\n0 4\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF"
        upload = self._upload(entry.id, filename="doc.pdf", content=pdf)
        attachment_id = upload.get_json()["attachment"]["id"]

        prev = self.client.get(f"/attachment/preview/{attachment_id}")
        self.assertEqual(prev.status_code, 200)
        # PDFs are served as the raw file (not JSON)
        self.assertEqual(prev.mimetype, "application/pdf")
        self.assertEqual(prev.data, pdf)

    # ---- clipboard upload --------------------------------------------

    def test_upload_clipboard_image_png(self):
        self.login()
        entry = self._make_entry()
        # 1x1 transparent PNG
        png = bytes.fromhex(
            "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
            "890000000d49444154789c6300010000000500010d0a2db4000000004945"
            "4e44ae426082"
        )
        data_url = "data:image/png;base64," + base64.b64encode(png).decode()

        resp = self.client.post(
            f"/attachment/upload-clipboard/{entry.id}",
            json={"image_data": data_url, "filename": "clip.png"},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["attachment"]["mime_type"], "image/png")

        # download round-trips the original bytes
        attachment_id = body["attachment"]["id"]
        dl = self.client.get(f"/attachment/download/{attachment_id}")
        self.assertEqual(dl.data, png)

    def test_upload_clipboard_invalid_base64_rejected(self):
        self.login()
        entry = self._make_entry()
        resp = self.client.post(
            f"/attachment/upload-clipboard/{entry.id}",
            json={"image_data": "data:image/png;base64,@@@not-base64@@@"},
        )
        self.assertEqual(resp.status_code, 400)

    # ---- file-type / size limits -------------------------------------

    def test_upload_rejects_disallowed_extension(self):
        self.login()
        entry = self._make_entry()
        resp = self._upload(entry.id, filename="evil.exe", content=b"MZ")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("not allowed", resp.get_json()["error"])

    def test_upload_rejects_oversized_file(self):
        """Oversized multipart uploads now return 413 with a JSON body,
        thanks to the dedicated error handler added in Phase 1 (previously
        the catch-all Exception handler masked this as a 500).
        """
        self.login()
        entry = self._make_entry()
        too_big = b"x" * (Attachment.MAX_FILE_SIZE + 1)
        resp = self._upload(entry.id, filename="big.txt", content=too_big)
        self.assertEqual(resp.status_code, 413)
        self.assertIn("too large", resp.get_json()["error"].lower())

    def test_upload_rejects_empty_filename(self):
        self.login()
        entry = self._make_entry()
        resp = self.client.post(
            f"/attachment/upload/{entry.id}",
            data={"file": (io.BytesIO(b"x"), "")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)

    def test_upload_rejects_missing_file_field(self):
        self.login()
        entry = self._make_entry()
        resp = self.client.post(f"/attachment/upload/{entry.id}", data={})
        self.assertEqual(resp.status_code, 400)

    # ---- auth / ownership --------------------------------------------

    def test_upload_requires_login(self):
        entry = self._make_entry()
        resp = self._upload(entry.id)
        self.assertEqual(resp.status_code, 401)

    def test_upload_other_user_denied(self):
        self.login()
        entry = self._make_entry()  # owned by self.user
        self.logout()
        self.login_other()
        resp = self._upload(entry.id)
        self.assertEqual(resp.status_code, 403)

    def test_download_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        upload = self._upload(entry.id)
        attachment_id = upload.get_json()["attachment"]["id"]
        self.logout()
        self.login_other()
        resp = self.client.get(f"/attachment/download/{attachment_id}")
        self.assertEqual(resp.status_code, 403)

    def test_preview_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        upload = self._upload(entry.id)
        attachment_id = upload.get_json()["attachment"]["id"]
        self.logout()
        self.login_other()
        resp = self.client.get(f"/attachment/preview/{attachment_id}")
        self.assertEqual(resp.status_code, 403)

    def test_delete_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        upload = self._upload(entry.id)
        attachment_id = upload.get_json()["attachment"]["id"]
        self.logout()
        self.login_other()
        resp = self.client.post(f"/attachment/delete/{attachment_id}")
        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(Attachment, attachment_id))

    def test_list_other_user_denied(self):
        self.login()
        entry = self._make_entry()
        self._upload(entry.id)
        self.logout()
        self.login_other()
        resp = self.client.get(f"/attachment/list/{entry.id}")
        self.assertEqual(resp.status_code, 403)

    # ---- on-disk encryption ------------------------------------------

    def test_attachment_is_encrypted_at_rest(self):
        """The bytes written to disk must NOT be the plaintext upload."""
        self.login()
        entry = self._make_entry()
        plaintext = b"super-secret-attachment-content"
        self._upload(entry.id, filename="secret.txt", content=plaintext)

        stored = next(Path(self.attachments_dir).iterdir()).read_bytes()
        self.assertNotIn(plaintext, stored)
        # and must round-trip via the user's key
        decrypted = decrypt_binary(self.key, stored)
        self.assertEqual(decrypted, plaintext)
