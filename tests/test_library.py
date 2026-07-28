import base64
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from pwd_manager import create_app, db
from pwd_manager.models import Document, DocumentAttachment, User
from pwd_manager.utils.crypto import decrypt_data


class TestLibrary(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.user = User(username="libuser")
        self.user.set_password("libpass")
        db.session.add(self.user)

        self.other_user = User(username="otheruser")
        self.other_user.set_password("otherpass")
        db.session.add(self.other_user)

        db.session.commit()

        self.attachments_dir = tempfile.mkdtemp()
        self.app.config["ATTACHMENTS_DIR"] = self.attachments_dir
        self.key = self.user.encryption_key.encode()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        shutil.rmtree(self.attachments_dir)
        self.app_context.pop()

    def login(self, username="libuser", password="libpass"):
        return self.client.post(
            "/auth/login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )

    def _upload_test_file(self, document_id, filename="test.txt", content=b"hello"):
        return self.client.post(
            f"/library/attachment/upload/{document_id}",
            data={"file": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
        )

    def test_add_creates_draft(self):
        """GET /library/add should create a draft document"""
        self.login()
        count_before = Document.query.count()
        response = self.client.get("/library/add")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Document.query.count(), count_before + 1)
        draft = Document.query.order_by(Document.id.desc()).first()
        self.assertTrue(draft.is_draft)
        self.assertEqual(draft.user_id, self.user.id)

    def test_add_document(self):
        """POST /library/add should save a draft document with encrypted content"""
        self.login()
        self.client.get("/library/add")
        draft = Document.query.order_by(Document.id.desc()).first()

        response = self.client.post(
            "/library/add",
            data={
                "document_id": draft.id,
                "title": "My Document",
                "content": "Some **bold** content",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        document = Document.query.get(draft.id)
        self.assertFalse(document.is_draft)
        self.assertEqual(document.title, "My Document")
        self.assertEqual(
            decrypt_data(self.key, document.encrypted_content),
            "Some **bold** content",
        )
        self.assertIn(b"<strong>bold</strong>", response.data)

    def test_add_document_saves_existing_attachments(self):
        """Attachments uploaded to the draft before save should remain attached"""
        self.login()
        self.client.get("/library/add")
        draft = Document.query.order_by(Document.id.desc()).first()

        upload_response = self._upload_test_file(draft.id)
        self.assertEqual(upload_response.status_code, 200)
        self.assertTrue(upload_response.get_json()["success"])

        self.client.post(
            "/library/add",
            data={
                "document_id": draft.id,
                "title": "Doc with Attachment",
                "content": "",
            },
            follow_redirects=True,
        )

        document = Document.query.get(draft.id)
        self.assertFalse(document.is_draft)
        list_response = self.client.get(f"/library/attachment/list/{document.id}")
        self.assertEqual(len(list_response.get_json()["attachments"]), 1)

    def test_add_validation_preserves_draft(self):
        """Missing title should not discard an already-uploaded attachment"""
        self.login()
        self.client.get("/library/add")
        draft = Document.query.order_by(Document.id.desc()).first()

        self._upload_test_file(draft.id)
        response = self.client.post(
            "/library/add",
            data={"document_id": draft.id, "title": "", "content": "content"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Title is required", response.data)
        self.assertIsNotNone(Document.query.get(draft.id))
        self.assertEqual(
            len(DocumentAttachment.query.filter_by(document_id=draft.id).all()), 1
        )

    def test_view_document_unauthorized(self):
        """Users should not be able to view another user's document"""
        document = Document(
            user_id=self.user.id,
            title="Secret",
            encrypted_content=None,
            is_draft=False,
        )
        db.session.add(document)
        db.session.commit()

        self.login("otheruser", "otherpass")
        response = self.client.get(f"/library/{document.id}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Unauthorized", response.data)

    def test_edit_document(self):
        """Documents should be editable and content re-encrypted"""
        document = Document(
            user_id=self.user.id,
            title="Old",
            encrypted_content=None,
            is_draft=False,
        )
        db.session.add(document)
        db.session.commit()

        self.login()
        response = self.client.post(
            f"/library/edit/{document.id}",
            data={"title": "New", "content": "updated content"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        db.session.refresh(document)
        self.assertEqual(document.title, "New")
        self.assertEqual(
            decrypt_data(self.key, document.encrypted_content),
            "updated content",
        )

    def test_delete_document(self):
        """Documents and their on-disk attachments should be deletable"""
        document = Document(
            user_id=self.user.id,
            title="To Delete",
            encrypted_content=None,
            is_draft=False,
        )
        db.session.add(document)
        db.session.commit()

        self.login()
        upload_response = self._upload_test_file(document.id)
        attachment_id = upload_response.get_json()["attachment"]["id"]

        response = self.client.post(
            f"/library/delete/{document.id}", follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(Document.query.get(document.id))
        self.assertIsNone(DocumentAttachment.query.get(attachment_id))
        self.assertEqual(list(Path(self.attachments_dir).iterdir()), [])

    def test_cancel_document(self):
        """Cancel should delete the draft and any uploaded attachments"""
        self.login()
        self.client.get("/library/add")
        draft = Document.query.order_by(Document.id.desc()).first()

        self._upload_test_file(draft.id)
        response = self.client.get(f"/library/cancel/{draft.id}", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(Document.query.get(draft.id))
        self.assertEqual(list(Path(self.attachments_dir).iterdir()), [])

    def test_attachment_lifecycle(self):
        """Upload, list, download, preview, and delete attachments"""
        document = Document(
            user_id=self.user.id,
            title="With Attachments",
            encrypted_content=None,
            is_draft=False,
        )
        db.session.add(document)
        db.session.commit()

        self.login()
        upload_response = self._upload_test_file(
            document.id, filename="hello.txt", content=b"hello world"
        )
        self.assertEqual(upload_response.status_code, 200)
        upload_data = upload_response.get_json()
        self.assertTrue(upload_data["success"])
        attachment_id = upload_data["attachment"]["id"]

        list_response = self.client.get(f"/library/attachment/list/{document.id}")
        self.assertEqual(len(list_response.get_json()["attachments"]), 1)

        download_response = self.client.get(
            f"/library/attachment/download/{attachment_id}"
        )
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.data, b"hello world")

        preview_response = self.client.get(
            f"/library/attachment/preview/{attachment_id}"
        )
        self.assertEqual(preview_response.status_code, 200)
        preview_data = preview_response.get_json()
        self.assertTrue(preview_data["success"])
        self.assertEqual(
            base64.b64decode(preview_data["content"]).decode(), "hello world"
        )

        delete_response = self.client.post(
            f"/library/attachment/delete/{attachment_id}"
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertTrue(delete_response.get_json()["success"])
        self.assertIsNone(DocumentAttachment.query.get(attachment_id))


if __name__ == "__main__":
    unittest.main()
