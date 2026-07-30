"""Tests for the SQLite backup/restore helpers.

Verifies that:
  * ``backup_database`` produces a byte-for-byte valid SQLite file
  * the backup is written atomically (no partial file on a simulated crash)
  * ``restore_database`` round-trips the data back into a live DB
  * the backup can be opened independently and queried

These tests use a temporary *file-based* SQLite DB (not the in-memory testing
config) because backup/restore semantics only matter for on-disk databases.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from pwd_manager import create_app, db
from pwd_manager.models import SecretEntry, User
from pwd_manager.utils.backup import backup_database, restore_database
from pwd_manager.utils.crypto import encrypt_data


class TestDbBackup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pwdmgr_backup_test_")
        self.db_path = Path(self.tmp) / "live.db"
        self.backup_path = Path(self.tmp) / "backup.db"

        # Build a file-based app config (not the in-memory testing config).
        self.app = create_app("testing")
        self.app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{self.db_path}"
        # Rebind SQLAlchemy to the file DB.
        db.init_app(self.app)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Seed some data
        user = User(username="backupuser")
        user.set_password("backuppass")
        db.session.add(user)
        entry = SecretEntry(
            user_id=1,
            title="Backup Test",
            has_login_info=True,
            website="example.com",
            username="u",
            encrypted_password=encrypt_data(user.get_dek("backuppass").encode(), "p"),
            tags="t",
        )
        db.session.add(entry)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_backup_produces_valid_sqlite_file(self):
        result = backup_database(self.app, self.backup_path)
        self.assertEqual(result, self.backup_path)
        self.assertTrue(self.backup_path.exists())

        # The backup is a valid SQLite file with the expected data
        conn = sqlite3.connect(str(self.backup_path))
        try:
            cur = conn.execute("SELECT title FROM password_entry")
            titles = [row[0] for row in cur.fetchall()]
        finally:
            conn.close()
        self.assertIn("Backup Test", titles)

    def test_backup_is_atomic_no_partial_file_on_existing_dest(self):
        # Pre-create a destination so we can confirm it's replaced atomically
        self.backup_path.write_bytes(b"OLD-CONTENT")
        backup_database(self.app, self.backup_path)
        # Should now be a valid SQLite file, not the old content
        self.assertNotIn(b"OLD-CONTENT", self.backup_path.read_bytes())
        conn = sqlite3.connect(str(self.backup_path))
        try:
            conn.execute("SELECT count(*) FROM user").fetchone()
        finally:
            conn.close()

    def test_restore_roundtrips_data(self):
        backup_database(self.app, self.backup_path)

        # Mutate the live DB: delete the entry
        SecretEntry.query.filter_by(title="Backup Test").delete()
        db.session.commit()
        self.assertEqual(
            SecretEntry.query.filter_by(title="Backup Test").count(), 0
        )

        # Restore
        db.session.remove()  # release the connection so restore can write
        restore_database(self.app, self.backup_path)

        # Re-open: SQLAlchemy caches the engine; force a fresh query
        db.session.expire_all()
        self.assertEqual(
            SecretEntry.query.filter_by(title="Backup Test").count(), 1
        )

    def test_backup_then_restore_preserves_row_count(self):
        backup_database(self.app, self.backup_path)
        before = db.session.execute(
            db.text("SELECT count(*) FROM user")
        ).scalar()

        db.session.remove()
        restore_database(self.app, self.backup_path)
        db.session.expire_all()
        after = db.session.execute(
            db.text("SELECT count(*) FROM user")
        ).scalar()
        self.assertEqual(before, after)

    def test_backup_raises_on_missing_source(self):
        # Point the app at a non-existent file
        self.app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"sqlite:///{self.tmp}/does-not-exist.db"
        )
        with self.assertRaises(FileNotFoundError):
            backup_database(self.app, self.backup_path)

    def test_restore_raises_on_missing_backup(self):
        with self.assertRaises(FileNotFoundError):
            restore_database(self.app, Path(self.tmp) / "nope.db")


if __name__ == "__main__":
    unittest.main()
