"""SQLite online backup / restore helpers.

These use the SQLite online backup API (``sqlite3.Connection.backup``) so the
running app can be backed up without being taken offline and without risking
a torn read of a partial write. This is the safe replacement for naively
copying the DB file while the app is writing to it.

Usage (e.g. from a management script or a cron job)::

    from pwd_manager import create_app
    from pwd_manager.utils.backup import backup_database

    app = create_app()
    backup_database(app, "/var/backups/pwd_manager-2026-07-29.db")

The helpers are intentionally framework-light: they read
``app.config["SQLALCHEMY_DATABASE_URI"]`` to find the source file, so they
work regardless of how the app was configured. They raise ``ValueError`` for
non-SQLite URIs (the only DB type the app currently supports) and
``FileNotFoundError`` if the source DB file does not yet exist.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path


def _sqlite_path_from_uri(uri: str) -> Path | None:
    """Extract the on-disk path from a ``sqlite:///path`` URI.

    Returns ``None`` for in-memory databases (``sqlite:///:memory:``), for
    which backup/restore to a file is still possible but the "source file
    does not exist" checks do not apply.
    """
    if not uri.startswith("sqlite:///"):
        return None
    path = uri[len("sqlite:///") :]
    if path == ":memory:":
        return None
    return Path(path)


def backup_database(app, dest_path: str | os.PathLike) -> Path:
    """Online-copy the app's SQLite database to ``dest_path``.

    Uses the SQLite backup API, which is safe to run while the app is serving
    requests. The destination is written atomically (to a temp file in the
    same directory, then renamed) so a crash mid-backup never leaves a
    half-written file at ``dest_path``.

    Args:
        app: A Flask app with ``SQLALCHEMY_DATABASE_URI`` configured.
        dest_path: Where to write the backup file. Parent directory must
            exist and be writable.

    Returns:
        The ``Path`` to the written backup.

    Raises:
        ValueError: If the configured DB is not SQLite.
        FileNotFoundError: If the source DB file does not exist.
    """
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    src = _sqlite_path_from_uri(uri)
    if src is None and not uri.startswith("sqlite:///"):
        raise ValueError(f"backup_database only supports SQLite, got URI: {uri}")
    if src is not None and not src.exists():
        raise FileNotFoundError(f"Source database not found: {src}")

    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file in the same directory so the final rename is atomic
    # on POSIX. This prevents a partial backup from appearing at dest_path.
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".backup-", suffix=".tmp", dir=str(dest.parent)
    )
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    try:
        source_conn = sqlite3.connect(str(src) if src is not None else ":memory:")
        try:
            dest_conn = sqlite3.connect(str(tmp_path))
            try:
                source_conn.backup(dest_conn)
            finally:
                dest_conn.close()
        finally:
            source_conn.close()

        # Atomic on POSIX; on Windows os.replace handles the replace atomically.
        os.replace(tmp_path, dest)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return dest


def restore_database(app, backup_path: str | os.PathLike) -> None:
    """Restore the app's SQLite database from ``backup_path``.

    Copies the backup file back over the live DB using the SQLite backup API
    (in the reverse direction). The app should ideally be quiesced (no
    in-flight writes) before calling this; the backup API itself is safe,
    but a restore changes every row and concurrent writers will see
    inconsistent state.

    Args:
        app: A Flask app with ``SQLALCHEMY_DATABASE_URI`` configured.
        backup_path: Path to a previously-produced backup file.

    Raises:
        ValueError: If the configured DB is not SQLite.
        FileNotFoundError: If ``backup_path`` does not exist.
    """
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    dest = _sqlite_path_from_uri(uri)
    if dest is None and not uri.startswith("sqlite:///"):
        raise ValueError(f"restore_database only supports SQLite, got URI: {uri}")

    src = Path(backup_path)
    if not src.exists():
        raise FileNotFoundError(f"Backup file not found: {src}")

    if dest is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)

    source_conn = sqlite3.connect(str(src))
    try:
        dest_conn = sqlite3.connect(str(dest) if dest is not None else ":memory:")
        try:
            source_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    finally:
        source_conn.close()
