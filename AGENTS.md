# AGENTS.md

Project-specific guidance for AI agents (and humans) working on `pwd-manager`.

## Project layout

- `pwd_manager/` — Flask app package
  - `__init__.py` — app factory (`create_app`), error handlers, Jinja filters
  - `routes.py` — main blueprint: secrets + secret-entry attachments
  - `auth/routes.py` — register / login / logout
  - `library/routes.py` — library blueprint: documents + document attachments
  - `models.py` — SQLAlchemy models (User, SecretEntry, Attachment, Document, DocumentAttachment)
  - `utils/crypto.py` — Fernet encrypt/decrypt helpers
  - `utils/auth.py` — `get_user_encryption_key()` (reads `User.encryption_key` from DB)
  - `utils/password_generator.py` — passphrase-style generator (uses `secrets`)
  - `utils/__init__.py` — `escape_like()` for SQL LIKE wildcard escaping, `safe_error_message()` for hiding internal error details
  - `utils/backup.py` — SQLite online backup / restore (Phase 0)
  - `feature_flags.py` — env-var feature flags for the security rollout (Phase 0/1)
- `tests/` — pytest suite (unittest-style `TestCase`s)
- `migrations/` — Flask-Migrate (Alembic) migrations
- `run.py` — dev entrypoint (`python run.py -p 5000`)
- `Dockerfile` / `docker-compose.yml` — production-ish deployment (gunicorn)

## Environment

- Python 3.12+ (tested on 3.14 in the local venv).
- Virtualenv at `.venv/`. Use `uv` for any new package installs (per global rules).
- `.env` is loaded by `create_app`; `.env.local` takes priority if present.
  Both are gitignored. `.env.example` and `.env.local.example` are tracked.

## Common commands

Run from the repo root.

| Task | Command |
|------|---------|
| Run the full test suite | `.venv/bin/python -m pytest tests/ -q` |
| Run a single test file | `.venv/bin/python -m pytest tests/test_secret_routes.py -q` |
| Run a single test | `.venv/bin/python -m pytest tests/test_markdown.py::TestMarkdownFilter::test_bold -q` |
| Start the dev server | `.venv/bin/python run.py -p 5000` |
| Start with a specific env file | `.venv/bin/python run.py -e .env.local` |
| Open a Flask shell | `.venv/bin/python -c "from pwd_manager import create_app, db; app=create_app(); app.app_context().push()"` |
| Add a new dependency | `uv add <pkg>` (then commit `requirements.txt`) |
| Generate a migration | `.venv/bin/flask --app run.py db migrate -m "description"` |
| Apply migrations | `.venv/bin/flask --app run.py db upgrade` |

## Testing conventions

- Tests use `unittest.TestCase`, not pytest fixtures, for parity with the
  existing suite. `pytest` is the runner.
- Shared setup lives in `tests/conftest.py` as `BaseTestCase`. New
  integration tests should subclass it instead of re-deriving setUp/tearDown.
- The testing config (`create_app("testing")`) uses an in-memory SQLite DB
  and disables CSRF. Do **not** enable CSRF in the testing config — flip it
  per-test via `pwd_manager.feature_flags.override_flag` once CSRF lands.
- Attachment tests must use a temp `ATTACHMENTS_DIR` (BaseTestCase does this
  automatically) so on-disk files don't leak between tests or into the repo.

## Baseline / regression test policy

Several Phase 0 tests deliberately asserted the **current, unsafe** behaviour
as trip-wires. Phase 1 has now landed, and those tests have been updated to
assert the new, safe behaviour:

- `tests/test_markdown.py` — covers both legacy (unsanitised) and sanitised
  markdown filter behaviour via `ENABLE_MARKDOWN_SANITIZE`.
- `tests/test_secret_attachments.py::test_upload_rejects_oversized_file` —
  now asserts 413 (was 500) thanks to the dedicated 413 error handler.
- `tests/test_csrf.py` — covers CSRF enforcement when `ENABLE_CSRF` is on
  and legacy behaviour when it's off.

## Feature flags

All potentially-disruptive security changes are gated behind env-var flags
in `pwd_manager/feature_flags.py`. Every flag defaults to `False` (current
behaviour), so importing the module changes nothing. Flip a flag in `.env`
or via `override_flag(name, True)` in tests. Never reference an unknown flag
name — `is_enabled` raises `KeyError` to catch typos early.

### Phase 1 flags

| Flag | Effect when `1` |
|------|-----------------|
| `ENABLE_CSRF` | Flask-WTF CSRFProtect validates all POST/PUT/DELETE/PATCH. Forms render `{{ csrf_token() }}`; AJAX calls send `X-CSRFToken` header (auto-patched by `base.html`). |
| `ENABLE_SECURITY_HEADERS` | Adds `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP, and HSTS (HTTPS only) via `after_request`. Hardens session cookie (`HttpOnly`, `SameSite=Lax`, `Secure` on HTTPS). |
| `ENABLE_MARKDOWN_SANITIZE` | Runs `bleach.clean` with a strict allowlist over markdown output before `Markup()`. Strips `<script>`, inline event handlers, `javascript:` URLs, `<iframe>`, etc. |
| `HIDE_INTERNAL_ERRORS` | Route handlers return generic `"Internal error"` messages instead of exception strings. Full detail logged server-side via `logger.exception()`. |
| `STRICT_SECRET_KEY` | App refuses to start if `SECRET_KEY` is unset, too short (<16 chars), or a known default value. When off, emits a loud warning instead. |

## Database backup before any DB-touching change

Before running any migration that touches the `user`, `password_entry`,
`document`, `attachment`, or `document_attachment` tables, take a backup:

```python
from pwd_manager import create_app
from pwd_manager.utils.backup import backup_database
app = create_app()
backup_database(app, "/var/backups/pwd-manager-pre-<change>.db")
```

`backup_database` uses the SQLite online backup API and writes atomically, so
it's safe to run while the app is serving. Verify the restore on a copy
before proceeding.

## Security context

See `vulnerability-report.md` for the full findings and
`security-fix-plan.md` for the phased rollout plan. Do not introduce changes
that bypass the planned phase ordering without discussing first.

# General Development
- MUST follow Python software develpment best practices
- MUST use uv for package management, run test, run project, etc.
- MUST take into account the migration strategy when making changes. Any new change in the database schema must be reflected in the migration script.
