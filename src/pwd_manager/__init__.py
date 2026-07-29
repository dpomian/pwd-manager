import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()

# Known-insecure default SECRET_KEY values that must never be used in
# production. If the env var is set to one of these, the app will either
# warn loudly (default) or refuse to start (STRICT_SECRET_KEY=1).
_KNOWN_WEAK_SECRET_KEYS = frozenset(
    {
        "your_very_secret_and_unique_key_here",  # .env.example
        "local-dev-secret-key",  # .env.local.example
        "default-secret-key-change-in-production",  # docker-compose.yml
        "abcdefg",  # current .env (will be rotated)
        "change-me",
        "secret",
    }
)


def _validate_secret_key(secret_key):
    """Check the configured ``SECRET_KEY`` for known-weak values.

    Behaviour:
    * If ``STRICT_SECRET_KEY`` is enabled, raise ``RuntimeError`` for any
      of: unset, empty, shorter than 16 bytes, or a known default value.
    * If ``STRICT_SECRET_KEY`` is off (the default for backward
      compatibility), emit a loud warning for the same conditions but
      allow the app to start. This gives operators a grace period to
      rotate the key before the next release flips the default.

    The previous behaviour fell back to ``os.urandom(24)`` when the env
    var was unset, which silently regenerated the key on every restart
    (invalidating all sessions) and masked the misconfiguration. We now
    require the env var to be set explicitly.
    """
    import warnings

    from pwd_manager.feature_flags import is_enabled

    strict = is_enabled("STRICT_SECRET_KEY")

    issues = []
    if not secret_key:
        issues.append("SECRET_KEY is not set")
    elif len(secret_key) < 16:
        issues.append(f"SECRET_KEY is too short ({len(secret_key)} chars, need >= 16)")
    elif secret_key in _KNOWN_WEAK_SECRET_KEYS:
        issues.append("SECRET_KEY is a known default/weak value")

    if not issues:
        return

    message = "SECURITY: " + "; ".join(issues) + (
        ". Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

    if strict:
        raise RuntimeError(message)
    warnings.warn(message, RuntimeWarning, stacklevel=2)

# Known-insecure default SECRET_KEY values that must never be used in
# production. If the env var is set to one of these, the app will either
# warn loudly (default) or refuse to start (STRICT_SECRET_KEY=1).
_KNOWN_WEAK_SECRET_KEYS = frozenset(
    {
        "your_very_secret_and_unique_key_here",  # .env.example
        "local-dev-secret-key",  # .env.local.example
        "default-secret-key-change-in-production",  # docker-compose.yml
        "abcdefg",  # current .env (will be rotated)
        "change-me",
        "secret",
    }
)


def _validate_secret_key(secret_key):
    """Check the configured ``SECRET_KEY`` for known-weak values.

    Behaviour:
    * If ``STRICT_SECRET_KEY`` is enabled, raise ``RuntimeError`` for any
      of: unset, empty, shorter than 16 bytes, or a known default value.
    * If ``STRICT_SECRET_KEY`` is off (the default for backward
      compatibility), emit a loud warning for the same conditions but
      allow the app to start. This gives operators a grace period to
      rotate the key before the next release flips the default.

    The previous behaviour fell back to ``os.urandom(24)`` when the env
    var was unset, which silently regenerated the key on every restart
    (invalidating all sessions) and masked the misconfiguration. We now
    require the env var to be set explicitly.
    """
    import warnings

    from pwd_manager.feature_flags import is_enabled

    strict = is_enabled("STRICT_SECRET_KEY")

    issues = []
    if not secret_key:
        issues.append("SECRET_KEY is not set")
    elif len(secret_key) < 16:
        issues.append(f"SECRET_KEY is too short ({len(secret_key)} chars, need >= 16)")
    elif secret_key in _KNOWN_WEAK_SECRET_KEYS:
        issues.append("SECRET_KEY is a known default/weak value")

    if not issues:
        return

    message = "SECURITY: " + "; ".join(issues) + (
        ". Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

    if strict:
        raise RuntimeError(message)
    warnings.warn(message, RuntimeWarning, stacklevel=2)


def create_app(config_name=None):
    # Load environment variables based on config
    # Priority: PWD_MANAGER_ENV_FILE > .env.local > .env.{config_name} > .env
    env_file = ".env"
    if config_name and config_name != "testing":
        env_file = f".env.{config_name}"
    env_file = os.getenv("PWD_MANAGER_ENV_FILE", env_file)

    base_dir = PROJECT_ROOT
    local_env = base_dir / ".env.local"
    config_env = base_dir / env_file

    if config_name != "testing":
        if local_env.exists():
            load_dotenv(local_env, override=True)
            print(f"Loaded environment from: {local_env}")
        elif config_env.exists():
            load_dotenv(config_env, override=True)
            print(f"Loaded environment from: {config_env}")
        else:
            load_dotenv(base_dir / ".env")
            print("Loaded environment from: .env")

    instance_path = base_dir / "instance"
    instance_path.mkdir(parents=True, exist_ok=True)

    # Initialize Flask app
    app = Flask(__name__, instance_path=str(instance_path))

    if config_name == "testing":
        # Testing configuration
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for testing
    else:
        # Production configuration
        secret_key = os.getenv("SECRET_KEY")
        _validate_secret_key(secret_key)
        app.config["SECRET_KEY"] = secret_key

        # Configure database
        db_type = os.getenv("DATABASE_TYPE", "sqlite")
        db_path = os.getenv(
            "DATABASE_PATH", str(Path(app.instance_path) / "passwords.db")
        )

        # Ensure the directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        # Construct database URL
        if db_type == "sqlite":
            app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Configure attachments directory. Allow override via env var so the
    # attachments can live alongside the database when DATABASE_PATH points
    # to a custom location outside the Flask instance path.
    attachments_dir = os.getenv(
        "ATTACHMENTS_DIR",
        os.path.join(app.instance_path, "attachments"),
    )
    os.makedirs(attachments_dir, exist_ok=True)
    app.config["ATTACHMENTS_DIR"] = attachments_dir
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB max upload size

    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    # CSRF protection (C3) — gated behind ENABLE_CSRF so it can be rolled
    # out per-environment. CSRFProtect is always initialised so that the
    # ``csrf_token()`` Jinja function is available in templates (forms
    # render the hidden field regardless), but validation is only active
    # when the flag is on. This lets us ship the template changes first
    # and flip the flag per-environment without a redeploy.
    from flask_wtf.csrf import CSRFProtect

    from pwd_manager.feature_flags import is_enabled

    csrf = CSRFProtect(app)
    app.extensions["csrf"] = csrf
    if not is_enabled("ENABLE_CSRF") or config_name == "testing":
        app.config["WTF_CSRF_ENABLED"] = False

    # Register blueprints
    from pwd_manager.auth.routes import auth_bp
    from pwd_manager.library.routes import library_bp
    from pwd_manager.routes import main_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(main_bp)
    app.register_blueprint(library_bp, url_prefix="/library")

    # Register Jinja2 filters
    register_template_filters(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    # Configure logging (only in non-debug mode or if explicitly enabled)
    if not app.debug or os.getenv("ENABLE_FILE_LOGGING", "false").lower() == "true":
        configure_logging(app)

    # Register security headers (M2/M6) — gated behind a feature flag so
    # it can be enabled per-environment without a code change.
    register_security_headers(app)

    # Register error handlers
    register_error_handlers(app)

    return app


def register_security_headers(app):
    """Add security headers and harden session cookie flags.

    Gated behind the ``ENABLE_SECURITY_HEADERS`` feature flag. When off
    (the default), no headers are added and cookie flags are unchanged,
    preserving the app's pre-hardening behaviour. When on:

    * Sets ``X-Content-Type-Options: nosniff``
    * Sets ``X-Frame-Options: DENY`` (clickjacking protection)
    * Sets ``Referrer-Policy: no-referrer``
    * Sets a Content-Security-Policy that allows the app's own assets,
      Bootstrap/jsDelivr CDN, and Google Fonts; blocks everything else
    * Sets ``Strict-Transport-Security`` only when the request is HTTPS
      (so dev over HTTP isn't broken)
    * Marks the session cookie ``HttpOnly`` and ``SameSite=Lax``.
      ``Secure`` is set only when the request is HTTPS.
    """
    from pwd_manager.feature_flags import is_enabled

    if not is_enabled("ENABLE_SECURITY_HEADERS"):
        return

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            # 'unsafe-inline' is needed because the templates use inline
            # <script> blocks and onclick handlers. A future phase should
            # move JS to external files and replace this with nonces.
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "frame-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'"
        )
        # HSTS only over HTTPS to avoid breaking local dev over HTTP.
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    # Harden the session cookie. These are app-level config (not per-request
    # headers) so they apply to every Set-Cookie Flask emits.
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # SESSION_COOKIE_SECURE is set dynamically per-request below so that
    # dev over HTTP still works.
    @app.before_request
    def _set_secure_cookie_flag():
        app.config["SESSION_COOKIE_SECURE"] = request.is_secure


def configure_logging(app):
    """Configure file-based logging with rotation"""
    from pathlib import Path

    # Create logs directory
    logs_dir = Path(app.instance_path) / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Configure rotating file handler (max 10MB per file, keep 10 backups)
    file_handler = RotatingFileHandler(
        logs_dir / "pwd_manager.log", maxBytes=10 * 1024 * 1024, backupCount=10  # 10MB
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
        )
    )
    file_handler.setLevel(logging.ERROR)

    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info("Password Manager startup")


def register_error_handlers(app):
    """Register custom error handlers"""

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Handle MAX_CONTENT_LENGTH violations.

        Returns JSON for AJAX callers (attachment uploads) and a rendered
        page for browser navigations. Previously this was swallowed by the
        catch-all Exception handler and returned a 500.
        """
        if (
            request.path.startswith("/attachment/")
            or request.path.startswith("/library/attachment/")
        ):
            return (
                jsonify({"error": "File too large. Maximum size is 10MB"}),
                413,
            )
        return render_template("errors/500.html"), 413

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()  # Roll back any failed transactions
        app.logger.exception(f"Server Error: {error}")
        return render_template("errors/500.html"), 500

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        """Let Werkzeug HTTPExceptions (4xx/5xx raised deliberately) keep
        their proper status code instead of being masked as 500 by the
        catch-all below. This is the fix for the 413→500 bug pinned in
        ``tests/test_secret_attachments.py``.
        """
        return error

    @app.errorhandler(Exception)
    def handle_exception(error):
        # Log the full exception
        app.logger.exception(f"Unhandled Exception: {error}")
        db.session.rollback()
        return render_template("errors/500.html"), 500


def register_template_filters(app):
    """Register custom Jinja2 template filters"""
    import bleach
    import markdown
    from markupsafe import Markup

    from pwd_manager.feature_flags import is_enabled

    # Allowlist of HTML tags/attributes that the markdown filter may emit.
    # Anything outside this set is stripped when sanitisation is enabled.
    _ALLOWED_TAGS = [
        "p", "br", "hr", "strong", "em", "del", "ul", "ol", "li",
        "code", "pre", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6",
        "a", "table", "thead", "tbody", "tr", "th", "td",
    ]
    _ALLOWED_ATTRIBUTES = {
        "a": ["href", "title", "rel"],
    }
    # Schemes allowed in href attributes. ``javascript:`` is explicitly
    # blocked by only permitting http/https/mailto.
    _ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

    @app.template_filter("markdown")
    def markdown_filter(text):
        """Convert markdown text to HTML.

        When ``ENABLE_MARKDOWN_SANITIZE`` is on, the output is run through
        ``bleach.clean`` with a strict allowlist before being marked safe,
        so raw ``<script>``, inline event handlers, ``javascript:`` URLs,
        and other XSS vectors are stripped (C4). When the flag is off (the
        default), the legacy behaviour is preserved: raw HTML passes
        through unchanged.

        The flag is read at **call time** (not registration time) so that
        ``override_flag`` in tests works even when ``create_app`` calls
        ``load_dotenv(override=True)`` after the override is set.
        """
        if not text:
            return ""
        html = markdown.markdown(text, extensions=["fenced_code", "tables", "nl2br"])
        if is_enabled("ENABLE_MARKDOWN_SANITIZE"):
            html = bleach.clean(
                html,
                tags=_ALLOWED_TAGS,
                attributes=_ALLOWED_ATTRIBUTES,
                protocols=_ALLOWED_PROTOCOLS,
                strip=True,
            )
        return Markup(html)
