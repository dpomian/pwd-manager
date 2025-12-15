from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import logging
from logging.handlers import RotatingFileHandler

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()

def create_app(config_name=None):
    # Load environment variables based on config
    # Priority: .env.local > .env.{config_name} > .env
    env_file = '.env'
    if config_name and config_name != 'testing':
        env_file = f'.env.{config_name}'
    
    # Check for .env.local first (highest priority for local development)
    from pathlib import Path
    base_dir = Path(__file__).resolve().parent.parent
    local_env = base_dir / '.env.local'
    config_env = base_dir / env_file
    
    if local_env.exists():
        load_dotenv(local_env, override=True)
        print(f"Loaded environment from: {local_env}")
    elif config_env.exists():
        load_dotenv(config_env, override=True)
        print(f"Loaded environment from: {config_env}")
    else:
        load_dotenv()  # Default .env
        print("Loaded environment from: .env")
    
    # Initialize Flask app
    app = Flask(__name__)
    
    if config_name == 'testing':
        # Testing configuration
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
    else:
        # Production configuration
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
        
        # Configure database
        db_type = os.getenv('DATABASE_TYPE', 'sqlite')
        db_path = os.getenv('DATABASE_PATH', os.path.join(app.instance_path, 'passwords.db'))
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Construct database URL
        if db_type == 'sqlite':
            app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
        else:
            raise ValueError(f'Unsupported database type: {db_type}')
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Configure attachments directory
    attachments_dir = os.path.join(app.instance_path, 'attachments')
    os.makedirs(attachments_dir, exist_ok=True)
    app.config['ATTACHMENTS_DIR'] = attachments_dir
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max upload size

    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    from pwd_manager.auth.routes import auth_bp
    from pwd_manager.routes import main_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)

    # Register Jinja2 filters
    register_template_filters(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    # Configure logging (only in non-debug mode or if explicitly enabled)
    if not app.debug or os.getenv('ENABLE_FILE_LOGGING', 'false').lower() == 'true':
        configure_logging(app)

    # Register error handlers
    register_error_handlers(app)

    return app


def configure_logging(app):
    """Configure file-based logging with rotation"""
    from pathlib import Path
    
    # Create logs directory
    logs_dir = Path(app.instance_path) / 'logs'
    logs_dir.mkdir(exist_ok=True)
    
    # Configure rotating file handler (max 10MB per file, keep 10 backups)
    file_handler = RotatingFileHandler(
        logs_dir / 'pwd_manager.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.ERROR)
    
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Password Manager startup')


def register_error_handlers(app):
    """Register custom error handlers"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()  # Roll back any failed transactions
        app.logger.error(f'Server Error: {error}', exc_info=True)
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        # Log the full exception
        app.logger.error(f'Unhandled Exception: {error}', exc_info=True)
        db.session.rollback()
        return render_template('errors/500.html'), 500


def register_template_filters(app):
    """Register custom Jinja2 template filters"""
    import markdown
    from markupsafe import Markup
    
    @app.template_filter('markdown')
    def markdown_filter(text):
        """Convert markdown text to HTML"""
        if not text:
            return ''
        # Convert markdown to HTML with safe extensions
        html = markdown.markdown(
            text,
            extensions=['fenced_code', 'tables', 'nl2br']
        )
        return Markup(html)
