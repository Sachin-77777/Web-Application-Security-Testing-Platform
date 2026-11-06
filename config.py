import os
from datetime import timedelta
from urllib.parse import quote_plus

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


DEFAULT_SECRET_KEY = "change-this-in-production"
MIN_SECRET_KEY_LENGTH = 32


def _env(name, default=None):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = _env("SECRET_KEY", DEFAULT_SECRET_KEY)

    MYSQL_HOST = _env("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(_env("MYSQL_PORT", "3306"))
    MYSQL_USER = _env("MYSQL_USER", "root")
    MYSQL_PASSWORD = _env("MYSQL_PASSWORD", "")
    MYSQL_DB = _env("MYSQL_DB", "wastp")
    MYSQL_CURSORCLASS = _env("MYSQL_CURSORCLASS", "DictCursor")

    SQLALCHEMY_DATABASE_URI = _env("DATABASE_URL") or (
        "mysql+pymysql://{user}:{password}@{host}:{port}/{db}".format(
            user=quote_plus(MYSQL_USER),
            password=quote_plus(MYSQL_PASSWORD),
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            db=MYSQL_DB,
        )
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    REPORTS_FOLDER = _env("REPORTS_FOLDER")

    # Defense-in-depth response headers (CSP, X-Frame-Options, ...).
    SECURITY_HEADERS_ENABLED = _env_bool("SECURITY_HEADERS_ENABLED", True)

    # Rows per page in the HTML list views.
    PER_PAGE = int(_env("PER_PAGE", "10"))

    # Brute-force protection shared by the session login and the JWT login.
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(_env("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "5"))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(_env("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))
    LOGIN_RATE_LIMIT_LOCKOUT_SECONDS = int(_env("LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", "300"))

    # Password-reset one-time codes. The attempt cap is what keeps a six-digit
    # code from being guessable inside its validity window.
    PASSWORD_RESET_OTP_MINUTES = int(_env("PASSWORD_RESET_OTP_MINUTES", "10"))
    PASSWORD_RESET_MAX_ATTEMPTS = int(_env("PASSWORD_RESET_MAX_ATTEMPTS", "5"))

    # SMTP for outgoing reset codes. Leave MAIL_SERVER unset in the lab: the
    # mailer then writes the code to the server log instead of sending it.
    MAIL_SERVER = _env("MAIL_SERVER")
    MAIL_PORT = int(_env("MAIL_PORT", "587"))
    MAIL_USERNAME = _env("MAIL_USERNAME")
    MAIL_PASSWORD = _env("MAIL_PASSWORD")
    MAIL_USE_TLS = _env_bool("MAIL_USE_TLS", True)
    MAIL_FROM = _env("MAIL_FROM", "no-reply@wastp.local")

    # JSON REST API (/api) uses bearer tokens instead of the session cookie.
    JWT_SECRET_KEY = _env("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(_env("JWT_ACCESS_MINUTES", "60")))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(_env("JWT_REFRESH_DAYS", "7")))
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_ERROR_MESSAGE_KEY = "message"


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    # Only send cookies over HTTPS, and redirect plain-HTTP URLs to HTTPS.
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    PREFERRED_URL_SCHEME = "https"


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SECRET_KEY = _env("SECRET_KEY", "testing-secret-key-not-for-production")
    JWT_SECRET_KEY = _env("JWT_SECRET_KEY", "testing-jwt-secret-not-for-production")
    SQLALCHEMY_DATABASE_URI = _env(
        "TEST_DATABASE_URI",
        "sqlite:///:memory:",
    )


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config(name=None):
    env_name = name or _env("FLASK_ENV", "development")
    return config_by_name.get(env_name, DevelopmentConfig)


def configuration_problems(app):
    """Return a list of insecure settings that should be fixed before shipping."""
    problems = []

    secret_key = app.config.get("SECRET_KEY") or ""
    if secret_key == DEFAULT_SECRET_KEY:
        problems.append("SECRET_KEY is still the built-in default value.")
    elif len(secret_key) < MIN_SECRET_KEY_LENGTH:
        problems.append(
            f"SECRET_KEY is shorter than {MIN_SECRET_KEY_LENGTH} characters."
        )

    jwt_secret = app.config.get("JWT_SECRET_KEY") or ""
    if jwt_secret == DEFAULT_SECRET_KEY:
        problems.append("JWT_SECRET_KEY is still the built-in default value.")
    elif len(jwt_secret) < MIN_SECRET_KEY_LENGTH:
        problems.append(
            f"JWT_SECRET_KEY is shorter than {MIN_SECRET_KEY_LENGTH} characters."
        )

    return problems
