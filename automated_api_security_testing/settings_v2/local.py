"""
Local development settings for LLM-Powered Automated API Security Testing Framework.
Use only for development. Never use in production.
"""

from .base import *

# ------------------------------------
# ✅ Debugging & Host Configuration
# ------------------------------------
DEBUG = True
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])
CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=[
    "http://localhost",
    "http://127.0.0.1"
])

# ------------------------------------
# ✅ Local SQLite or PostgreSQL Setup
# ------------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# To use PostgreSQL locally instead, uncomment and configure:
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': env("DB_NAME"),
#         'USER': env("DB_USER"),
#         'PASSWORD': env("DB_PASSWORD"),
#         'HOST': env("DB_HOST"),
#         'PORT': env.int("DB_PORT", default=5432),
#     }
# }

# ------------------------------------
# ✅ Email Configuration (Console for Dev)
# ------------------------------------
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# ------------------------------------
# ✅ Session & Cookie Settings
# ------------------------------------
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
JWT_AUTH_COOKIE_SECURE = False
JWT_AUTH_HTTPONLY = True
JWT_AUTH_SAMESITE = "Lax"

# ------------------------------------
# ✅ Secure Proxy Header
# ------------------------------------
SECURE_PROXY_SSL_HEADER = None  # Not needed for local dev

# ------------------------------------
# ✅ Optional Debug Tools
# ------------------------------------
# INSTALLED_APPS += [
#     'debug_toolbar',
# ]

# MIDDLEWARE += [
#     'debug_toolbar.middleware.DebugToolbarMiddleware',
# ]

# ------------------------------------
# ✅ Logging (Optional SQL Debug)
# ------------------------------------
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'DEBUG',  # Change to 'INFO' to reduce verbosity
        },
    }
}
