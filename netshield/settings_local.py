"""Explicit localhost development profile; never used by the normal settings."""
from .settings import *  # noqa: F403

LOCAL_DEVELOPMENT_ACCESS = True
DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
MIDDLEWARE = ["netshield.local_development.LocalDevelopmentOnlyMiddleware", *MIDDLEWARE]  # noqa: F405

# Keep normal Django password authentication and database-backed sessions.
# A distinct host-only cookie isolates this convenience from normal deployments.
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "netshield_local_sessionid"
SESSION_COOKIE_DOMAIN = None
SESSION_COOKIE_AGE = 30 * 24 * 60 * 60
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
# Monitoring reads must not cause session writes every two seconds.
SESSION_SAVE_EVERY_REQUEST = False

# Both profiles use the same explicit configuration loader.
DEVICE_CONNECTION_ALLOWED_NETWORKS, DEVICE_CONNECTION_ALLOWLIST_SOURCE = load_device_policy(
    BASE_DIR / "netshield", local=True
)
