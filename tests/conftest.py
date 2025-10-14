
import os
import json
import pytest

try:
    from app import create_app as _real_create_app
    _create_app = _real_create_app
except Exception:
    _create_app = None

@pytest.fixture(scope="session")
def app():
    if _create_app is None:
        pytest.skip("No app factory found (app.create_app). Skipping app-dependent tests.")
    os.environ.setdefault("APP_CONFIG", "testing")
    os.environ.setdefault("SECRET_KEY", "test-secret")
    os.environ.setdefault("SECURITY_PASSWORD_SALT", "testsalt")
    os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_xxx")
    os.environ.setdefault("STRIPE_PUBLISHABLE_KEY", "pk_test_xxx")
    os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_test_xxx")
    os.environ.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    os.environ.setdefault("WTF_CSRF_ENABLED", "False")
    try:
        a = _create_app("testing")
    except Exception:
        a = _create_app()
    a.config.update(TESTING=True)
    return a

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
