import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from universalmail.security import cipher


@pytest.fixture(autouse=True)
def environment(monkeypatch, tmp_path):
    monkeypatch.setenv("UNIVERSALMAIL_MASTER_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("UNIVERSALMAIL_API_KEY", "test-owner-key-" + "x" * 40)
    monkeypatch.setenv("UNIVERSALMAIL_DB_PATH", str(tmp_path / "vault.db"))
    monkeypatch.setenv("UNIVERSALMAIL_PUBLIC_URL", "https://testserver")
    monkeypatch.setenv("UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST", "false")
    monkeypatch.setenv("UNIVERSALMAIL_ALLOW_PRIVATE_MAIL_HOSTS", "false")
    for prefix in ("GOOGLE", "MICROSOFT"):
        monkeypatch.setenv(prefix + "_CLIENT_ID", "test-client")
        monkeypatch.setenv(prefix + "_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("MICROSOFT_TENANT", "common")
    cipher.cache_clear()
    yield
    cipher.cache_clear()


@pytest.fixture
def client(environment):
    from universalmail.main import app
    with TestClient(app, base_url="https://testserver") as client:
        yield client


@pytest.fixture
def headers():
    return {"X-API-Key": "test-owner-key-" + "x" * 40}
