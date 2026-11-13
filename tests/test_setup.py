"""Deployment/configuration tests; no cloud registration, mail or host installation."""
import base64
import importlib.util
import os
from pathlib import Path
import re

from cryptography.fernet import Fernet
import pytest

from universalmail import client_config, provider_http

spec = importlib.util.spec_from_file_location("setup_configure", Path(__file__).parents[1] / "scripts" / "configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


def test_first_run_generates_separate_keys_and_does_not_rotate(tmp_path):
    values, created = configure.initialize(tmp_path, "local")
    assert created and len(base64.urlsafe_b64decode(values["UNIVERSALMAIL_MASTER_KEY"])) == 32
    assert len(values["UNIVERSALMAIL_API_KEY"]) >= 48
    assert values["UNIVERSALMAIL_API_KEY"] != values["UNIVERSALMAIL_MASTER_KEY"]
    before = (tmp_path / ".env").read_bytes()
    repeated, created = configure.initialize(tmp_path, "local")
    assert not created and repeated == values and before == (tmp_path / ".env").read_bytes()
    if os.name == "posix":
        assert (tmp_path / ".env").stat().st_mode & 0o777 == 0o600


def test_existing_config_not_silently_migrated(tmp_path):
    configure.initialize(tmp_path, "local")
    with pytest.raises(ValueError, match="differs"):
        configure.initialize(tmp_path, "server", domain="mail.example.com")
    assert configure.read_env(tmp_path / ".env")["UNIVERSALMAIL_DEPLOYMENT_MODE"] == "local"


def test_server_configuration_enforces_https(tmp_path):
    values, created = configure.initialize(tmp_path, "server", domain="Mail.Example.com")
    assert created
    assert values["UNIVERSALMAIL_PUBLIC_URL"] == "https://mail.example.com"
    assert values["UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST"] == "false"
    assert values["UNIVERSALMAIL_TLS_DOMAIN"] == "mail.example.com"


@pytest.mark.parametrize("domain", ["", "localhost", "a.local", "a.internal", "127.0.0.1", "https://mail.example.com", "mail.example.com/x", "*.example.com", "example.com;id", "a\n.example.com", "-x.example.com"])
def test_server_host_injection_rejected(domain, tmp_path):
    with pytest.raises(ValueError):
        configure.initialize(tmp_path, "server", domain=domain)
    assert not (tmp_path / ".env").exists()


@pytest.mark.parametrize("port", [0, 80, 65536])
def test_invalid_local_port(port, tmp_path):
    with pytest.raises(ValueError):
        configure.initialize(tmp_path, "local", port)


def test_nondefault_port_matches_callback_origin(tmp_path):
    values, _ = configure.initialize(tmp_path, "local", 8765)
    assert values["UNIVERSALMAIL_PUBLIC_URL"] == "http://localhost:8765"
    assert values["UNIVERSALMAIL_HOST_PORT"] == "8765"


def test_placeholder_configuration_preserved(tmp_path):
    p = tmp_path / ".env"
    p.write_text("UNIVERSALMAIL_MASTER_KEY=replace-me\nUNIVERSALMAIL_API_KEY=replace-me\n")
    with pytest.raises(ValueError, match="NOT overwritten"):
        configure.initialize(tmp_path, "local")
    assert "replace-me" in p.read_text()


def test_symlink_refused(tmp_path):
    target = tmp_path / "target"
    target.write_text("untouched")
    try:
        (tmp_path / ".env").symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation unavailable on this host")
    with pytest.raises(ValueError, match="symbolic-link"):
        configure.initialize(tmp_path, "local")
    assert target.read_text() == "untouched"


def test_duplicate_dotenv_key_rejected(tmp_path):
    p = tmp_path / ".env"
    p.write_text("X=one\nX=two\n")
    with pytest.raises(ValueError, match="duplicate"):
        configure.read_env(p)


def test_setup_page_no_secret_or_browser_storage(client):
    response = client.get("/setup")
    assert response.status_code == 200
    assert "This computer" in response.text and "My backend server" in response.text
    assert "test-owner-key" not in response.text and "test-client-secret" not in response.text
    assert "localStorage" not in response.text and "sessionStorage" not in response.text
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/").url.path == "/setup"


def test_setup_status_auth_required(client):
    assert client.get("/setup/status").status_code == 401
    assert client.post("/setup/providers/gmail", json={}).status_code == 401


def test_setup_status_does_not_claim_mcp_connected(client, headers):
    response = client.get("/setup/status", headers=headers)
    data = response.json()
    assert response.status_code == 200
    assert data["mcp_connected"] is False
    assert data["server_provisioning_from_browser"] is False
    assert len(data["deployment_options"]) == 2
    assert data["providers"]["gmail"]["redirect_uri"] == "https://testserver/oauth/gmail/callback"
    assert "test-client-secret" not in response.text


def payload(**updates):
    return {"client_id": "new-client.apps.googleusercontent.com", "client_secret": "unique-private-secret-value", **updates}


def test_save_encrypted_provider_configuration(client, headers, monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID")
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET")
    response = client.post("/setup/providers/gmail", headers=headers, json=payload())
    assert response.status_code == 200
    assert response.json()["saved"] is True
    assert response.json()["provider_credentials_validated"] is False
    assert "unique-private-secret-value" not in response.text
    cfg = provider_http.settings("gmail")
    assert cfg["client_id"] == payload()["client_id"]
    assert cfg["client_secret"] == payload()["client_secret"]
    path = Path(os.environ["UNIVERSALMAIL_DB_PATH"]).parent / "oauth-client-gmail.enc"
    assert "unique-private-secret-value" not in path.read_text()
    assert "new-client" not in path.read_text()
    assert client.get("/setup/status", headers=headers).json()["providers"]["gmail"]["configured"]


def test_replacing_existing_credentials_needs_explicit_flag(client, headers):
    response = client.post("/setup/providers/gmail", headers=headers, json=payload())
    assert response.status_code == 409
    response = client.post("/setup/providers/gmail", headers=headers, json=payload(replace_existing=True))
    assert response.status_code == 200 and response.json()["reconnect_existing_accounts"] is True


def test_saved_credentials_work_for_oauth_start(client, headers):
    assert client.post("/setup/providers/gmail", headers=headers, json=payload(replace_existing=True)).status_code == 200
    response = client.post("/oauth/gmail/start", headers=headers, json={})
    assert response.status_code == 200
    assert "client_id=new-client.apps.googleusercontent.com" in response.json()["authorization_url"]
    assert "unique-private-secret-value" not in response.text


def test_cross_origin_setup_denied(client, headers):
    h = {**headers, "Origin": "https://attacker.invalid"}
    assert client.post("/setup/providers/gmail", headers=h, json=payload(replace_existing=True)).status_code == 403


@pytest.mark.parametrize("body", [payload(client_secret="abc"), payload(client_secret="secret-value\ninjected"), payload(client_id="bad client"), payload(tenant="common/../../evil")])
def test_invalid_client_values_not_echoed(client, headers, body):
    response = client.post("/setup/providers/outlook", headers=headers, json=body)
    assert response.status_code in (400, 422)
    assert body["client_secret"] not in response.text


def test_encrypted_saved_config_precedes_environment(client, headers):
    client.post("/setup/providers/outlook", headers=headers, json=payload(tenant="consumers", replace_existing=True))
    cfg = provider_http.settings("outlook")
    assert cfg["token_url"] == "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
    assert cfg["client_id"].startswith("new-client")


def test_server_compose_does_not_publish_mail_backend():
    root = Path(__file__).parents[1]
    content = (root / "compose.server.yaml").read_text()
    backend = content.split("  proxy:")[0]
    assert "ports:" not in backend
    assert '"80:80"' in content and '"443:443"' in content
    assert "log {" not in (root / "deploy/Caddyfile").read_text()
    assert '127.0.0.1:${UNIVERSALMAIL_HOST_PORT:-8000}:8000' in (root / "compose.yaml").read_text()


def test_setup_javascript_parses(tmp_path):
    import shutil, subprocess
    from universalmail.setup_page import PAGE
    if not shutil.which("node"):
        pytest.skip("Node is required for JS syntax validation")
    script = re.search(r'<script nonce="__NONCE__">(.*?)</script>', PAGE, re.S).group(1)
    path = tmp_path / "setup.js"
    path.write_text(script, encoding="utf-8")
    result = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
