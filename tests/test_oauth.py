import base64
import hashlib
import os
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from universalmail import oauth, provider_http as provider, vault
from universalmail.main import app


def begin(client, headers, kind="gmail", **body):
    response = client.post(f"/oauth/{kind}/start", headers=headers, json=body)
    assert response.status_code == 200, response.text
    return parse_qs(urlsplit(response.json()["authorization_url"]).query), response


def grant(monkeypatch, kind="gmail", **changes):
    tokens = {"access_token": "sensitive-access", "refresh_token": "sensitive-refresh",
              "expires_in": 3600, "token_type": "Bearer", "scope": " ".join(provider.settings(kind)["scopes"])}
    tokens.update(changes)
    exchange = Mock(return_value=tokens)
    monkeypatch.setattr(provider, "token_request", exchange)
    profile = {"emailAddress": "owner@example.com"} if kind == "gmail" else {
        "id": "stable-microsoft-id", "mail": "owner@example.com", "displayName": "Owner"}
    identity = Mock(return_value=profile)
    monkeypatch.setattr(provider, "_request", identity)
    return exchange, identity


def complete(client, query, kind="gmail", **extra):
    return client.get(f"/oauth/{kind}/callback", params={"state": query["state"][0], "code": "one-use-code", **extra})


@pytest.mark.parametrize("kind", ["gmail", "outlook"])
def test_pkce_browser_cookie_and_verified_identity(client, headers, monkeypatch, kind):
    exchange, identity = grant(monkeypatch, kind)
    query, response = begin(client, headers, kind, expected_email="owner@example.com")
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == [f"https://testserver/oauth/{kind}/callback"]
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    result = complete(client, query, kind)
    assert result.status_code == 200
    assert "owner@example.com" in result.text
    verifier = exchange.call_args.args[1]["code_verifier"]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert query["code_challenge"] == [expected]
    assert "sensitive-access" not in result.text and "sensitive-refresh" not in result.text
    accounts = client.get("/accounts", headers=headers).json()
    assert len(accounts) == 1 and "config" not in accounts[0]
    saved = vault.get_account(accounts[0]["id"])
    assert saved["config"]["refresh_token"] == "sensitive-refresh"
    assert b"sensitive-refresh" not in open(os.environ["UNIVERSALMAIL_DB_PATH"], "rb").read()
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["referrer-policy"] == "no-referrer"
    identity.assert_called_once()


def test_start_requires_owner_key(client):
    assert client.post("/oauth/gmail/start", json={}).status_code == 401


def test_cross_origin_start_rejected(client, headers):
    assert client.post("/oauth/gmail/start", json={}, headers={**headers, "Origin": "https://evil.example"}).status_code == 403


def test_callback_cannot_be_replayed(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 200
    assert complete(client, q).status_code == 400
    exchange.assert_called_once()


def test_wrong_browser_cannot_consume_state(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    with TestClient(app, base_url="https://testserver") as stranger:
        assert complete(stranger, q).status_code == 400
    exchange.assert_not_called()
    assert complete(client, q).status_code == 200


def test_provider_mismatch_does_not_exchange(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    assert complete(client, q, "outlook").status_code == 400
    exchange.assert_not_called()
    assert complete(client, q).status_code == 200


def test_expired_state_rejected(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    with vault.connection() as con:
        con.execute("UPDATE oauth_states SET expires=0")
    assert complete(client, q).status_code == 400
    exchange.assert_not_called()


def test_denied_consent_consumes_state(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    assert complete(client, q, error="access_denied").status_code == 400
    assert complete(client, q).status_code == 400
    assert vault.list_accounts() == []
    exchange.assert_not_called()


def test_mailbox_mismatch_not_saved(client, headers, monkeypatch):
    grant(monkeypatch)
    q, _ = begin(client, headers, expected_email="someone-else@example.com")
    assert complete(client, q).status_code == 400
    assert vault.list_accounts() == []


@pytest.mark.parametrize("scope", ["", "https://www.googleapis.com/auth/gmail.modify"])
def test_missing_permissions_not_saved(client, headers, monkeypatch, scope):
    grant(monkeypatch, scope=scope)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 403
    assert vault.list_accounts() == []


def test_missing_offline_token_not_saved(client, headers, monkeypatch):
    grant(monkeypatch, refresh_token=None)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 400
    assert vault.list_accounts() == []


def test_reconnect_updates_same_account(client, headers, monkeypatch):
    grant(monkeypatch)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 200
    original_id = vault.list_accounts()[0]["id"]
    grant(monkeypatch, refresh_token="rotated-refresh")
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 200
    assert len(vault.list_accounts()) == 1
    assert vault.list_accounts()[0]["id"] == original_id
    assert vault.get_account(original_id)["config"]["refresh_token"] == "rotated-refresh"


def test_reconnect_without_new_refresh_keeps_old(client, headers, monkeypatch):
    grant(monkeypatch)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 200
    grant(monkeypatch, refresh_token=None)
    q, _ = begin(client, headers)
    assert complete(client, q).status_code == 200
    assert vault.get_account(vault.list_accounts()[0]["id"])["config"]["refresh_token"] == "sensitive-refresh"


def test_client_config_change_rejects_callback(client, headers, monkeypatch):
    exchange, _ = grant(monkeypatch)
    q, _ = begin(client, headers)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "different-client")
    assert complete(client, q).status_code == 400
    exchange.assert_not_called()


@pytest.mark.parametrize("origin", ["http://mail.example", "https://user:pass@mail.example", "https://mail.example/path", "https://mail.example/?x=1", "https://mail.example/#frag", "", "javascript:alert(1)"])
def test_invalid_public_origins_fail(monkeypatch, origin):
    monkeypatch.setenv("UNIVERSALMAIL_PUBLIC_URL", origin)
    with pytest.raises(provider.ProviderError):
        oauth.public_origin()


def test_localhost_http_requires_opt_in(monkeypatch):
    monkeypatch.setenv("UNIVERSALMAIL_PUBLIC_URL", "http://127.0.0.1:8000")
    with pytest.raises(provider.ProviderError):
        oauth.public_origin()
    monkeypatch.setenv("UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST", "true")
    assert oauth.public_origin() == "http://127.0.0.1:8000"


def test_no_manual_refresh_token_registration(client, headers):
    assert client.post("/accounts/native", headers=headers, json={"refresh_token": "do-not-echo"}).status_code == 410


def test_validation_does_not_echo_sensitive_body(client, headers):
    r = client.post("/oauth/gmail/start", headers=headers, json={"refresh_token": "do-not-echo"})
    assert r.status_code == 422 and "do-not-echo" not in r.text


def test_onboarding_page_has_no_storage_or_external_scripts(client):
    r = client.get("/connect")
    assert r.status_code == 200
    assert "localStorage" not in r.text and "sessionStorage" not in r.text
    assert "nonce-" in r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_status_reports_missing_configuration(client, headers, monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET")
    result = client.get("/oauth/status", headers=headers)
    assert result.json()["providers"]["gmail"]["configured"] is False
    assert result.json()["providers"]["outlook"]["configured"] is True
    assert client.post("/oauth/gmail/start", headers=headers, json={}).status_code == 503
