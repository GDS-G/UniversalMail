import json
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from unittest.mock import Mock, MagicMock, patch

import pytest
import httpx
from universalmail import imap_smtp, provider_http as provider, vault
from universalmail.security import encrypt_secret, validate_mail_hostname


def account(config=None):
    cfg = {"client_id": "test-client", "refresh_token": "original-refresh", "expires_at": 0}
    cfg.update(config or {})
    return vault.get_account(vault.add_account("Test", "owner@example.com", "gmail", cfg))


def test_rotated_refresh_token_persisted_before_api_call(monkeypatch):
    record = account()
    refresh = Mock(return_value={"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600})
    monkeypatch.setattr(provider, "refresh_token", refresh)
    def request(*args, **kwargs):
        saved = vault.get_account(record["id"])["config"]
        assert saved["refresh_token"] == "new-refresh"
        assert args[2] == "new-access"
        return {}
    monkeypatch.setattr(provider, "_request", request)
    provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    refresh.assert_called_once()


def test_omitted_rotated_refresh_token_retains_original(monkeypatch):
    record = account()
    monkeypatch.setattr(provider, "refresh_token", Mock(return_value={"access_token": "access", "expires_in": 3600}))
    monkeypatch.setattr(provider, "_request", Mock(return_value={}))
    provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    assert vault.get_account(record["id"])["config"]["refresh_token"] == "original-refresh"


def test_unexpired_cached_token_not_refreshed(monkeypatch):
    record = account({"access_token": "cached", "expires_at": time.time() + 3600})
    refresh = Mock()
    monkeypatch.setattr(provider, "refresh_token", refresh)
    monkeypatch.setattr(provider, "_request", Mock(return_value={}))
    provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    refresh.assert_not_called()


def test_parallel_requests_only_refresh_once(monkeypatch):
    record = account()
    def rotate(*args):
        time.sleep(0.02)
        return {"access_token": "new", "refresh_token": "rotated", "expires_in": 3600}
    refresh = Mock(side_effect=rotate)
    monkeypatch.setattr(provider, "refresh_token", refresh)
    monkeypatch.setattr(provider, "_request", Mock(return_value={}))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile"), range(4)))
    assert results == [{}, {}, {}, {}]
    refresh.assert_called_once()


def test_refresh_failure_preserves_stored_credentials(monkeypatch):
    record = account()
    monkeypatch.setattr(provider, "refresh_token", Mock(side_effect=provider.ProviderError(401, "Reconnect")))
    with pytest.raises(provider.ProviderError):
        provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    assert vault.get_account(record["id"])["config"]["refresh_token"] == "original-refresh"


@pytest.mark.parametrize("url", ["https://evil.example/gmail/v1/test", "http://gmail.googleapis.com/gmail/v1/test", "https://gmail.googleapis.com@evil.example/gmail/v1/test", "https://gmail.googleapis.com/gmail/v1/test#fragment"])
def test_tokens_not_sent_to_untrusted_urls(monkeypatch, url):
    request = Mock()
    monkeypatch.setattr(provider, "_request", request)
    with pytest.raises(provider.ProviderError):
        provider.authorized(account(), "GET", url)
    request.assert_not_called()


def test_changed_client_requires_reconnect(monkeypatch):
    record = account({"client_id": "old-client"})
    refresh = Mock()
    monkeypatch.setattr(provider, "refresh_token", refresh)
    with pytest.raises(provider.ProviderError, match="client changed"):
        provider.authorized(record, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile")
    refresh.assert_not_called()


def test_old_schema_migrated_without_losing_credentials():
    con = sqlite3.connect(os.environ["UNIVERSALMAIL_DB_PATH"])
    con.execute("CREATE TABLE accounts(id TEXT PRIMARY KEY,name TEXT,email TEXT,kind TEXT,secrets TEXT)")
    con.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", ("old", "Old", "old@example.com", "custom", encrypt_secret(json.dumps({"password": "unchanged"}))))
    con.commit()
    con.close()
    assert vault.get_account("old")["config"]["password"] == "unchanged"


def fake_imap(monkeypatch, caps, responses):
    conn = Mock()
    conn.capabilities = caps
    conn.select.return_value = ("OK", [b"1"])
    conn.uid.side_effect = responses
    monkeypatch.setattr(imap_smtp, "imap_connection", lambda cfg: nullcontext(conn))
    return conn


def test_imap_move_recognizes_byte_capabilities(monkeypatch):
    conn = fake_imap(monkeypatch, (b"IMAP4REV1", b"MOVE"), [("OK", [b"12"]), ("OK", [None])])
    imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert conn.uid.call_args.args[0] == "MOVE"
    conn.expunge.assert_not_called()


def test_imap_fallback_expunge_only_requested_uid(monkeypatch):
    conn = fake_imap(monkeypatch, (b"UIDPLUS",), [("OK", [b"12"])] + [("OK", [None])] * 3)
    imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert conn.uid.call_args.args == ("EXPUNGE", "12")
    conn.expunge.assert_not_called()


def test_imap_unsupported_safe_move_does_not_copy_or_delete(monkeypatch):
    conn = fake_imap(monkeypatch, (b"IMAP4REV1",), [])
    with pytest.raises(provider.ProviderError) as exc:
        imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert exc.value.status == 501
    conn.uid.assert_not_called()
    conn.expunge.assert_not_called()


def test_missing_imap_uid_not_reported_moved(monkeypatch):
    conn = fake_imap(monkeypatch, (b"MOVE",), [("OK", [b""])])
    with pytest.raises(LookupError):
        imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert conn.uid.call_count == 1


def test_imap_copy_failure_never_marks_source_deleted(monkeypatch):
    conn = fake_imap(monkeypatch, (b"UIDPLUS",), [("OK", [b"12"]), ("NO", [b"failure"])])
    with pytest.raises(RuntimeError):
        imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert [call.args[0] for call in conn.uid.call_args_list] == ["SEARCH", "COPY"]


def test_imap_partial_move_reported_not_silent_success(monkeypatch):
    fake_imap(monkeypatch, (b"UIDPLUS",), [("OK", [b"12"]), ("OK", [None]), ("NO", [b"failure"])])
    with pytest.raises(provider.ProviderError) as exc:
        imap_smtp.move_message({}, "INBOX", "Archive", 12)
    assert exc.value.status == 409


def test_smtp_partial_acceptance_exposed(monkeypatch):
    monkeypatch.setattr(imap_smtp, "validate_mail_hostname", lambda *args: None)
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    smtp.sendmail.return_value = {"bad@example.com": (550, b"refused")}
    with patch.object(imap_smtp.smtplib, "SMTP_SSL", return_value=smtp):
        result = imap_smtp.send_message({"smtp_host": "mail.example.com", "smtp_port": 465,
            "smtp_security": "ssl", "username": "test", "password": "test"}, b"mime", ["good@example.com", "bad@example.com"], "owner@example.com")
    assert result["accepted_recipients"] == ["good@example.com"]
    assert result["refused_recipients"] == ["bad@example.com"]
    assert result["retry_safe"] is False


def test_dns_private_address_rejected(monkeypatch):
    monkeypatch.setattr("universalmail.security.socket.getaddrinfo", lambda *a, **k: [(None,None,None,None,("127.0.0.1",993))])
    with pytest.raises(ValueError, match="non-public"):
        validate_mail_hostname("mail.example.com", 993)


@pytest.mark.parametrize("http_status", [401, 403, 429, 500, 302])
def test_provider_errors_redacted_and_not_retried(monkeypatch, http_status):
    response = httpx.Response(http_status, json={"error": "sensitive-token-must-not-leak"})
    client = Mock()
    client.request.return_value = response
    monkeypatch.setattr(provider.httpx, "Client", lambda **kwargs: nullcontext(client))
    with pytest.raises(provider.ProviderError) as exc:
        provider._request("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", "private-token")
    assert "sensitive-token" not in exc.value.detail
    client.request.assert_called_once()


def test_weak_api_key_rejected(client, monkeypatch):
    monkeypatch.setenv("UNIVERSALMAIL_API_KEY", "short")
    assert client.get("/accounts", headers={"X-API-Key": "short"}).status_code == 401


def test_api_state_mutation_requires_auth(client):
    assert client.post("/native/unknown/send", json={}).status_code == 401
    assert client.delete("/accounts/unknown").status_code == 401


def test_health_does_not_claim_live_provider_validation(client):
    assert client.get("/health").json()["provider_connectivity"] == "not_checked"
