from unittest.mock import patch
from universalmail import native_providers


def test_gmail_safe_sender_requires_verified_filter():
    account = {"kind": "gmail", "email": "me@example.com", "config": {"refresh_token": "placeholder"}}
    with patch.object(native_providers, "authorized", side_effect=[
        {"id": "filter123"},
        {"criteria": {"from": "sender@example.com"}, "action": {"neverSpam": True}}
    ]) as request:
        result = native_providers.allowlist_sender(account, "sender@example.com")
    assert result["sender_allowlisted"] is True
    assert request.call_count == 2


def test_outlook_safe_sender_is_not_faked():
    account = {"kind": "outlook", "email": "me@example.com", "config": {}}
    try:
        native_providers.allowlist_sender(account, "sender@example.com")
    except Exception as exc:
        assert getattr(exc, "status", None) == 501
    else:
        raise AssertionError("Outlook must not claim Safe Senders support")
