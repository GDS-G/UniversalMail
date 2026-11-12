import base64
from email import message_from_bytes
from email.policy import default
from unittest.mock import patch

import pytest
from universalmail import native_providers as native
from universalmail.main import OutboundMessage
from universalmail.provider_http import ProviderError

ACCOUNT = {"kind": "gmail", "email": "me@example.com", "config": {}}
FILTER = {"id": "filter123", "criteria": {"from": "sender@example.com"}, "action": {"removeLabelIds": ["SPAM"]}}


def test_gmail_safe_sender_documented_schema_verified():
    with patch.object(native, "authorized", side_effect=[{}, {"id": "filter123"}, FILTER]) as request:
        result = native.allowlist_sender(ACCOUNT, "sender@example.com")
    assert result["sender_allowlisted"] is True
    assert result["existing_messages_changed"] is False
    assert request.call_args_list[1].kwargs["json_body"]["action"] == {"removeLabelIds": ["SPAM"]}
    assert request.call_count == 3


def test_existing_safe_sender_filter_reused():
    with patch.object(native, "authorized", side_effect=[{"filter": [FILTER]}, FILTER]) as request:
        result = native.allowlist_sender(ACCOUNT, "sender@example.com")
    assert result["created"] is False
    assert all(x.args[1] == "GET" for x in request.call_args_list)


def test_unverified_safe_sender_not_reported_as_success():
    with patch.object(native, "authorized", side_effect=[{}, {"id": "filter123"}, {**FILTER, "action": {}}]):
        with pytest.raises(ProviderError, match="not verified"):
            native.allowlist_sender(ACCOUNT, "sender@example.com")


def test_outlook_safe_sender_is_not_faked():
    with patch.object(native, "authorized") as request:
        with pytest.raises(ProviderError) as exc:
            native.allowlist_sender({**ACCOUNT, "kind": "outlook"}, "sender@example.com")
    assert exc.value.status == 501
    request.assert_not_called()


@pytest.mark.parametrize("kind", ["outlook", "gmail"])
def test_native_mime_includes_bcc_and_html(kind):
    payload = OutboundMessage(to=["you@example.com"], bcc=["hidden@example.com"], subject="Test", html="<table><tr><td><b>Bold</b></td></tr></table>")
    with patch.object(native, "authorized", return_value={"id": "sent-id"}) as request:
        result = native.send({**ACCOUNT, "kind": kind}, payload)
    data = request.call_args.kwargs
    if kind == "outlook":
        msg = message_from_bytes(base64.b64decode(data["data"]), policy=default)
    else:
        value = data["json_body"]["raw"]
        msg = message_from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), policy=default)
    assert msg["Bcc"] == "hidden@example.com"
    assert "<table>" in msg.get_body(preferencelist=("html",)).get_content()
    assert result["delivered"] == "unverified"


def test_gmail_junk_listing_and_cursor():
    with patch.object(native, "authorized", return_value={"messages": [{"id": "1"}], "nextPageToken": "next"}) as request:
        result = native.messages(ACCOUNT, "SPAM", 30, "previous")
    assert request.call_args.kwargs["params"]["includeSpamTrash"] == "true"
    assert request.call_args.kwargs["params"]["pageToken"] == "previous"
    assert result["next_page_token"] == "next"


def test_graph_nested_folders_and_pagination():
    with patch.object(native, "authorized", return_value={"value": [], "@odata.nextLink": "next"}) as request:
        result = native.folders({**ACCOUNT, "kind": "outlook"}, "parent")
    assert request.call_args.args[2].endswith("/mailFolders/parent/childFolders")
    assert result["next_page_token"] == "next"


def test_graph_cursor_cannot_redirect_to_other_resource():
    with patch.object(native, "authorized") as request:
        with pytest.raises(ProviderError):
            native.messages({**ACCOUNT, "kind": "outlook"}, "INBOX", 10, "https://evil.example/messages")
    request.assert_not_called()


def test_not_spam_verifies_labels_but_does_not_claim_sender_trust():
    with patch.object(native, "authorized", side_effect=[{}, {"labelIds": ["INBOX"]}]):
        result = native.mark_not_spam(ACCOUNT, "message")
    assert result["message_not_spam"] and not result["sender_allowlisted"]


def test_not_spam_verification_failure():
    with patch.object(native, "authorized", side_effect=[{}, {"labelIds": ["SPAM"]}]):
        with pytest.raises(ProviderError):
            native.mark_not_spam(ACCOUNT, "message")


def test_move_does_not_add_and_remove_same_label():
    with patch.object(native, "authorized", side_effect=[{"labelIds": ["INBOX", "STARRED"]}, {}]) as request:
        native.move(ACCOUNT, "id", "INBOX")
    assert request.call_args.kwargs["json_body"] == {"removeLabelIds": [], "addLabelIds": ["INBOX"]}
