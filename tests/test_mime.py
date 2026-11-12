import base64
from email import message_from_bytes
from email.policy import default
from universalmail.mime import compose_message


def test_html_attachment_and_hidden_bcc():
    raw, recipients = compose_message(
        "me@example.com", ["you@example.com"], "Hello",
        "Plain", "<table><tr><td><b>Bold</b></td></tr></table>",
        bcc=["hidden@example.com"],
        attachments=[{"filename":"hello.txt", "content_base64":base64.b64encode(b"abc").decode()}])
    msg = message_from_bytes(raw, policy=default)
    assert msg["Bcc"] is None
    assert "hidden@example.com" in recipients
    assert msg.get_body(preferencelist=("html",)).get_content().startswith("<table>")
    assert len(list(msg.iter_attachments())) == 1
