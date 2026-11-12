"""HTML/plain-text MIME; SMTP envelopes and provider-MIME Bcc are distinct."""
import base64
import mimetypes
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid


def compose_message(sender: str, recipients: list[str], subject: str,
                    text: str = "", html: str | None = None,
                    cc: list[str] | None = None, bcc: list[str] | None = None,
                    attachments: list[dict] | None = None,
                    in_reply_to: str | None = None, references: str | None = None,
                    *, include_bcc_header: bool = False) -> tuple[bytes, list[str]]:
    if not recipients:
        raise ValueError("At least one recipient required")
    msg = EmailMessage(policy=SMTP)
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    if cc:
        msg["Cc"] = ", ".join(cc)
    # Native MIME APIs derive recipients from headers. SMTP uses a separate envelope.
    if bcc and include_bcc_header:
        msg["Bcc"] = ", ".join(bcc)
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid()
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg.set_content(text or "")
    if html is not None:
        msg.add_alternative(html, subtype="html")
    total = 0
    for att in attachments or []:
        content = base64.b64decode(att["content_base64"], validate=True)
        total += len(content)
        if total > 20 * 1024 * 1024:
            raise ValueError("Combined attachments must be <= 20 MiB; providers may impose smaller limits")
        ctype = att.get("content_type") or mimetypes.guess_type(att["filename"])[0] or "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=att["filename"])
    return msg.as_bytes(), list(dict.fromkeys([*recipients, *(cc or []), *(bcc or [])]))
