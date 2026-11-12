"""Authenticated REST interface. Provider claims are intentionally capability-gated."""
import base64
import os
from email import message_from_bytes
from email.policy import default
from typing import Literal

from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr, Field
import secrets

from . import imap_smtp, vault, native_providers
from .provider_http import ProviderError
from .mime import compose_message
from .security import cipher, validate_mail_hostname


app = FastAPI(title="Universal Mail & Calendar", version="0.3.0", description="Development-stage provider-neutral mail gateway.")


def auth(x_api_key: str | None = Header(default=None)):
    expected = os.getenv("UNIVERSALMAIL_API_KEY", "")
    if not expected or len(expected) < 24 or not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise HTTPException(401, "Valid X-API-Key required")


class CustomAccount(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    imap_host: str
    imap_port: int = 993
    smtp_host: str
    smtp_port: int = 465
    smtp_security: Literal["ssl", "starttls"] = "ssl"


class NativeAccount(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    kind: Literal["gmail", "outlook"]
    refresh_token: str = Field(min_length=8)


class NativeMove(BaseModel):
    message_id: str
    destination: str


class SenderAllowlist(BaseModel):
    sender: EmailStr


class NativeRead(BaseModel):
    read: bool


class Attachment(BaseModel):
    filename: str
    content_type: str | None = None
    content_base64: str


class OutboundMessage(BaseModel):
    to: list[EmailStr] = Field(min_length=1)
    cc: list[EmailStr] = []
    bcc: list[EmailStr] = []
    subject: str
    text: str = ""
    html: str | None = None
    attachments: list[Attachment] = []
    in_reply_to: str | None = None
    references: str | None = None


class FlagUpdate(BaseModel):
    flag: Literal["seen", "flagged"]
    enabled: bool


class MoveRequest(BaseModel):
    source_folder: str
    destination_folder: str
    uid: int = Field(gt=0)


@app.on_event("startup")
def startup():
    cipher()


@app.get("/health")
def health():
    return {"status": "ok", "service": "universalmail", "version": "0.3.0"}


@app.get("/capabilities", dependencies=[Depends(auth)])
def capabilities():
    return {"custom_imap_smtp": {
        "folders": True, "list_messages": True, "read_messages": True,
        "raw_rfc822": True, "attachments_download": True, "send_html_mime": True,
        "attachments_send": True, "flags": True, "move": True,
        "sender_allowlist": False, "spam_report": False, "phishing_report": False,
        "calendar": False, "cross_provider_move": False
    }, "outlook_graph": {"implemented": True, "mail_read": True, "mail_send": True, "move": True,
        "sender_allowlist": False, "phishing_report": False, "calendar": False},
        "gmail_api": {"implemented": True, "mail_read": True, "mail_send": True, "move": True,
        "message_not_spam": True, "sender_allowlist": True, "phishing_report": False, "calendar": False},
        "oauth_browser_login": False, "production_ready": False}


@app.post("/accounts/custom", dependencies=[Depends(auth)], status_code=201)
def add_custom(payload: CustomAccount):
    try:
        validate_mail_hostname(payload.imap_host, payload.imap_port)
        validate_mail_hostname(payload.smtp_host, payload.smtp_port)
        config = payload.model_dump(mode="json", exclude={"name", "email"})
        account_id = vault.add_account(payload.name, str(payload.email), "custom", config)
        return {"id": account_id, "email": payload.email, "kind": "custom", "connected": False,
                "note": "Saved encrypted; connection will be verified on first mailbox operation"}
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc))


@app.post("/accounts/native", dependencies=[Depends(auth)], status_code=201)
def add_native(payload: NativeAccount):
    # Development-only onboarding. OAuth browser consent flow is not implemented.
    account_id = vault.add_account(payload.name, str(payload.email), payload.kind,
                                   {"refresh_token": payload.refresh_token})
    return {"id": account_id, "kind": payload.kind, "connected": False,
            "note": "Refresh token encrypted; live provider access not yet verified"}


@app.get("/accounts", dependencies=[Depends(auth)])
def accounts():
    return vault.list_accounts()


@app.delete("/accounts/{account_id}", dependencies=[Depends(auth)])
def delete_account(account_id: str):
    if not vault.delete_account(account_id):
        raise HTTPException(404, "Account not found")
    return {"deleted": True}


def load_native(account_id: str) -> dict:
    record = vault.get_account(account_id)
    if record is None:
        raise HTTPException(404, "Account not found")
    if record["kind"] not in ("gmail", "outlook"):
        raise HTTPException(400, "Not a native provider account")
    return record


def native_guarded(fn, *args):
    try:
        return fn(*args)
    except ProviderError as exc:
        raise HTTPException(exc.status, exc.detail)
    except (ValueError, KeyError) as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "Native provider operation failed") from None


def load_custom(account_id: str) -> dict:
    record = vault.get_account(account_id)
    if record is None:
        raise HTTPException(404, "Account not found")
    if record["kind"] != "custom":
        raise HTTPException(501, "Provider adapter not implemented")
    return record


def guarded(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ValueError, LookupError) as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "Mail provider operation failed; consult server logs") from None


@app.get("/accounts/{account_id}/folders", dependencies=[Depends(auth)])
def folders(account_id: str):
    return guarded(imap_smtp.list_folders, load_custom(account_id)["config"])


@app.get("/accounts/{account_id}/messages", dependencies=[Depends(auth)])
def messages(account_id: str, folder: str = "INBOX", limit: int = 30):
    if not 1 <= limit <= 100:
        raise HTTPException(400, "limit must be between 1 and 100")
    return guarded(imap_smtp.list_messages, load_custom(account_id)["config"], folder, limit)


@app.get("/accounts/{account_id}/messages/{uid}/raw", dependencies=[Depends(auth)])
def raw(account_id: str, uid: int, folder: str = "INBOX"):
    data = guarded(imap_smtp.raw_message, load_custom(account_id)["config"], folder, uid)
    return Response(data, media_type="message/rfc822", headers={"Content-Disposition": 'attachment; filename="message.eml"'})


@app.get("/accounts/{account_id}/messages/{uid}", dependencies=[Depends(auth)])
def message(account_id: str, uid: int, folder: str = "INBOX"):
    raw_bytes = guarded(imap_smtp.raw_message, load_custom(account_id)["config"], folder, uid)
    msg = message_from_bytes(raw_bytes, policy=default)
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    plain = []; html = []; attachments = []
    for i, part in enumerate(parts):
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            attachments.append({"part_index": i, "filename": part.get_filename(), "content_type": part.get_content_type()})
        elif part.get_content_type() == "text/plain":
            plain.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html.append(part.get_content())
    return {"from": str(msg.get("From", "")), "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")), "message_id": str(msg.get("Message-ID", "")),
            "date": str(msg.get("Date", "")), "text": "\n".join(plain),
            "html": "\n".join(html), "attachments": attachments}


@app.get("/accounts/{account_id}/messages/{uid}/attachments/{part_index}", dependencies=[Depends(auth)])
def attachment(account_id: str, uid: int, part_index: int, folder: str = "INBOX"):
    raw_bytes = guarded(imap_smtp.raw_message, load_custom(account_id)["config"], folder, uid)
    msg = message_from_bytes(raw_bytes, policy=default)
    parts = list(msg.walk()) if msg.is_multipart() else [msg]
    if part_index < 0 or part_index >= len(parts) or parts[part_index].get_content_disposition() != "attachment":
        raise HTTPException(404, "Attachment not found")
    part = parts[part_index]
    return Response(part.get_payload(decode=True), media_type="application/octet-stream",
                    headers={"Content-Disposition": 'attachment; filename="attachment.bin"'})


@app.post("/accounts/{account_id}/send", dependencies=[Depends(auth)])
def send(account_id: str, payload: OutboundMessage):
    account = load_custom(account_id)
    try:
        raw_bytes, all_recipients = compose_message(
            account["email"], [str(x) for x in payload.to], payload.subject, payload.text, payload.html,
            [str(x) for x in payload.cc], [str(x) for x in payload.bcc],
            [x.model_dump() for x in payload.attachments], payload.in_reply_to, payload.references)
    except (ValueError, KeyError) as exc:
        raise HTTPException(400, str(exc))
    guarded(imap_smtp.send_message, account["config"], raw_bytes, all_recipients, account["email"])
    return {"submitted_to_smtp": True, "delivered": "unverified"}


@app.patch("/accounts/{account_id}/messages/{uid}/flags", dependencies=[Depends(auth)])
def flags(account_id: str, uid: int, payload: FlagUpdate, folder: str = "INBOX"):
    guarded(imap_smtp.set_flag, load_custom(account_id)["config"], folder, uid,
            "\\Seen" if payload.flag == "seen" else "\\Flagged", payload.enabled)
    return {"updated": True}


@app.post("/accounts/{account_id}/move", dependencies=[Depends(auth)])
def move(account_id: str, payload: MoveRequest):
    guarded(imap_smtp.move_message, load_custom(account_id)["config"],
            payload.source_folder, payload.destination_folder, payload.uid)
    return {"moved": True, "spam_reclassification": False, "sender_allowlisted": False}


@app.post("/accounts/{account_id}/safe-senders", dependencies=[Depends(auth)])
def safe_senders(account_id: str):
    load_custom(account_id)
    raise HTTPException(501, "Persistent sender allowlisting requires a verified provider-specific mechanism; generic IMAP folder moves are insufficient")


@app.post("/accounts/{account_id}/report-phishing", dependencies=[Depends(auth)])
def phishing(account_id: str):
    load_custom(account_id)
    raise HTTPException(501, "Provider-specific phishing reporting not implemented; message was not reported")


@app.get("/native/{account_id}/folders", dependencies=[Depends(auth)])
def native_folders(account_id: str):
    return native_guarded(native_providers.folders, load_native(account_id))


@app.get("/native/{account_id}/messages", dependencies=[Depends(auth)])
def native_messages(account_id: str, folder: str = "INBOX", limit: int = 30):
    if not 1 <= limit <= 100:
        raise HTTPException(400, "limit must be between 1 and 100")
    return native_guarded(native_providers.messages, load_native(account_id), folder, limit)


@app.get("/native/{account_id}/messages/{message_id}", dependencies=[Depends(auth)])
def native_message(account_id: str, message_id: str):
    return native_guarded(native_providers.message, load_native(account_id), message_id)


@app.get("/native/{account_id}/messages/{message_id}/raw", dependencies=[Depends(auth)])
def native_raw(account_id: str, message_id: str):
    content = native_guarded(native_providers.raw, load_native(account_id), message_id)
    return Response(content, media_type="message/rfc822")


@app.post("/native/{account_id}/send", dependencies=[Depends(auth)])
def native_send(account_id: str, payload: OutboundMessage):
    return native_guarded(native_providers.send, load_native(account_id), payload)


@app.patch("/native/{account_id}/messages/{message_id}/read", dependencies=[Depends(auth)])
def native_read(account_id: str, message_id: str, payload: NativeRead):
    return native_guarded(native_providers.set_read, load_native(account_id), message_id, payload.read)


@app.post("/native/{account_id}/move", dependencies=[Depends(auth)])
def native_move(account_id: str, payload: NativeMove):
    return native_guarded(native_providers.move, load_native(account_id), payload.message_id, payload.destination)


@app.post("/native/{account_id}/messages/{message_id}/not-spam", dependencies=[Depends(auth)])
def native_not_spam(account_id: str, message_id: str):
    return native_guarded(native_providers.mark_not_spam, load_native(account_id), message_id)


@app.post("/native/{account_id}/safe-senders", dependencies=[Depends(auth)])
def native_safe_senders(account_id: str, payload: SenderAllowlist):
    return native_guarded(native_providers.allowlist_sender, load_native(account_id), str(payload.sender))
