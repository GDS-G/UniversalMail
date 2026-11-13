"""Single-owner authenticated mail API. Live provider verification is still required."""
import os
from contextlib import asynccontextmanager
from email import message_from_bytes
from email.policy import default
from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Path, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, EmailStr, Field

from . import imap_smtp, native_providers, oauth, vault
from .auth import require_api_key as auth
from .mime import compose_message
from .provider_http import ProviderError
from .security import cipher, validate_mail_hostname
from .onboarding import router as onboarding_router
from .setup_routes import router as setup_router
from .setup_page import router as setup_page_router


@asynccontextmanager
async def lifespan(app):
    cipher()
    key = os.getenv("UNIVERSALMAIL_API_KEY", "")
    if len(key) < 32 or key.startswith("replace-"):
        raise RuntimeError("Set a random UNIVERSALMAIL_API_KEY of at least 32 characters")
    yield


app = FastAPI(title="Universal Mail & Calendar", version="0.5.0", lifespan=lifespan,
              description="Development-stage single-owner gateway; not production certified.")
app.include_router(oauth.router)
app.include_router(onboarding_router)
app.include_router(setup_router)
app.include_router(setup_page_router)
Uid = Annotated[int, Path(gt=0)]


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # FastAPI's default response can echo submitted passwords/tokens in `input`.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": list(x["loc"]), "type": x["type"], "msg": x["msg"]} for x in exc.errors()]})


@app.middleware("http")
async def private_responses(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


class CustomAccount(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    imap_host: str
    imap_port: int = Field(default=993, ge=1, le=65535)
    smtp_host: str
    smtp_port: int = Field(default=465, ge=1, le=65535)
    smtp_security: Literal["ssl", "starttls"] = "ssl"


class NativeMove(BaseModel):
    message_id: str = Field(min_length=1)
    destination: str = Field(min_length=1)


class SenderAllowlist(BaseModel):
    sender: EmailStr


class NativeRead(BaseModel):
    read: bool


class Attachment(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_type: str | None = None
    content_base64: str


class OutboundMessage(BaseModel):
    to: list[EmailStr] = Field(min_length=1, max_length=100)
    cc: list[EmailStr] = Field(default_factory=list, max_length=100)
    bcc: list[EmailStr] = Field(default_factory=list, max_length=100)
    subject: str = Field(max_length=998)
    text: str = ""
    html: str | None = None
    attachments: list[Attachment] = Field(default_factory=list, max_length=25)
    in_reply_to: str | None = None
    references: str | None = None


class FlagUpdate(BaseModel):
    flag: Literal["seen", "flagged"]
    enabled: bool


class MoveRequest(BaseModel):
    source_folder: str
    destination_folder: str
    uid: int = Field(gt=0)


def guarded(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ProviderError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    except LookupError:
        raise HTTPException(404, "Requested provider item not found") from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:
        raise HTTPException(502, "Provider operation failed; writes may have an unknown outcome; do not blindly retry") from None


native_guarded = guarded


def load_account(account_id: str, kinds: tuple[str, ...]):
    record = vault.get_account(account_id)
    if record is None:
        raise HTTPException(404, "Account not found")
    if record["kind"] not in kinds:
        raise HTTPException(400, "Wrong account type for this route")
    return record


def load_custom(account_id: str):
    return load_account(account_id, ("custom",))


def load_native(account_id: str):
    return load_account(account_id, ("gmail", "outlook"))


@app.get("/health")
def health():
    return {"status": "ok", "service": "universalmail", "version": app.version,
            "provider_connectivity": "not_checked"}


@app.get("/capabilities", dependencies=[Depends(auth)])
def capabilities():
    return {"custom_imap_smtp": {
        "folders": True, "list_messages": True, "read_messages": True,
        "raw_rfc822": True, "attachments_download": True, "send_html_mime": True,
        "attachments_send": True, "flags": True, "move": "requires_MOVE_or_UIDPLUS",
        "sender_allowlist": False, "spam_report": False, "phishing_report": False,
        "calendar": False, "cross_provider_move": False, "paginated_inventory": False},
        "outlook_graph": {"implemented": True, "mail_read": True, "mail_send": True,
            "move": True, "sender_allowlist": False, "phishing_report": False, "calendar": False},
        "gmail_api": {"implemented": True, "mail_read": True, "mail_send": True, "move": True,
            "message_not_spam": True, "sender_allowlist": True, "phishing_report": False, "calendar": False},
        "oauth_browser_login": True, "live_provider_tests": False, "production_ready": False,
        "mcp_connected": False, "authorization_model": "single_owner"}


@app.post("/accounts/custom", dependencies=[Depends(auth)], status_code=201)
def add_custom(payload: CustomAccount):
    guarded(validate_mail_hostname, payload.imap_host, payload.imap_port)
    guarded(validate_mail_hostname, payload.smtp_host, payload.smtp_port)
    config = payload.model_dump(mode="json", exclude={"name", "email"})
    account_id = vault.add_account(payload.name, str(payload.email), "custom", config)
    return {"id": account_id, "email": payload.email, "kind": "custom", "connected": False,
            "note": "Saved encrypted; connection not yet verified"}


@app.post("/accounts/native", dependencies=[Depends(auth)])
def add_native():
    raise HTTPException(410, "Manual token registration removed; connect through /connect using provider sign-in")


@app.get("/accounts", dependencies=[Depends(auth)])
def accounts():
    return vault.list_accounts()


@app.delete("/accounts/{account_id}", dependencies=[Depends(auth)])
def delete_account(account_id: str):
    if not vault.delete_account(account_id):
        raise HTTPException(404, "Account not found")
    return {"deleted": True, "provider_consent_revoked": False}


@app.get("/accounts/{account_id}/folders", dependencies=[Depends(auth)])
def folders(account_id: str):
    return guarded(imap_smtp.list_folders, load_custom(account_id)["config"])


@app.get("/accounts/{account_id}/messages", dependencies=[Depends(auth)])
def messages(account_id: str, folder: str = "INBOX", limit: int = Query(default=30, ge=1, le=100)):
    return guarded(imap_smtp.list_messages, load_custom(account_id)["config"], folder, limit)


def custom_raw(account_id, folder, uid):
    return guarded(imap_smtp.raw_message, load_custom(account_id)["config"], folder, uid)


@app.get("/accounts/{account_id}/messages/{uid}/raw", dependencies=[Depends(auth)])
def raw(account_id: str, uid: Uid, folder: str = "INBOX"):
    return Response(custom_raw(account_id, folder, uid), media_type="message/rfc822",
                    headers={"Content-Disposition": 'attachment; filename="message.eml"'})


@app.get("/accounts/{account_id}/messages/{uid}", dependencies=[Depends(auth)])
def message(account_id: str, uid: Uid, folder: str = "INBOX"):
    msg = message_from_bytes(custom_raw(account_id, folder, uid), policy=default)
    plain, html, attachments = [], [], []
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename() or part.get("Content-ID"):
            attachments.append({"part_index": i, "filename": part.get_filename(),
                "content_type": part.get_content_type(), "content_id": part.get("Content-ID")})
        elif part.get_content_type() == "text/plain":
            plain.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html.append(part.get_content())
    return {"from": str(msg.get("From", "")), "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")), "message_id": str(msg.get("Message-ID", "")),
            "date": str(msg.get("Date", "")), "text": "\n".join(plain), "html": "\n".join(html),
            "attachments": attachments, "content_trust": "untrusted_email"}


@app.get("/accounts/{account_id}/messages/{uid}/attachments/{part_index}", dependencies=[Depends(auth)])
def attachment(account_id: str, uid: Uid, part_index: int, folder: str = "INBOX"):
    parts = list(message_from_bytes(custom_raw(account_id, folder, uid), policy=default).walk())
    if part_index < 0 or part_index >= len(parts):
        raise HTTPException(404, "Attachment not found")
    part = parts[part_index]
    if part.is_multipart() or not (part.get_filename() or part.get("Content-ID") or part.get_content_disposition() == "attachment"):
        raise HTTPException(404, "Attachment not found")
    filename = (part.get_filename() or "attachment.bin").replace("\\", "/").split("/")[-1]
    return Response(part.get_payload(decode=True) or b"", media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=\"attachment.bin\"; filename*=UTF-8''" + quote(filename, safe="")})


@app.post("/accounts/{account_id}/send", dependencies=[Depends(auth)])
def send(account_id: str, payload: OutboundMessage):
    account = load_custom(account_id)
    raw_bytes, recipients = guarded(compose_message, account["email"], [str(x) for x in payload.to],
        payload.subject, payload.text, payload.html, [str(x) for x in payload.cc],
        [str(x) for x in payload.bcc], [x.model_dump() for x in payload.attachments],
        payload.in_reply_to, payload.references)
    return guarded(imap_smtp.send_message, account["config"], raw_bytes, recipients, account["email"])


@app.patch("/accounts/{account_id}/messages/{uid}/flags", dependencies=[Depends(auth)])
def flags(account_id: str, uid: Uid, payload: FlagUpdate, folder: str = "INBOX"):
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
    raise HTTPException(501, "Persistent sender allowlisting is not implemented for generic IMAP; no folder move was substituted")


@app.post("/accounts/{account_id}/report-phishing", dependencies=[Depends(auth)])
def phishing(account_id: str):
    load_custom(account_id)
    raise HTTPException(501, "Provider-specific phishing reporting not implemented; message was not reported")


@app.get("/native/{account_id}/folders", dependencies=[Depends(auth)])
def native_folders(account_id: str, parent: str | None = None, cursor: str | None = Query(default=None, max_length=8192)):
    return guarded(native_providers.folders, load_native(account_id), parent, cursor)


@app.get("/native/{account_id}/messages", dependencies=[Depends(auth)])
def native_messages(account_id: str, folder: str = "INBOX", limit: int = Query(default=30, ge=1, le=100), cursor: str | None = Query(default=None, max_length=8192)):
    return guarded(native_providers.messages, load_native(account_id), folder, limit, cursor)


@app.get("/native/{account_id}/messages/{message_id}", dependencies=[Depends(auth)])
def native_message(account_id: str, message_id: str):
    return guarded(native_providers.message, load_native(account_id), message_id)


@app.get("/native/{account_id}/messages/{message_id}/raw", dependencies=[Depends(auth)])
def native_raw(account_id: str, message_id: str):
    return Response(guarded(native_providers.raw, load_native(account_id), message_id), media_type="message/rfc822",
                    headers={"Content-Disposition": 'attachment; filename="message.eml"'})


@app.post("/native/{account_id}/send", dependencies=[Depends(auth)])
def native_send(account_id: str, payload: OutboundMessage):
    return guarded(native_providers.send, load_native(account_id), payload)


@app.patch("/native/{account_id}/messages/{message_id}/read", dependencies=[Depends(auth)])
def native_read(account_id: str, message_id: str, payload: NativeRead):
    return guarded(native_providers.set_read, load_native(account_id), message_id, payload.read)


@app.post("/native/{account_id}/move", dependencies=[Depends(auth)])
def native_move(account_id: str, payload: NativeMove):
    return guarded(native_providers.move, load_native(account_id), payload.message_id, payload.destination)


@app.post("/native/{account_id}/messages/{message_id}/not-spam", dependencies=[Depends(auth)])
def native_not_spam(account_id: str, message_id: str):
    return guarded(native_providers.mark_not_spam, load_native(account_id), message_id)


@app.post("/native/{account_id}/safe-senders", dependencies=[Depends(auth)])
def native_safe_senders(account_id: str, payload: SenderAllowlist):
    return guarded(native_providers.allowlist_sender, load_native(account_id), str(payload.sender))


@app.post("/native/{account_id}/report-phishing", dependencies=[Depends(auth)])
def native_phishing(account_id: str):
    load_native(account_id)
    raise HTTPException(501, "Provider-specific phishing reporting not implemented; message was not reported")
