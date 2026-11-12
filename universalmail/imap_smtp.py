"""Generic IMAP/SMTP adapter. IMAP does not guarantee provider spam training."""
import email
import imaplib
import smtplib
import ssl
from contextlib import contextmanager
from email.policy import default

from .security import validate_mail_hostname


def _imap_mailbox(name: str) -> str:
    if not name or "\r" in name or "\n" in name or '"' in name or "\\" in name:
        raise ValueError("Invalid IMAP mailbox")
    return '"' + name + '"'


@contextmanager
def imap_connection(cfg: dict):
    host, port = cfg["imap_host"], cfg["imap_port"]
    validate_mail_hostname(host, port)
    if port == 993:
        conn = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=20)
    else:
        conn = imaplib.IMAP4(host, port, timeout=20)
        if "STARTTLS" not in conn.capabilities:
            conn.logout()
            raise ValueError("IMAP server does not support STARTTLS")
        conn.starttls(ssl_context=ssl.create_default_context())
    try:
        conn.login(cfg["username"], cfg["password"])
        yield conn
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _select(conn, folder: str, readonly: bool):
    typ, payload = conn.select(_imap_mailbox(folder), readonly=readonly)
    if typ != "OK":
        raise ValueError("Could not open IMAP folder")
    return int(payload[0])


def list_folders(cfg: dict):
    with imap_connection(cfg) as conn:
        typ, data = conn.list()
        if typ != "OK":
            raise RuntimeError("IMAP LIST failed")
        return [x.decode(errors="replace") for x in (data or []) if x]


def list_messages(cfg: dict, folder: str = "INBOX", limit: int = 30):
    with imap_connection(cfg) as conn:
        _select(conn, folder, True)
        typ, data = conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise RuntimeError("IMAP SEARCH failed")
        uids = data[0].split()[-limit:]
        result = []
        for uid in reversed(uids):
            typ, items = conn.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)] FLAGS)")
            if typ != "OK":
                continue
            header = next((item[1] for item in items if isinstance(item, tuple)), b"")
            msg = email.message_from_bytes(header, policy=default)
            result.append({"uid": uid.decode(), "from": str(msg.get("From", "")),
                           "to": str(msg.get("To", "")), "subject": str(msg.get("Subject", "")),
                           "date": str(msg.get("Date", "")), "message_id": str(msg.get("Message-ID", ""))})
        return result


def raw_message(cfg: dict, folder: str, uid: int) -> bytes:
    with imap_connection(cfg) as conn:
        _select(conn, folder, True)
        typ, items = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
        if typ != "OK":
            raise LookupError("Could not fetch message")
        data = next((item[1] for item in items if isinstance(item, tuple)), None)
        if not data:
            raise LookupError("Message not found")
        return data


def set_flag(cfg: dict, folder: str, uid: int, flag: str, enabled: bool):
    if flag not in ("\\Seen", "\\Flagged"):
        raise ValueError("Unsupported flag")
    with imap_connection(cfg) as conn:
        _select(conn, folder, False)
        typ, _ = conn.uid("STORE", str(uid), "+FLAGS.SILENT" if enabled else "-FLAGS.SILENT", "(" + flag + ")")
        if typ != "OK":
            raise RuntimeError("IMAP flag modification failed")


def move_message(cfg: dict, source: str, dest: str, uid: int):
    with imap_connection(cfg) as conn:
        _select(conn, source, False)
        # MOVE is atomic where supported; fallback COPY + deletion only after COPY success.
        if "MOVE" in conn.capabilities:
            typ, _ = conn.uid("MOVE", str(uid), _imap_mailbox(dest))
            if typ != "OK":
                raise RuntimeError("IMAP MOVE failed")
        else:
            typ, _ = conn.uid("COPY", str(uid), _imap_mailbox(dest))
            if typ != "OK":
                raise RuntimeError("IMAP COPY failed; source preserved")
            typ, _ = conn.uid("STORE", str(uid), "+FLAGS.SILENT", "(\\Deleted)")
            if typ != "OK":
                raise RuntimeError("IMAP COPY completed but source deletion flag failed")
            conn.expunge()


def send_message(cfg: dict, raw: bytes, recipients: list[str], sender: str):
    host, port = cfg["smtp_host"], cfg["smtp_port"]
    validate_mail_hostname(host, port)
    if cfg["smtp_security"] == "ssl":
        smtp = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20)
    else:
        smtp = smtplib.SMTP(host, port, timeout=20)
    with smtp:
        if cfg["smtp_security"] == "starttls":
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        elif cfg["smtp_security"] != "ssl":
            raise ValueError("Unencrypted SMTP is not supported")
        smtp.login(cfg["username"], cfg["password"])
        smtp.sendmail(sender, recipients, raw)
