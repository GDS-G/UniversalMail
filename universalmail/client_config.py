"""Encrypted owner-supplied OAuth app configuration, separate from mailbox tokens."""
import json
import os
from pathlib import Path
import tempfile

from .security import decrypt_secret, encrypt_secret


def _path(kind: str) -> Path:
    if kind not in ("gmail", "outlook"):
        raise ValueError("Unsupported provider")
    return Path(os.getenv("UNIVERSALMAIL_DB_PATH", "./data/accounts.db")).parent / f"oauth-client-{kind}.enc"


def read(kind: str) -> dict:
    path = _path(kind)
    if not path.exists():
        return {}
    if path.is_symlink() or path.stat().st_size > 32768:
        raise ValueError("Invalid encrypted OAuth client configuration")
    result = json.loads(decrypt_secret(path.read_text(encoding="utf-8")))
    if not isinstance(result, dict):
        raise ValueError("Invalid OAuth client configuration")
    return result


def write(kind: str, values: dict) -> None:
    path = _path(kind)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Refusing symbolic-link OAuth configuration")
    fd, tmp = tempfile.mkstemp(prefix=".oauth-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encrypt_secret(json.dumps(values)))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def values(kind: str) -> dict:
    # Saved encrypted configuration is authoritative; env is a deployment fallback.
    saved = read(kind)
    if saved:
        return saved
    prefix = "GOOGLE" if kind == "gmail" else "MICROSOFT"
    return {"client_id": os.getenv(prefix + "_CLIENT_ID", ""),
            "client_secret": os.getenv(prefix + "_CLIENT_SECRET", ""),
            "tenant": os.getenv("MICROSOFT_TENANT", "common")}
