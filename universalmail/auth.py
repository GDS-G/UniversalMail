"""Single-owner administration authentication (not multi-user authorization)."""
import os
import secrets

from fastapi import Header, HTTPException


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("UNIVERSALMAIL_API_KEY", "")
    if (len(expected) < 32 or expected.startswith("replace-") or not x_api_key
            or not secrets.compare_digest(x_api_key.encode(), expected.encode())):
        raise HTTPException(401, "Valid X-API-Key required")
