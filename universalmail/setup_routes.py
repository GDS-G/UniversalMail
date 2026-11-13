"""Authenticated setup/readiness API. Never provisions arbitrary hosts via HTTP."""
import os
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from . import client_config, provider_http, vault
from .auth import require_api_key
from .oauth import public_origin

router = APIRouter(prefix="/setup", dependencies=[Depends(require_api_key)])
Kind = Literal["gmail", "outlook"]


class ProviderSetup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str = Field(min_length=4, max_length=512, pattern=r"^[A-Za-z0-9._-]+$")
    client_secret: SecretStr = Field(min_length=8, max_length=4096)
    tenant: str = Field(default="common", max_length=253, pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
    replace_existing: bool = False


def origin_or_error() -> str:
    try:
        return public_origin()
    except provider_http.ProviderError as exc:
        raise HTTPException(exc.status, exc.detail) from None


@router.get("/status")
def setup_status():
    origin = origin_or_error()
    configured = {}
    for kind in ("gmail", "outlook"):
        try:
            cfg = provider_http.settings(kind)
            ready, scopes = True, list(cfg["scopes"])
        except (provider_http.ProviderError, ValueError):
            ready, scopes = False, []
        configured[kind] = {"configured": ready, "requested_scopes": scopes,
                            "redirect_uri": f"{origin}/oauth/{kind}/callback"}
    return {"mode": os.getenv("UNIVERSALMAIL_DEPLOYMENT_MODE", "local" if origin.startswith("http://") else "server"),
            "origin": origin, "providers": configured,
            "accounts": vault.list_accounts(), "mcp_connected": False,
            "mailbox_actions_live_tested": False,
            "deployment_options": [
                {"id": "local", "label": "This computer", "launcher": "Start-UniversalMail.ps1 or start-universalmail.sh", "network_binding": "127.0.0.1 only"},
                {"id": "server", "label": "Your backend server", "launcher": "start-universalmail.sh --mode server --domain HOSTNAME", "requirements": "Linux Docker engine, Compose v2, persistent disk, DNS and inbound 80/443; run on the authorized server"}],
            "server_provisioning_from_browser": False}


@router.post("/providers/{kind}")
def save_provider(kind: Kind, payload: ProviderSetup, request: Request):
    origin = origin_or_error()
    if request.headers.get("origin") not in (None, origin) or request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-origin configuration is not allowed")
    secret = payload.client_secret.get_secret_value()
    if any(ord(c) < 32 or ord(c) == 127 for c in secret):
        raise HTTPException(400, "Client secret must be a single-line value")
    old = client_config.values(kind)
    values = {"client_id": payload.client_id, "client_secret": secret,
              "tenant": payload.tenant if kind == "outlook" else "common"}
    has_existing = bool(old.get("client_id") and old.get("client_secret"))
    changed = any(old.get(k, "common" if k == "tenant" else "") != v for k, v in values.items())
    if has_existing and changed and not payload.replace_existing:
        raise HTTPException(409, "Existing app configuration differs; explicitly approve replacement and reconnect affected mailboxes")
    try:
        client_config.write(kind, values)
    except (ValueError, OSError):
        raise HTTPException(500, "Encrypted configuration could not be saved") from None
    return {"saved": True, "encrypted_at_rest": True, "provider": kind,
            "redirect_uri": f"{origin}/oauth/{kind}/callback",
            "reconnect_existing_accounts": has_existing and changed,
            "provider_credentials_validated": False,
            "next_step": "Use Connect to sign in at the provider and approve access"}
