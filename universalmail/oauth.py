"""Browser-bound authorization code + S256 PKCE onboarding for the owner."""
import base64
import hashlib
import html
import os
import secrets
from typing import Literal
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field, TypeAdapter

from . import provider_http as provider, vault
from .auth import require_api_key

router = APIRouter()
Kind = Literal["gmail", "outlook"]


class StartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(default="", max_length=100)
    expected_email: EmailStr | None = None


def public_origin() -> str:
    value = os.getenv("UNIVERSALMAIL_PUBLIC_URL", "").rstrip("/")
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError as exc:
        raise provider.ProviderError(503, "Invalid UNIVERSALMAIL_PUBLIC_URL") from exc
    local = (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")
             and os.getenv("UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST", "false").lower() == "true")
    if (not value or any(ord(c) <= 32 or c == "\\" for c in value) or not u.hostname or (u.scheme != "https" and not local)
            or u.username or u.password or u.query or u.fragment or u.path
            or (port is not None and not 1 <= port <= 65535)):
        raise provider.ProviderError(503, "Configure a fixed HTTPS public origin; HTTP is only allowed for explicitly enabled localhost development")
    return value


def cookie_name(state: str) -> str:
    return "um_oauth_" + vault.digest(state)[:32]


def safe_response(response):
    response.headers.update({"Cache-Control": "no-store", "Pragma": "no-cache",
                             "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
                             "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"})
    return response


@router.get("/oauth/status", dependencies=[Depends(require_api_key)])
def status():
    try:
        origin = public_origin()
    except provider.ProviderError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    result = {}
    for kind in ("gmail", "outlook"):
        try:
            provider.settings(kind)
            ready = True
        except provider.ProviderError:
            ready = False
        result[kind] = {"configured": ready, "redirect_uri": f"{origin}/oauth/{kind}/callback"}
    return {"providers": result, "live_provider_validation": False}


@router.post("/oauth/{kind}/start", dependencies=[Depends(require_api_key)])
def start(kind: Kind, payload: StartRequest, request: Request):
    try:
        origin = public_origin()
        if request.headers.get("origin") not in (None, origin) or request.headers.get("sec-fetch-site") == "cross-site":
            raise provider.ProviderError(403, "Cross-origin sign-in initiation is not allowed")
        cfg = provider.settings(kind)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        redirect = f"{origin}/oauth/{kind}/callback"
        state, browser = vault.create_state(kind, {"verifier": verifier, "redirect_uri": redirect,
            "client_id": cfg["client_id"], "token_url": cfg["token_url"], "name": payload.name,
            "expected_email": str(payload.expected_email) if payload.expected_email else None})
        args = {"client_id": cfg["client_id"], "redirect_uri": redirect, "response_type": "code",
                "scope": " ".join(cfg["scopes"]), "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256"}
        if kind == "gmail":
            args.update(access_type="offline", prompt="consent", include_granted_scopes="true")
        else:
            args.update(response_mode="query", prompt="select_account")
        response = JSONResponse({"authorization_url": cfg["authorize_url"] + "?" + urlencode(args)})
        response.set_cookie(cookie_name(state), browser, max_age=600, httponly=True,
                            secure=origin.startswith("https://"), samesite="lax",
                            path=f"/oauth/{kind}/callback")
        return safe_response(response)
    except provider.ProviderError as exc:
        raise HTTPException(exc.status, exc.detail) from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


def verified_identity(kind: str, access_token: str) -> tuple[str, str, str]:
    url = ("https://gmail.googleapis.com/gmail/v1/users/me/profile" if kind == "gmail"
           else "https://graph.microsoft.com/v1.0/me?$select=id,mail,userPrincipalName,displayName")
    profile = provider._request("GET", url, access_token)
    if not isinstance(profile, dict):
        raise provider.ProviderError(502, "Provider profile was invalid")
    address = profile.get("emailAddress") if kind == "gmail" else profile.get("mail") or profile.get("userPrincipalName")
    try:
        address = str(TypeAdapter(EmailStr).validate_python(address))
    except ValueError as exc:
        raise provider.ProviderError(502, "Provider did not verify a mailbox address") from exc
    subject = address.casefold() if kind == "gmail" else profile.get("id")
    if not isinstance(subject, str) or not subject:
        raise provider.ProviderError(502, "Provider did not verify an account identity")
    return subject, address, str(profile.get("displayName") or address)[:100]


@router.get("/oauth/{kind}/callback")
def callback(kind: Kind, request: Request, state: str = "", code: str = "", error: str = ""):
    status_code = 200
    try:
        if not 20 <= len(state) <= 256:
            raise ValueError("Missing or invalid sign-in state; start again")
        flow = vault.consume_state(state, kind, request.cookies.get(cookie_name(state), ""))
        if error:
            raise ValueError("Provider sign-in was declined or failed; no account was connected")
        if not code or len(code) > 8192:
            raise ValueError("Missing or invalid authorization code; start again")
        cfg = provider.settings(kind)
        if cfg["client_id"] != flow["client_id"] or cfg["token_url"] != flow["token_url"] or flow["redirect_uri"] != f"{public_origin()}/oauth/{kind}/callback":
            raise ValueError("Sign-in configuration changed; start again")
        tokens = provider.token_request(kind, {"grant_type": "authorization_code", "code": code,
            "redirect_uri": flow["redirect_uri"], "code_verifier": flow["verifier"]})
        config = provider.token_config(kind, tokens)
        subject, address, name = verified_identity(kind, tokens["access_token"])
        if flow.get("expected_email") and flow["expected_email"].casefold() != address.casefold():
            raise ValueError("A different mailbox was selected; no account was connected")
        vault.save_oauth_account(flow["name"] or name, address, kind, subject, config)
        message = f"Connected {address}. Identity verified and tokens saved on this server. Mail actions have not been tested. You may close this page."
    except provider.ProviderError as exc:
        status_code, message = exc.status, exc.detail
    except ValueError as exc:
        status_code, message = 400, str(exc)
    except Exception:
        status_code, message = 500, "Connection could not be saved; start sign-in again"
    response = HTMLResponse("<!doctype html><html lang='en'><meta charset='utf-8'><title>UniversalMail connection</title><h1>UniversalMail</h1><p>" + html.escape(message) + "</p></html>", status_code=status_code)
    response.delete_cookie(cookie_name(state), path=f"/oauth/{kind}/callback")
    return safe_response(response)
