"""Fixed-origin provider HTTP transport and encrypted OAuth token lifecycle."""
import os
import re
import time
from urllib.parse import urlsplit

import httpx

from . import vault, client_config


class ProviderError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


GMAIL_SCOPES = ("https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.settings.basic")
GRAPH_SCOPES = ("https://graph.microsoft.com/User.Read",
                "https://graph.microsoft.com/Mail.ReadWrite",
                "https://graph.microsoft.com/Mail.Send")


def settings(kind: str) -> dict:
    if kind not in ("gmail", "outlook"):
        raise ProviderError(400, "Unsupported OAuth provider")
    credentials = client_config.values(kind)
    if kind == "gmail":
        result = dict(client_id=credentials.get("client_id"),
                      client_secret=credentials.get("client_secret"),
                      authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
                      token_url="https://oauth2.googleapis.com/token", scopes=GMAIL_SCOPES)
    elif kind == "outlook":
        tenant = credentials.get("tenant", "common")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", tenant):
            raise ProviderError(503, "Invalid Microsoft tenant configuration")
        base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
        result = dict(client_id=credentials.get("client_id"),
                      client_secret=credentials.get("client_secret"),
                      authorize_url=base + "/authorize", token_url=base + "/token",
                      scopes=(*GRAPH_SCOPES, "offline_access"))
    else:
        raise ProviderError(400, "Unsupported OAuth provider")
    if not result["client_id"] or not result["client_secret"]:
        raise ProviderError(503, "Provider OAuth client ID and secret must be configured on the server")
    return result


def _validate_url(kind: str, url: str) -> None:
    parsed = urlsplit(url)
    host, prefix = (("gmail.googleapis.com", "/gmail/v1/") if kind == "gmail"
                    else ("graph.microsoft.com", "/v1.0/"))
    if (kind not in ("gmail", "outlook") or parsed.scheme != "https"
            or parsed.netloc != host or not parsed.path.startswith(prefix)
            or parsed.fragment):
        raise ProviderError(400, "Untrusted provider URL")


def _request(method, url, token, *, params=None, json_body=None, data=None, headers=None):
    h = {**(headers or {}), "Authorization": "Bearer " + token}
    try:
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            r = client.request(method, url, params=params, json=json_body, content=data, headers=h)
    except httpx.RequestError as exc:
        raise ProviderError(502, "Provider network request failed; write outcome may be unknown; do not automatically retry") from exc
    if not 200 <= r.status_code < 300:
        status = r.status_code if r.status_code in (401, 403, 429) else 502
        raise ProviderError(status, "Provider rejected request (HTTP %s)" % r.status_code)
    if not r.content:
        return {}
    if r.headers.get("content-type", "").startswith("application/json"):
        try:
            return r.json()
        except ValueError as exc:
            raise ProviderError(502, "Provider returned invalid JSON") from exc
    return r.content


def token_request(kind: str, grant: dict) -> dict:
    cfg = settings(kind)
    body = {**grant, "client_id": cfg["client_id"], "client_secret": cfg["client_secret"]}
    try:
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            response = client.post(cfg["token_url"], data=body)
    except httpx.RequestError as exc:
        raise ProviderError(502, "OAuth provider is unreachable; start sign-in again") from exc
    if response.status_code != 200:
        raise ProviderError(401, "Provider authorization failed; reconnect the account")
    try:
        result = response.json()
        if not isinstance(result, dict) or not isinstance(result.get("access_token"), str) or not result["access_token"]:
            raise ValueError()
        if not isinstance(result.get("token_type"), str) or result["token_type"].lower() != "bearer" or int(result.get("expires_in", 0)) <= 0:
            raise ValueError()
    except (ValueError, TypeError) as exc:
        raise ProviderError(502, "Provider returned an invalid token response") from exc
    return result


def granted_scopes(kind: str, result: dict) -> list[str]:
    value = result.get("scope")
    if not isinstance(value, str) or not value:
        raise ProviderError(403, "Provider did not confirm granted scopes; reconnect the account")
    scopes = value.split()
    normalize = (lambda x: x.removeprefix("https://graph.microsoft.com/").lower()) if kind == "outlook" else (lambda x: x)
    required = GRAPH_SCOPES if kind == "outlook" else GMAIL_SCOPES
    if not {normalize(x) for x in required}.issubset({normalize(x) for x in scopes}):
        raise ProviderError(403, "Required mail permissions were not granted; reconnect and grant consent")
    return scopes


def token_config(kind: str, result: dict) -> dict:
    return {"access_token": result["access_token"],
            "refresh_token": result.get("refresh_token"),
            "expires_at": time.time() + int(result["expires_in"]),
            "scopes": granted_scopes(kind, result), "client_id": settings(kind)["client_id"]}


def refresh_token(kind: str, refresh: str) -> dict:
    # Omit scope on refresh: retain the actual original grant, not future features.
    return token_request(kind, {"grant_type": "refresh_token", "refresh_token": refresh})


def authorized(account: dict, method: str, url: str, **kwargs):
    _validate_url(account["kind"], url)
    # The DB transaction prevents multiple workers from losing rotated refresh tokens.
    with vault.token_session(account["id"]) as current:
        cfg = current["config"]
        client = settings(current["kind"])["client_id"]
        if cfg.get("client_id", client) != client:
            raise ProviderError(401, "OAuth client changed; reconnect the account")
        if not cfg.get("access_token") or float(cfg.get("expires_at", 0)) <= time.time() + 60:
            if not cfg.get("refresh_token"):
                raise ProviderError(401, "Provider account needs OAuth authorization")
            result = refresh_token(current["kind"], cfg["refresh_token"])
            cfg.update(access_token=result["access_token"], expires_at=time.time() + int(result["expires_in"]), client_id=client)
            if result.get("refresh_token"):
                cfg["refresh_token"] = result["refresh_token"]
            if result.get("scope"):
                cfg["scopes"] = result["scope"].split()
        token = cfg["access_token"]
    # Never retry writes automatically: a timeout can follow a successful submission.
    return _request(method, url, token, **kwargs)
