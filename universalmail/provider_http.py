"""Provider HTTP transport and OAuth refresh; no token values are logged."""
import base64
import json
import os
from urllib.parse import urlencode

import httpx


class ProviderError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _request(method, url, token, *, params=None, json_body=None, data=None, headers=None):
    h = {"Authorization": "Bearer " + token, **(headers or {})}
    try:
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            r = client.request(method, url, params=params, json=json_body, content=data, headers=h)
    except httpx.RequestError as exc:
        raise ProviderError(502, "Provider network request failed") from exc
    if r.status_code >= 400:
        raise ProviderError(502, "Provider rejected request (HTTP %s)" % r.status_code)
    if not r.content:
        return {}
    if r.headers.get("content-type", "").startswith("application/json"):
        return r.json()
    return r.content


def refresh_token(kind: str, refresh: str) -> dict:
    if kind == "gmail":
        endpoint = "https://oauth2.googleapis.com/token"
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        secret = os.getenv("GOOGLE_CLIENT_SECRET")
        body = {"client_id": client_id, "client_secret": secret,
                "refresh_token": refresh, "grant_type": "refresh_token"}
    elif kind == "outlook":
        tenant = os.getenv("MICROSOFT_TENANT", "common")
        if not tenant.replace("-", "").isalnum():
            raise ProviderError(400, "Invalid Microsoft tenant")
        endpoint = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        body = {"client_id": os.getenv("MICROSOFT_CLIENT_ID"),
                "client_secret": os.getenv("MICROSOFT_CLIENT_SECRET"),
                "refresh_token": refresh, "grant_type": "refresh_token",
                "scope": "offline_access Mail.ReadWrite Mail.Send Calendars.ReadWrite"}
    else:
        raise ProviderError(400, "Unsupported OAuth provider")
    if not body["client_id"]:
        raise ProviderError(503, "Provider OAuth client is not configured")
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(endpoint, data=body)
    except httpx.RequestError as exc:
        raise ProviderError(502, "OAuth token endpoint unreachable") from exc
    if response.status_code != 200:
        raise ProviderError(401, "Provider OAuth refresh failed; reconnect account")
    result = response.json()
    if not result.get("access_token"):
        raise ProviderError(502, "Provider did not return an access token")
    return result


def authorized(account: dict, method: str, url: str, **kwargs):
    cfg = account["config"]
    if not cfg.get("refresh_token"):
        raise ProviderError(401, "Provider account needs OAuth authorization")
    # Refresh for each request initially: no stale access-token persistence.
    token = refresh_token(account["kind"], cfg["refresh_token"])["access_token"]
    return _request(method, url, token, **kwargs)
