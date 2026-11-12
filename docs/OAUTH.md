# Browser OAuth setup (backend 0.4.0)

The owner connects accounts on `/connect`. Provider passwords are entered only on Microsoft/Google pages. Authorization codes are exchanged by the backend; tokens are encrypted in SQLite. Do not paste client secrets, account passwords, or tokens into ChatGPT, issues, commits, or URLs.

## Server configuration

Set `UNIVERSALMAIL_PUBLIC_URL` to the exact externally reachable HTTPS origin, with no path, query, credentials, or fragment. Callback addresses are derived from this fixed setting, not inbound Host/Forwarded headers. Local development can use `http://localhost:8000` only with `UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST=true`; open that same hostname in the browser.

Set a generated `UNIVERSALMAIL_MASTER_KEY` and an independently generated `UNIVERSALMAIL_API_KEY` of at least 32 characters. No default master key is provided. A key change requires a migration plan for already encrypted data.

## Google

Create a Google Cloud project, enable Gmail API, configure the consent screen/audience/test users as appropriate, and create an OAuth client of type **Web application**. Register the exact callback:

`<public-origin>/oauth/gmail/callback`

Place `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` on the server. The current mail adapter requests `https://www.googleapis.com/auth/gmail.modify` and `https://www.googleapis.com/auth/gmail.settings.basic`. It requests offline access and consent so a refresh token can be issued. Missing required scopes or missing offline access fail explicitly. Calendar permissions are not requested yet.

Google verification, test-mode restrictions, and Workspace policies may affect availability or credential lifetime. Those requirements are not bypassed by this project.

## Microsoft

Register an Entra application for the intended audience. To support organizational and personal Outlook accounts with `MICROSOFT_TENANT=common`, select the corresponding multi-tenant plus personal-account audience. Configure a **Web** platform redirect, not SPA:

`<public-origin>/oauth/outlook/callback`

Set `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` (the secret value), and `MICROSOFT_TENANT`. Delegated scopes are `User.Read`, `Mail.ReadWrite`, `Mail.Send`, and `offline_access`; full Microsoft Graph resource prefixes are used for the Graph permissions. Organizational policy may require administrator consent. Calendar scopes are intentionally deferred.

The mailbox identity comes from the provider profile API. This flow does not decode an unverified ID token or accept an email address as proof of ownership. Selecting an optional expected mailbox prevents connecting the wrong account accidentally.

## Flow behavior

- Only an authenticated owner can initiate sign-in. The public connection page exposes no account data.
- Each attempt has S256 PKCE and an encrypted transaction with hashed state/browser binding, ten-minute expiry, provider binding, and a one-use callback.
- The browser binding is an HttpOnly, SameSite=Lax cookie; it is Secure on HTTPS. No provider token is returned to the browser or stored in localStorage.
- Failed or declined sign-ins require restarting. Exact provider and callback configuration must still match when the callback arrives.
- Successful reconnects replace credentials for the same identity. Refresh-token rotation is persisted before using the new access token. SQLite serializes refresh operations across workers; a higher-volume deployment needs a different locking/storage design.
- Deletes remove local account credentials only; provider-side consent revocation remains manual/not implemented.
- There are no automatic retries of mail writes after ambiguous network failures.

Disable access logging of OAuth query strings in both the app server and reverse proxy. The included launch command/container disables Uvicorn access logs. Never log authorization codes, cookies, tokens, message bodies, or credential request bodies.

## Provider references checked for this implementation

- [Google web-server OAuth](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google OAuth Flow / PKCE implementation](https://googleapis.dev/python/google-auth-oauthlib/latest/_modules/google_auth_oauthlib/flow.html)
- [Microsoft authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Gmail filter actions](https://developers.google.com/workspace/gmail/api/guides/filter_settings)
- [Microsoft Graph sendMail MIME contract](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)

The protocol paths are implemented and mock-tested, not yet verified by signing into real accounts. This does not connect the server to the installed ChatGPT plugin; hosting and authenticated MCP integration remain separate work.
