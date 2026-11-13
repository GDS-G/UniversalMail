# Universal Mail & Calendar

**Backend 0.5.0 — development, single-owner deployment. Not yet a live ChatGPT mail service.**

Self-hosted FastAPI gateway with Gmail/Microsoft Graph adapters and a custom IMAP/SMTP path. No Replit dependency. The installed ChatGPT skill/plugin remains separate and has not been connected to this server.

## Start here — local computer or your server

For Windows, install/start Docker Desktop in Linux-container mode, extract this
repository and run from its folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-UniversalMail.ps1 -CopyKey
```

The launcher checks compatibility, builds the app, generates keys without overwriting
existing ones, starts the local service, verifies health and opens `/setup`. No host
Python installation is needed. This command must run on **your PC**, not in ChatGPT's
sandbox. No mailbox is connected until you complete provider consent.

[Local setup](docs/LOCAL_SETUP.md) · [Server setup](docs/SERVER_SETUP.md)

The `/setup` page offers both deployment paths, exact callback URIs, one-time app
registration guidance, encrypted provider app-credential storage and mailbox sign-in.
The Linux server launcher configures Docker volumes and a Caddy HTTPS proxy on an
existing compatible host; it does not buy a server or change DNS/firewalls. Remote
SSH provisioning and automatic local-to-server data migration are not implemented.

## Earlier mail/OAuth milestone

- Browser account connection at `/connect`, with provider-hosted consent, authorization code + S256 PKCE, expiring one-time browser-bound state, and server-verified mailbox identity.
- Encrypted access/refresh token storage, access-token caching, serialized refresh-token rotation, and account reconnection without duplicate identities.
- Gmail persistent never-mark-as-spam filters using `action.removeLabelIds=["SPAM"]`, with read-back verification and reuse of matching filters. Message not-spam remains a separate action. Outlook Safe Senders is explicitly not implemented.
- Native mailbox pagination and Outlook child-folder browsing; Gmail Junk/Trash enumeration enabled.
- HTML/multipart MIME, attachments and Bcc handling for native APIs; SMTP keeps Bcc only in its separate envelope. Receiving clients still control rendering.
- IMAP moves no longer use mailbox-wide EXPUNGE. They require MOVE or UIDPLUS and report partial failures. SMTP responses distinguish accepted and refused recipients.
- 103 automated tests after the setup milestone, using mocked provider responses. CI adds Windows PowerShell checks and a real Linux Docker startup test. Live mailbox operations and real OAuth consent have not been tested.

## Local setup

1. Install Python 3.12 or 3.13 and run `python -m pip install -r requirements.txt`.
2. Copy `.env.example` to `.env` and generate a master key and an independent API key:

```sh
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

3. Store the generated values in `.env`; do not commit that file. Enter provider app credentials there, following [OAuth setup](docs/OAUTH.md).
4. Run:

```sh
python -m uvicorn universalmail.main:app --host 127.0.0.1 --port 8000 --env-file .env --no-access-log
```

5. Open `http://localhost:8000/connect`. Enter the **server API key**, not an email password. Check configuration, then choose a provider. The key is sent only to this server in an HTTP header and is not put in browser storage or a URL.
6. Inspect the authenticated API at `/docs`, using the `X-API-Key` header. `/health` reports server health, not provider connectivity.

For Docker, populate `.env`, then `docker compose up --build`. The service binds to localhost. The container runs as UID 10001; an existing data volume must be writable by that UID. Back up existing data before changing ownership or upgrading.

For remote use, configure a fixed HTTPS origin and disable insecure localhost mode. Suppress OAuth query strings in proxy logs. No hosting account, OAuth app registration, paid subscription, or deployment is created by this repository.

## API and compatibility notes

`POST /accounts/native` now returns **410**: manual refresh-token registration was removed. Use `/connect` and the authenticated `/oauth/{gmail|outlook}/start` flow. Existing encrypted accounts are retained; reconnect when requested. `/oauth/status` reports configuration without returning secrets.

Native folder/message listings now return `{ "items": [...], "next_page_token": ... }`. Pass the cursor back to the same resource until it is null. Outlook root folders are not the complete hierarchy: query each folder with children using `parent=<folder id>`. IMAP listings currently return the most recent bounded set, not a complete paginated inventory.

A sender filter does not change existing messages and does not mean a provider block list was inspected. Removing an account deletes local credentials; it does not revoke the provider's original consent. A successful send response means provider acceptance, not recipient delivery.

## What remains

Calendar CRUD/free-busy/RSVP, Outlook Safe Senders, actual spam/phishing reporting, cross-account MIME import/verified migration, an authenticated remote MCP integration, and autonomous processing are **not implemented**. Do not substitute folder moves for sender allowlisting or reporting.

Custom-mail work still includes explicit IMAP security selection on arbitrary ports, separate SMTP credentials, OAuth-enabled IMAP, POP3, Unicode folder handling, UIDVALIDITY tracking, complete pagination, and Sent-folder copy policy. Large native-provider attachment upload sessions, inline-image composition, and provider-specific reply/thread behavior also need completion.

Production work still includes request-size/rate limits, audit records, a deployment egress policy and stronger DNS-rebinding protection, dependency locking/scanning, live tests, and review of token revocation/rotation recovery. Hostname DNS checks alone are not a complete SSRF defense. This is a single-owner API-key service, not a multi-user authorization system. Email addresses/display names are metadata; tokens and passwords are encrypted. Protect the database and back up its master key separately.

## Tests

```sh
python -m pytest -q
```

See [test scope](docs/TESTING.md) and the [roadmap](docs/ROADMAP.md). No test sends mail, modifies a real inbox, or connects an actual provider account.
