# Universal Mail & Calendar

Self-hosted, provider-adapter email and calendar gateway for ChatGPT integrations.

**Status: foundation / development.** This release implements a secure API skeleton and a functional custom IMAP/SMTP path for common mailbox operations. Initial Microsoft Graph and Gmail mail adapters are now implemented but **untested against live accounts**. Browser OAuth onboarding, CalDAV, Outlook sender safe-listing, phishing reporting, calendar scheduling, cross-account migration and MCP exposure are **not yet implemented**. The API must not claim those operations succeeded.

## Current features
- Account configurations encrypted at rest using Fernet; custom IMAP/SMTP servers with explicit ports and TLS.
- List folders/messages, read message, download attachments, send multipart plain-text/HTML messages with multiple attachments, set seen/flagged, move messages, and fetch raw RFC822 bytes.
- Explicit provider capability reporting. Not-junk sender allowlisting is **unsupported** on generic IMAP; moving messages does not imply retraining spam filters or sender allowlisting.
- API-key authentication and Docker deployment scaffold. Intended to run behind TLS and a reverse proxy.

## Run locally
1. Install Python 3.12 or newer.
2. `pip install -r requirements.txt`
3. Generate a fresh key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
4. Set `UNIVERSALMAIL_MASTER_KEY` to that value and `UNIVERSALMAIL_API_KEY` to a long random value in your environment. Never commit either value.
5. Run `uvicorn universalmail.main:app --host 127.0.0.1 --port 8000`.
6. Visit `http://127.0.0.1:8000/docs`; authenticate using the `X-API-Key` header.

The backend stores encrypted provider credentials in SQLite at `UNIVERSALMAIL_DB_PATH` (default `./data/accounts.db`). Protect and back up the database and master key separately. No credentials belong in chat or GitHub.

### Example custom account
POST `/accounts/custom` with:
```json
{
  "name": "My mailbox",
  "email": "me@example.com",
  "username": "me@example.com",
  "password": "app-specific-password",
  "imap_host": "imap.example.com",
  "imap_port": 993,
  "smtp_host": "smtp.example.com",
  "smtp_port": 465,
  "smtp_security": "ssl"
}
```
Server connections are permitted only to public DNS addresses by default, to reduce server-side request forgery risks. Set `UNIVERSALMAIL_ALLOW_PRIVATE_MAIL_HOSTS=true` only in a controlled private network.

### Deployment
`docker compose up --build` with environment variables configured. Do not expose the API directly on the Internet without HTTPS, authentication, rate limits, network isolation, and a secrets-management plan. The docker compose file binds to localhost by default.

## Provider limitations
- IMAP folders/flags are server capabilities, not universal spam/phishing-report APIs.
- POP3 cannot provide full folder semantics. It is a future restricted adapter.
- Initial Outlook Microsoft Graph and Gmail API adapters support mailbox browsing, message reads, sending, and moving. Gmail also has message not-spam and persistent neverSpam filter operations. These require OAuth client registration and a valid refresh token; browser-based OAuth login is not implemented. Outlook sender allowlisting and calendar APIs are not implemented.
- HTML formatting is transmitted in standards-compliant MIME. Recipient clients may render it differently.
- This project is currently **not connected** to the installed ChatGPT plugin. Adding an authenticated MCP endpoint and changing the plugin configuration is a separate integration step.

## Test
`pytest -q`

## Roadmap
See [docs/ROADMAP.md](docs/ROADMAP.md).
## Native provider development
See [docs/OAUTH.md](docs/OAUTH.md). Provider adapters are unverified until real account OAuth, integration tests, and token lifecycle handling are complete. Never paste access or refresh tokens into ChatGPT.
