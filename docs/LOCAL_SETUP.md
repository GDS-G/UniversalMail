# Run on your computer — backend 0.5.0

The Windows launcher targets your Windows PC using Docker Desktop's Linux engine.
macOS and Linux can use the shell launcher with a local Docker engine. The ChatGPT
conversation sandbox is not your computer: a generated package is not an installed
service until you run the launcher on the intended machine.

## Windows

1. Install/start [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/).
   Use its Linux/WSL 2 backend. Follow Docker's hardware/Windows/WSL requirements;
   a Windows feature installation may require a restart. This launcher does not
   install drivers, enable virtualization or change execution policy permanently.
2. Download/extract this source package, or clone `GDS-G/UniversalMail`. Open
   PowerShell in the folder containing `Start-UniversalMail.ps1` and `Dockerfile`.
3. Optional read-only compatibility check:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-UniversalMail.ps1 -CheckOnly
   ```

4. Start the application:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-UniversalMail.ps1 -CopyKey
   ```

   `-ExecutionPolicy Bypass` applies only to this PowerShell process. The script
   checks the Docker engine and Compose (v2.24+), builds the container, creates
   independent random keys, protects `.env`, starts the service and verifies
   `/health`. `-CopyKey` explicitly places the administration key on your clipboard
   without printing it. Paste it into the setup page, then clear the clipboard when
   finished. Omit `-CopyKey` to retrieve the key from `.env` yourself.
5. The launcher opens `http://localhost:8000/setup`. Open it on the **computer
   running Docker**, not on your phone. Click **Check setup** after pasting the key.
   The page separates app registration from mailbox sign-in and displays exact
   redirect URIs. Existing Google/Microsoft connections in ChatGPT do not transfer
   their tokens into this independently hosted application.

Use `-Port 8765` for a fresh installation on a different free port. Register the
redirect URIs displayed by that installation. Existing `.env` values and master
keys are never silently replaced. A placeholder or mismatched configuration stops
setup with instructions rather than risking loss of access to encrypted data.

To stop without deleting mail credentials or data:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Stop-UniversalMail.ps1
```

Run the start command again to resume. Docker must remain running and the PC must
remain awake for the service to work. Docker's restart policy does not turn on a
powered-off PC. A remote Docker context is deliberately rejected.

## macOS / Linux

```sh
bash ./start-universalmail.sh --check-only
bash ./start-universalmail.sh
```

The master/API keys are generated inside an isolated, network-disabled container,
so no Python installation on the host is required. On Linux the setup helper runs
with your host UID/GID. Use the `UNIVERSALMAIL_API_KEY` value from `.env` to unlock
setup. API calls always require `X-API-Key`; `/health` and the empty setup page do
not expose account data.

## Sign in after the service starts

See [OAuth setup](OAUTH.md). Register the application once with each provider you
intend to use. Enter the client ID and client secret into **this local /setup page**;
they are stored encrypted in the data volume. Do not paste secrets into chat or
commit them to GitHub. The API does not return saved secret values.

Then click **Connect Gmail** or **Connect Outlook**, sign in at the provider,
complete MFA if required, review the mail permissions, and approve. The callback
verifies mailbox identity before saving encrypted access/refresh tokens. You may
connect multiple accounts against a suitably registered app. Organizational policy
can require administrator approval. No mail is sent during setup.

Server app credentials can also be supplied through environment variables for
headless deployments. Saved encrypted configuration takes precedence; changes to
an existing configuration require an explicit replacement checkbox. Reconnect
mailboxes after changing the OAuth client/tenant.

## Not yet a live ChatGPT mail connection

Starting this REST backend is a distinct milestone from connecting ChatGPT. The
MCP endpoint and authenticated bridge remain unfinished. The future local path
must use a supported private tunnel or a locally running MCP client; ChatGPT's
hosted service cannot just call a localhost URL on your PC. OpenAI documents
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
for supported private integrations. Do not expose this administration API through
an unauthenticated public tunnel as a substitute.

## Troubleshooting

- Docker not found/not running: install/start Docker Desktop, then rerun.
- Linux engine required: switch from Windows containers to Linux containers.
- Port occupied: use another port for a fresh install; do not overwrite an old master key.
- Existing `.env` rejected: preserve it and the data volume; fix its configuration explicitly.
- Permission error on an old Docker volume: back up before arranging ownership for UID 10001.
- App not configured: create the provider application, then save its ID/secret in `/setup`.
- Redirect mismatch: compare every character with the URI shown in `/setup`, including port/path.
- Failed consent: check the account type, test-user list, app permissions and organization policy.
- Backend healthy but no ChatGPT tools: expected until the separate MCP milestone is finished.
