# Deploy to your backend server

## Supported target for the first server launcher

An existing Linux host/VM with a working local Linux Docker engine, Docker Compose
v2.24+, persistent disk, outbound HTTPS to Google/Microsoft, and outbound TLS mail
ports required by the custom servers you use. Public HTTPS setup requires your DNS
hostname to point to this host, with inbound TCP 80/443 reaching Caddy. Check SMTP
port restrictions with the host provider before choosing it. This is not a claim
of support for every cloud platform, Windows Server, Kubernetes or ephemeral hosting.

The user supplies/provisions the host and authorizes access. The included launcher
configures the application and reverse proxy **when run on that host**. It does not
buy hosting, log into arbitrary servers, install Docker with root privileges,
change DNS/firewalls, or claim a deployment without checking its result.

## Deployment

Copy/clone the repository onto the authorized host, then run:

```sh
bash ./start-universalmail.sh --mode server --domain mail.your-domain.com --check-only
bash ./start-universalmail.sh --mode server --domain mail.your-domain.com
```

The launcher creates `.env` with generated keys, preserves existing valid keys,
builds the app, starts named persistent volumes and configures the Caddy proxy.
`compose.server.yaml` is a **standalone Compose file**, not an override to merge
with `compose.yaml`. Only Caddy publishes ports; the Python service is not exposed
on public port 8000. The app runs as UID 10001, without Linux capabilities.

Caddy manages HTTPS certificates and renewals when DNS and network requirements
are satisfied. Its access log is not enabled because OAuth callbacks contain codes.
A passing internal health check is not a certificate/DNS test. Verify the public
`https://YOUR_HOST/health` and `/setup` from outside the server before account consent.
See [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).

Open the server's `/setup`, unlock it with the generated API key, and register its
exact HTTPS callback URIs with the providers. Provider app credentials can be
saved encrypted there. Configuration, mailbox connection, mail operations and
ChatGPT MCP availability are reported as separate states.

## Migration from the local computer

Do not point the server at an empty database and expect existing mail accounts to
appear. Back up the complete app data volume **and its matching master key** while
the application is stopped. The volume includes accounts.db and encrypted OAuth
client configuration files. Restore to the server with permissions appropriate for
UID 10001; do not mount two concurrently writing instances on one SQLite database.
Update the fixed origin and provider redirect URIs. Test a read-only operation
first and reconnect accounts when required. Automatic migration/rollback and a
remote SSH provisioning agent are not implemented in 0.5.0.

## GitHub's role

GitHub stores source and can run build/test/deployment workflows. GitHub Pages does
not execute this Python backend. Codespaces can run temporary development sessions
but has idle/lifetime limits; it is not the persistent mailbox server target here.
The server launcher is independent of Replit and GitHub Codespaces.

Sources:
- https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site
- https://docs.github.com/en/codespaces/setting-your-user-preferences/setting-your-timeout-period-for-github-codespaces

## Release boundary

This server deployment path is a development/testing convenience, not a production
security certification. Request rate limits, complete auditing, deployment egress
restrictions/stronger SSRF defenses, dependency locking, remote MCP authentication,
live provider tests and several mail/calendar features remain open work. The server
needs ongoing backups, updates and access control beyond merely starting containers.
