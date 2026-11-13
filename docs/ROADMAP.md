# Implementation roadmap

## Backend 0.4.0 — implemented and locally mock-tested

Browser Google/Microsoft authorization, S256 PKCE, owner authentication, one-use browser-bound callbacks, encrypted token persistence/refresh, and verified provider identities. Native mail listing/read/send/move, cursor pagination and Outlook child folders. Correct Gmail sender-filter action with read-back verification. Custom IMAP/SMTP foundation, safer moves, MIME/Bcc handling, and explicit partial SMTP acceptance.

## Next implementation work

1. Calendar provider adapters: calendars, events, invitations, free/busy, RSVP, time zones and conflict checks. Request additional scopes only when used.
2. Outlook Safe Senders using a supported, verified mailbox configuration mechanism; distinguish personal Outlook from organizational accounts. No fallback that falsely claims sender trust.
3. Provider-specific spam/phishing reporting, blocked-sender management and authorized reconciliation of conflicting filters.
4. Attachments/inline images, native replies/threading, complete custom-server configuration, complete IMAP inventory, UIDVALIDITY and localized folders.
5. Raw MIME cross-account import/copy with durable jobs, deduplication, body/header/attachment verification and source removal only after verified import.
6. Remote MCP authentication and tool surface, deployed HTTPS service, installed plugin binding, approval policies and authorized autonomous workflows.

## Release gates

Register real OAuth applications and test Gmail, Outlook personal, Microsoft 365 and a custom IMAP/SMTP account. Verify mailbox-visible changes, formatting, Bcc privacy, attachment integrity, pagination, actual sender-filter persistence, revoked consent and token expiry. CI mock tests do not substitute for these checks.

Before public deployment, implement request/rate bounds, audit events, egress restrictions including DNS-rebinding defense, dependency locking/security scanning, backup/recovery and OAuth revocation. No credentials in Git, chat, logs or screenshots. Choose hosting separately; no Replit subscription is required by the code.

## Setup milestone delivered in 0.5.0
Local launchers, generated keys, authenticated setup UI, encrypted app configuration,
and compatible-host Linux Docker/Caddy launcher. Still required: local authenticated
MCP bridge, remote authenticated MCP endpoint, cloud-provider provisioning adapters,
explicit server-access delegation and automatic migration/rollback with verified backups.
