# Implementation roadmap

## Phase 1 (committed foundation)
- Encrypted per-account custom IMAP/SMTP config and mailbox operations.
- Multipart HTML composition and multiple attachments.
- Explicit capability flags; no false success when a provider operation is unsupported.

## Phase 2
- OAuth authorization-code + PKCE for Microsoft Graph and Gmail, refresh-token management and tenant validation.
- Native Outlook/Gmail folder search, send, reply, raw-message import/export, labels, categories, safe senders and spam classification.
- Secure attachment streaming with size and content-type controls; avoid storing plaintext files long-term.
- Server-side rules and provider-specific true phishing reporting only where supported.

## Phase 3
- CalDAV plus Graph/Google calendar operations, free/busy scheduling, invites, RSVPs.
- MIME-preserving cross-provider copy with Message-ID, Date, body/attachment integrity checks; delete source only after destination verification.
- Durable background jobs and idempotency for migration and automation.

## Phase 4
- Authenticated remote MCP server with least-privilege tool surface.
- ChatGPT plugin update to point at the deployed MCP endpoint.
- Audit trails, role-based access, consent-based automation policies, UI, continuous integration and end-to-end tests.

## Security and verification priorities
- No secrets in Git or chat; require TLS, token encryption and rotation.
- DNS rebinding/SSRF defense for custom server targets; egress policy at deployment.
- Bound data volumes, request sizes and rate limits, including attachment total size.
- Never infer safe-sender trust from Inbox moves.
- Do not claim `sent` means delivered to the recipient.
- No production readiness until OAuth, encrypted secrets, host restrictions and end-to-end tests have passed.
