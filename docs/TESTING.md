# Test scope — backend 0.4.0

Local result: **68 passed**, Python **3.13.5**, using `python -m pytest -q`. Source compilation also passed. The CI workflow is configured for Python 3.12 and 3.13; a configured workflow is not itself evidence of a completed CI run.

Coverage includes both provider OAuth redirects and mocked callbacks, S256 verifier binding, authenticated initiation, wrong-browser/provider/replay/expired-state rejection, declined consent, missing scopes, wrong-account rejection, reconnect identity, encrypted credential storage, refresh rotation/cache/concurrency, disallowed provider URLs, legacy vault migration, actual Gmail filter payloads and verification, MIME Bcc/HTML, native pagination, targeted IMAP moves and failures, partial SMTP acceptance, API authentication and error redaction.

Provider HTTP, mailbox and SMTP responses are simulated. No live provider consent, delivery, spam training, Safe Senders change, calendar action or cross-provider migration was exercised. Gmail/Graph Bcc is tested at the request/MIME boundary; privacy of received copies must also be confirmed in live integration testing.

The backend is not deployed, the Docker image has not been built/tested here, and the installed ChatGPT plugin has not been connected. HTTP smoke checks, where reported separately, only demonstrate local server responses.
