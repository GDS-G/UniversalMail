# Test scope — backend 0.5.0

Local result: **103 passed**, using `python -m pytest -q`. This includes 68 earlier
mail/OAuth regression tests and 35 setup/deployment tests. Python source and setup
JavaScript syntax checks pass. Provider responses are simulated; no actual provider
account is connected and no mail is sent by these tests.

Coverage includes OAuth state/PKCE/replay and wrong-browser rejection; token
rotation/cache; Gmail filters and read-back checks; MIME/Bcc; native pagination;
targeted IMAP moves; partial SMTP acceptance; API auth; secret redaction; setup-key
generation and preservation; encrypted provider app configuration; callback origin
configuration; server hostname validation; and loopback-only local port binding.

CI is configured for Python 3.12/3.13, Windows PowerShell parsing/read-only preflight
with a mocked Docker CLI, and Linux Docker build/start/readiness/authentication.
It also validates the Caddy configuration without obtaining a certificate. Consult
the actual GitHub Actions result for this commit before claiming those jobs passed.

Not verified on the user's PC: Docker Desktop installation, Windows Docker startup,
provider app registration, real OAuth consent, mail delivery, Bcc at destination,
phishing/spam reports, Safe Senders, calendars, migration or ChatGPT MCP connectivity.
Public DNS and TLS certificate issuance need an authorized actual server. Automated
unit tests and a healthy container are not evidence of those separate outcomes.
