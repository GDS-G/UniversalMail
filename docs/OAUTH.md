# OAuth integration requirements

The native provider adapters now support a **stored OAuth refresh token** but the browser-based authorization-code/PKCE onboarding flow has not yet been implemented. Do not request or send tokens through chat. Do not use the refresh-token registration endpoint in production until the server is protected behind HTTPS and a private administrative boundary.

## Microsoft Graph
Register an Entra application with delegated permissions: Mail.ReadWrite, Mail.Send, Calendars.ReadWrite and offline_access. Admin consent may be required for organizational accounts. Set MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, and optionally MICROSOFT_TENANT. Some consumer accounts or organizations may restrict scopes. The backend sends HTML/MIME through the Graph sendMail endpoint.

## Gmail
Create a Google Cloud OAuth client with Gmail API enabled. Use least-privilege Gmail scopes for required actions: gmail.modify, gmail.send, gmail.settings.basic (filters), and potentially gmail.readonly; scope selection must match actual operations and OAuth consent verification. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET. Google Workspace admins can restrict access.

## Account registration
The provisional /accounts/native endpoint accepts refresh tokens for development under an authenticated local administration interface. It is **not** a complete end-user OAuth sign-in experience. Replace it with PKCE-based browser login, CSRF-bound state, consent screens, redirect URI validation, and rotating refresh token persistence before production.

## Provider distinctions
Gmail neverSpam filters provide persistent sender-level classification behavior. They are not a universal guarantee against every security system. Outlook Safe Senders list management is not implemented by the Microsoft Graph adapter and must not be confused with moving a message out of Junk. Reporting phishing requires provider-specific supported endpoints and is not yet implemented.
