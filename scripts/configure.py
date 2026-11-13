"""Generate first-run deployment configuration without host Python dependencies.

Invoked inside the built container with a writable /workspace mount. Does not
install software, make network requests, overwrite existing secrets or migrate data.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import os
from pathlib import Path
import re
import secrets
import sys


def read_env(path: Path) -> dict[str, str]:
    """Read our single-line dotenv format; never evaluate shell expansions."""
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError("Existing .env has an unsupported line; no changes made")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in result:
            raise ValueError("Existing .env has an invalid or duplicate key; no changes made")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError("Existing .env has an unsupported quoted value")
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        result[key] = value
    return result


def validate_domain(domain: str) -> str:
    domain = domain.lower()
    if (len(domain) > 253 or "." not in domain or
            any(domain.endswith(x) for x in (".local", ".localhost", ".internal", ".test", ".invalid", ".home.arpa")) or
            not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in domain.split("."))):
        raise ValueError("Server mode requires a public DNS hostname, not a URL, path, wildcard or IP address")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("Server mode requires a DNS hostname, not an IP address")


def initialize(directory: Path, mode: str, port: int = 8000, domain: str = "") -> tuple[dict, bool]:
    if mode not in ("local", "server"):
        raise ValueError("Choose local or server mode")
    if not 1024 <= port <= 65535:
        raise ValueError("Local port must be between 1024 and 65535")
    if mode == "server":
        domain = validate_domain(domain)
    elif domain:
        raise ValueError("A domain is only used in server mode")
    expected_origin = f"http://localhost:{port}" if mode == "local" else f"https://{domain}"
    directory = directory.resolve(strict=True)
    path = directory / ".env"
    if path.is_symlink():
        raise ValueError("Refusing to read or write a symbolic-link .env")
    if path.exists():
        values = read_env(path)
        try:
            master = base64.b64decode(values["UNIVERSALMAIL_MASTER_KEY"], altchars=b"-_", validate=True)
            valid = len(master) == 32 and len(values["UNIVERSALMAIL_API_KEY"]) >= 32 and not values["UNIVERSALMAIL_API_KEY"].startswith("replace-")
        except (KeyError, ValueError):
            valid = False
        if not valid:
            raise ValueError("Existing .env contains missing/placeholder keys. It was NOT overwritten. Back it up and resolve configuration before starting")
        if (values.get("UNIVERSALMAIL_PUBLIC_URL", "").rstrip("/") != expected_origin or
                values.get("UNIVERSALMAIL_DEPLOYMENT_MODE", mode) != mode):
            raise ValueError("Existing deployment mode/origin differs. Use a separate checkout/configuration for the new target; existing secrets were NOT changed")
        if mode == "server" and (values.get("UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST", "false") != "false" or values.get("UNIVERSALMAIL_TLS_DOMAIN") != domain):
            raise ValueError("Existing server configuration does not match the requested HTTPS deployment")
        if mode == "local" and values.get("UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST") != "true":
            raise ValueError("Local HTTP requires UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST=true")
        if int(values.get("UNIVERSALMAIL_HOST_PORT", "8000")) != port and mode == "local":
            raise ValueError("Existing local port differs from the requested port")
        if os.name == "posix":
            path.chmod(0o600)
        return values, False
    values = {
        "UNIVERSALMAIL_MASTER_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "UNIVERSALMAIL_API_KEY": secrets.token_urlsafe(48),
        "UNIVERSALMAIL_DB_PATH": "./data/accounts.db",
        "UNIVERSALMAIL_DEPLOYMENT_MODE": mode,
        "UNIVERSALMAIL_PUBLIC_URL": expected_origin,
        "UNIVERSALMAIL_HOST_PORT": str(port),
        "UNIVERSALMAIL_ALLOW_INSECURE_LOCALHOST": "true" if mode == "local" else "false",
        "UNIVERSALMAIL_ALLOW_PRIVATE_MAIL_HOSTS": "false",
        "UNIVERSALMAIL_TLS_DOMAIN": domain,
        "GOOGLE_CLIENT_ID": "",
        "GOOGLE_CLIENT_SECRET": "",
        "MICROSOFT_CLIENT_ID": "",
        "MICROSOFT_CLIENT_SECRET": "",
        "MICROSOFT_TENANT": "common",
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("# Private UniversalMail settings. Keep this file and the data volume together in backups.\n")
        stream.write("# Provider app credentials can instead be saved encrypted through /setup.\n")
        for key, value in values.items():
            stream.write(f"{key}={value}\n")
    return values, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--mode", choices=("local", "server"), default="local")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--domain", default="")
    args = parser.parse_args()
    try:
        values, created = initialize(args.directory, args.mode, args.port, args.domain)
        print("Created private .env" if created else "Reusing existing configuration; keys unchanged")
        print("Setup page: " + values["UNIVERSALMAIL_PUBLIC_URL"] + "/setup")
        print("No mailbox is connected and no mail has been sent.")
        return 0
    except (OSError, ValueError) as exc:
        # Errors contain no secret values.
        print("Setup stopped: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
