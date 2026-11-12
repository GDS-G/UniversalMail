"""Encrypted account vault and inbound server restrictions."""
import ipaddress
import os
import socket
from functools import lru_cache

from cryptography.fernet import Fernet


@lru_cache(maxsize=1)
def cipher() -> Fernet:
    key = os.getenv("UNIVERSALMAIL_MASTER_KEY", "")
    if not key or key.startswith("replace-"):
        raise RuntimeError("UNIVERSALMAIL_MASTER_KEY must contain a generated Fernet key")
    return Fernet(key.encode())


def encrypt_secret(value: str) -> str:
    return cipher().encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return cipher().decrypt(value.encode()).decode()


def validate_mail_hostname(hostname: str, port: int) -> None:
    if not hostname or "/" in hostname or len(hostname) > 253:
        raise ValueError("Invalid mail server hostname")
    if not 1 <= port <= 65535:
        raise ValueError("Invalid mail server port")
    if os.getenv("UNIVERSALMAIL_ALLOW_PRIVATE_MAIL_HOSTS", "false").lower() == "true":
        return
    try:
        resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Mail server DNS lookup failed") from exc
    if not resolved:
        raise ValueError("Mail server has no DNS records")
    for addr in resolved:
        ip = ipaddress.ip_address(addr[4][0])
        if not ip.is_global:
            raise ValueError("Mail server resolves to a non-public IP address")
