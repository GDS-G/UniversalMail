"""Single-owner SQLite vault; credentials and OAuth transaction data are encrypted."""
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from .security import decrypt_secret, encrypt_secret


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@contextmanager
def connection():
    path = Path(os.getenv("UNIVERSALMAIL_DB_PATH", "./data/accounts.db"))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    con = sqlite3.connect(path, timeout=45, isolation_level=None)
    try:
        if os.name == "posix":
            path.chmod(0o600)
        con.execute("BEGIN IMMEDIATE")
        con.execute("""CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
            kind TEXT NOT NULL, secrets TEXT NOT NULL, subject TEXT)""")
        if "subject" not in {row[1] for row in con.execute("PRAGMA table_info(accounts)")}:
            con.execute("ALTER TABLE accounts ADD COLUMN subject TEXT")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS account_identity ON accounts(kind,subject) WHERE subject IS NOT NULL")
        con.execute("""CREATE TABLE IF NOT EXISTS oauth_states (
            state_hash TEXT PRIMARY KEY, provider TEXT NOT NULL,
            browser_hash TEXT NOT NULL, expires REAL NOT NULL, payload TEXT NOT NULL)""")
        con.commit()
        yield con
    finally:
        if con.in_transaction:
            con.rollback()
        con.close()


def _record(row) -> dict | None:
    if row is None:
        return None
    return dict(id=row[0], name=row[1], email=row[2], kind=row[3],
                config=json.loads(decrypt_secret(row[4])), subject=row[5])


def add_account(name: str, email: str, kind: str, config: dict) -> str:
    account_id = uuid4().hex
    with connection() as con:
        con.execute("INSERT INTO accounts(id,name,email,kind,secrets) VALUES (?,?,?,?,?)",
                    (account_id, name, email, kind, encrypt_secret(json.dumps(config))))
    return account_id


def list_accounts() -> list[dict]:
    with connection() as con:
        rows = con.execute("SELECT id,name,email,kind FROM accounts ORDER BY name").fetchall()
    return [dict(zip(("id", "name", "email", "kind"), row)) for row in rows]


def get_account(account_id: str) -> dict | None:
    with connection() as con:
        return _record(con.execute("SELECT id,name,email,kind,secrets,subject FROM accounts WHERE id=?", (account_id,)).fetchone())


def delete_account(account_id: str) -> bool:
    with connection() as con:
        return con.execute("DELETE FROM accounts WHERE id=?", (account_id,)).rowcount > 0


def save_oauth_account(name: str, email: str, kind: str, subject: str, config: dict) -> str:
    """Reconnect only the same provider identity; never trust a caller-supplied email."""
    with connection() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT id,secrets FROM accounts WHERE kind=? AND subject=?", (kind, subject)).fetchone()
        if row is None:
            row = con.execute("SELECT id,secrets FROM accounts WHERE kind=? AND lower(email)=lower(?) AND subject IS NULL ORDER BY id LIMIT 1", (kind, email)).fetchone()
        account_id = row[0] if row else uuid4().hex
        config = dict(config)
        if not config.get("refresh_token") and row:
            old = json.loads(decrypt_secret(row[1]))
            if old.get("client_id") == config.get("client_id"):
                config["refresh_token"] = old.get("refresh_token")
        if not config.get("refresh_token"):
            raise ValueError("Provider did not grant offline access; reconnect and grant consent")
        encrypted = encrypt_secret(json.dumps(config))
        con.execute("""INSERT INTO accounts(id,name,email,kind,secrets,subject) VALUES (?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET name=excluded.name,email=excluded.email,
            secrets=excluded.secrets,subject=excluded.subject""", (account_id, name, email, kind, encrypted, subject))
        con.commit()
    return account_id


@contextmanager
def token_session(account_id: str):
    """Serialize token refresh across workers; suitable for a single-owner SQLite service."""
    with connection() as con:
        con.execute("BEGIN IMMEDIATE")
        account = _record(con.execute("SELECT id,name,email,kind,secrets,subject FROM accounts WHERE id=?", (account_id,)).fetchone())
        if account is None:
            raise LookupError("Account not found")
        yield account
        con.execute("UPDATE accounts SET secrets=? WHERE id=?", (encrypt_secret(json.dumps(account["config"])), account_id))
        con.commit()


def create_state(provider: str, payload: dict) -> tuple[str, str]:
    state, browser = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = time.time()
    with connection() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM oauth_states WHERE expires<=?", (now,))
        if con.execute("SELECT count(*) FROM oauth_states").fetchone()[0] >= 100:
            raise ValueError("Too many pending sign-ins; finish one or retry after ten minutes")
        con.execute("INSERT INTO oauth_states VALUES (?,?,?,?,?)", (digest(state), provider, digest(browser), now + 600, encrypt_secret(json.dumps(payload))))
        con.commit()
    return state, browser


def consume_state(state: str, provider: str, browser: str) -> dict:
    """Atomically validate browser/provider binding and consume exactly once."""
    with connection() as con:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT provider,browser_hash,expires,payload FROM oauth_states WHERE state_hash=?", (digest(state),)).fetchone()
        if (row is None or row[0] != provider or row[2] <= time.time() or not browser
                or not secrets.compare_digest(row[1], digest(browser))):
            raise ValueError("Invalid, expired, or wrong-browser sign-in; start again")
        con.execute("DELETE FROM oauth_states WHERE state_hash=?", (digest(state),))
        con.commit()
        return json.loads(decrypt_secret(row[3]))
