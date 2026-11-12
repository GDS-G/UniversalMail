"""Encrypted SQLite account configuration store."""
import json
import os
import sqlite3
from pathlib import Path
from uuid import uuid4

from .security import encrypt_secret, decrypt_secret


def _connect():
    path = Path(os.getenv("UNIVERSALMAIL_DB_PATH", "./data/accounts.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
        kind TEXT NOT NULL, secrets TEXT NOT NULL
    )""")
    con.commit()
    return con


def add_account(name: str, email: str, kind: str, config: dict) -> str:
    account_id = uuid4().hex
    with _connect() as con:
        con.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", (
            account_id, name, email, kind, encrypt_secret(json.dumps(config))
        ))
    return account_id


def list_accounts() -> list[dict]:
    with _connect() as con:
        rows = con.execute("SELECT id, name, email, kind FROM accounts ORDER BY name").fetchall()
    return [dict(zip(("id", "name", "email", "kind"), r)) for r in rows]


def get_account(account_id: str) -> dict | None:
    with _connect() as con:
        row = con.execute("SELECT id,name,email,kind,secrets FROM accounts WHERE id=?", (account_id,)).fetchone()
    if row is None:
        return None
    return dict(id=row[0], name=row[1], email=row[2], kind=row[3], config=json.loads(decrypt_secret(row[4])))


def delete_account(account_id: str) -> bool:
    with _connect() as con:
        cur = con.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        return cur.rowcount > 0
