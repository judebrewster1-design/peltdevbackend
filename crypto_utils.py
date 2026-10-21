"""
Encrypts store-owner IMAP credentials before they touch the database.

The key lives ONLY on disk in secret.key (never in the DB, never in git).
Anyone deploying this for real should keep secret.key backed up somewhere
separate from the database backup — if you lose it, every store owner has
to re-enter their email credentials.
"""
import os
from cryptography.fernet import Fernet

KEY_PATH = os.path.join(os.path.dirname(__file__), "secret.key")


def _get_key():
    if not os.path.exists(KEY_PATH):
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        os.chmod(KEY_PATH, 0o600)
    with open(KEY_PATH, "rb") as f:
        return f.read()


_fernet = None


def _f():
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_get_key())
    return _fernet


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _f().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    return _f().decrypt(token.encode()).decode()
