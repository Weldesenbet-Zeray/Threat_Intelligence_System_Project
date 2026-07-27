"""
secrets_manager.py
Part C control: Encryption + secure secrets handling.

Fixes the vulnerability found in BDS_TI_Project.ipynb (Section 13), where
VT_API_KEY and ABUSE_API_KEY were hardcoded in plaintext inside the notebook.

What this module does:
1. Loads API keys from a local ".env" file (never hardcoded, never committed).
2. Derives a Fernet encryption key from a passphrase (PBKDF2-HMAC-SHA256).
3. Provides encrypt_file()/decrypt_file() so the SQLite DB or CSV exports
   can be stored encrypted at rest, and a helper to encrypt/decrypt single
   string values (e.g. if you want to store the API keys themselves
   encrypted on disk instead of as plain env vars).

Run directly (`python secrets_manager.py`) for a self-test that proves
encryption round-trips correctly.
"""

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
SALT_PATH = os.path.join(os.path.dirname(__file__), "vault.salt")

load_dotenv(ENV_PATH)


def get_api_key(name: str) -> str:
    """Read a required secret from the environment (loaded from .env)."""
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set. Copy .env.example to .env and fill it in."
        )
    return value


def _load_or_create_salt() -> bytes:
    """Persist a random salt once, reuse it so the derived key is stable."""
    if os.path.exists(SALT_PATH):
        with open(SALT_PATH, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_PATH, "wb") as f:
        f.write(salt)
    return salt


def get_fernet() -> Fernet:
    """Derive a Fernet cipher from VAULT_PASSPHRASE (never store the raw key)."""
    passphrase = get_api_key("VAULT_PASSPHRASE").encode()
    salt = _load_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    return Fernet(key)


def encrypt_file(path: str) -> str:
    """Encrypt a file in place, writing <path>.enc. Returns the new path."""
    fernet = get_fernet()
    with open(path, "rb") as f:
        data = f.read()
    token = fernet.encrypt(data)
    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(token)
    return out_path


def decrypt_file(enc_path: str, out_path: str) -> str:
    """Decrypt a .enc file back to plaintext at out_path."""
    fernet = get_fernet()
    with open(enc_path, "rb") as f:
        token = f.read()
    try:
        data = fernet.decrypt(token)
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed - wrong passphrase or the file was tampered with."
        ) from exc
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


if __name__ == "__main__":
    print("=" * 60)
    print("SECRETS MANAGER SELF-TEST")
    print("=" * 60)

    sample_path = os.path.join(os.path.dirname(__file__), "_selftest.txt")
    with open(sample_path, "w", encoding="utf-8") as f:
        f.write("this is a self-test file for encryption\n")

    enc_path = encrypt_file(sample_path)
    print(f"Encrypted  : {enc_path}")

    restored_path = sample_path + ".restored"
    decrypt_file(enc_path, restored_path)
    print(f"Decrypted  : {restored_path}")

    with open(sample_path, encoding="utf-8") as f:
        original = f.read()
    with open(restored_path, encoding="utf-8") as f:
        restored = f.read()

    assert original == restored, "Round-trip failed!"
    print("Round-trip verified: OK")

    for p in (sample_path, enc_path, restored_path):
        os.remove(p)
    print("Self-test files cleaned up.")
