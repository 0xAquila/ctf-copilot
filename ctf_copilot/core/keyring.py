"""
CTF Copilot — Keyring (AES-128 Fernet encryption for sensitive config values).

All API keys are encrypted at rest using a machine-local master key stored at
~/.ctf_copilot/.keyring (chmod 600 on POSIX).  The plaintext never touches
disk after the initial wizard entry — only the Fernet token is written to
config.yaml.

How it works:
  1. On first use, a random 32-byte Fernet key is generated and saved.
  2. `encrypt(plaintext)` returns a base64 Fernet token (starts with "gAAAAAB").
  3. `decrypt(token)` recovers the plaintext; returns the value unchanged if
     it looks like plain text (backwards-compatible with old installs).
  4. `is_encrypted(value)` lets callers check without try/except.

Fields that are always encrypted when non-empty:
  api_key, groq_api_key, nvd_api_key, htb_api_key, thm_api_key
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_KEYRING_FILE = Path.home() / ".ctf_copilot" / ".keyring"

# Config fields that must be encrypted at rest
ENCRYPTED_FIELDS: frozenset[str] = frozenset({
    "api_key",
    "groq_api_key",
    "nvd_api_key",
    "htb_api_key",
    "thm_api_key",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_fernet():
    """Load or generate the Fernet master key, returning a Fernet instance."""
    from cryptography.fernet import Fernet

    _KEYRING_FILE.parent.mkdir(parents=True, exist_ok=True)

    if _KEYRING_FILE.exists():
        raw = _KEYRING_FILE.read_bytes().strip()
    else:
        raw = Fernet.generate_key()
        _KEYRING_FILE.write_bytes(raw)
        # Restrict permissions on POSIX (600 = owner read/write only)
        if sys.platform != "win32":
            try:
                os.chmod(_KEYRING_FILE, 0o600)
            except OSError:
                pass

    return Fernet(raw)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_encrypted(value: str) -> bool:
    """
    Return True if value looks like a Fernet token.
    Fernet tokens are base64url-encoded and always start with "gAAAAAB".
    """
    return bool(value) and value.startswith("gAAAAAB") and len(value) > 60


def encrypt(plaintext: str) -> str:
    """
    Encrypt a plaintext string.  Returns a Fernet token (base64 ASCII).
    Returns the original string unchanged if it's empty.
    """
    if not plaintext:
        return plaintext
    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """
    Decrypt a Fernet token.  Returns the original string if:
      - The value is empty
      - The value doesn't look like a Fernet token (plain-text fallback)
      - Decryption fails for any reason (wrong key, corrupted token)
    """
    if not token or not is_encrypted(token):
        return token
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return token  # Graceful fallback — never crash on key read


def keyring_path() -> Path:
    """Return the path to the master key file."""
    return _KEYRING_FILE


def keyring_exists() -> bool:
    """Return True if the master key file exists."""
    return _KEYRING_FILE.exists()
