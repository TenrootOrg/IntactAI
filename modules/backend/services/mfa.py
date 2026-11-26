#!/usr/bin/env python3
"""Two-step login: TOTP authenticator codes (RFC 6238) and recovery codes.

Standard library only, and nothing here talks to a network: the appliance is
often air-gapped. The phone (or a hardware/desktop TOTP tool) computes the same
6 digits from the shared secret and the time, offline, so the only thing that
can break it is the clock -- see VALID_WINDOW.

The secret is stored encrypted with the box's Fernet key (the same root-only
key file as the cloud credentials and the tool-account vault); recovery codes
are stored only as hashes and work once each.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

DIGITS = 6
STEP = 30
# One step either side: a code from 30 s early to 30 s late still counts. An
# air-gapped box's clock drifts; the login page warns when the browser's clock
# and the appliance's differ by more than a minute.
VALID_WINDOW = 1
ISSUER = "Intact.AI"
RECOVERY_CODES = 10


def new_secret() -> str:
    """160 random bits, base32 without padding (what authenticator apps take)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int) -> str:
    mac = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    num = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(num % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: Optional[float] = None) -> int:
    return int((time.time() if now is None else now) // STEP)


def verify(secret: str, code: str, last_step: int = -1,
           now: Optional[float] = None) -> Optional[int]:
    """The matching time step, or None. A step at or before `last_step` (the
    last one accepted for this user) is refused, so a code seen over a
    shoulder cannot be replayed inside its 30 s."""
    code = (code or "").strip().replace(" ", "")
    # isascii: str.isdigit() also accepts e.g. "²", which compare_digest rejects.
    if len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    step = current_step(now)
    for s in range(step - VALID_WINDOW, step + VALID_WINDOW + 1):
        if s > last_step and hmac.compare_digest(code_at(secret, s), code):
            return s
    return None


def otpauth_uri(secret: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}", safe=":@")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


# --- recovery codes -------------------------------------------------------------

_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o, 1/l/i: read off paper


def _norm(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def hash_recovery(code: str, salt: str) -> str:
    """HMAC keyed per user (`salt`): a copy of the database alone does not let
    one table of guesses cover every user's codes."""
    return hmac.new(("intact-recovery:" + salt).encode(), _norm(code).encode(),
                    hashlib.sha256).hexdigest()


def new_recovery_codes(salt: str) -> Tuple[List[str], List[str]]:
    """(codes to show once, their hashes to store). Ten 10-character codes
    (~49 bits each), shown as xxxx-xxxx-xx."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        codes.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
    return codes, [hash_recovery(c, salt) for c in codes]


def use_recovery(code: str, hashes: List[str], salt: str) -> Optional[List[str]]:
    """The remaining hashes when `code` matched one (it is spent), else None."""
    h = hash_recovery(code, salt)
    # The unsalted form 4773a3b2 stored (never released; kept so a dev box's
    # codes still work until that user sets two-step login up again).
    old = hashlib.sha256(("intact-recovery:" + _norm(code)).encode()).hexdigest()
    for i, stored in enumerate(hashes):
        if hmac.compare_digest(stored, h) or hmac.compare_digest(stored, old):
            return hashes[:i] + hashes[i + 1:]
    return None
