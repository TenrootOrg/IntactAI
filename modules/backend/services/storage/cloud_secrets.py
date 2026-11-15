#!/usr/bin/env python3
"""Cloud credentials (Settings -> Cloud): encrypted at rest, deleted when they expire.

The cloud settings live in frontend_config["cloud"]. Its credential fields used
to be stored in clear inside intact.db, so any copy of the database file held a
working AWS / Azure credential (the DB download and the JSON export already
blank them; a raw copy of the file did not).

ENCRYPTION. The four credential fields are stored as "enc:v1:<Fernet token>"
(AES-128-CBC + HMAC-SHA256, from `cryptography`). The key is one random per-box
key in data/state/backend/cloud_secrets.key, created on first use, mode 0600 in
a 0700 directory owned by root: never in the database, an export, git or a
support bundle. A copy of intact.db alone cannot be decrypted. Limits, by
design: the app must decrypt unattended to run scans, so root on the host (and
a copy of the whole data/ directory) can; a lost key file makes the stored
credentials unreadable, and they read as empty (enter them again).

EXPIRY. When a credential is saved, `credentials_saved_at` is stamped (UTC).
After `credentials_ttl_days` (default 30; 0 = never) the credential fields are
deleted, on the next read or by the housekeeping loop each minute, whichever
comes first. Non-secret settings (regions, tenant / client id, time window)
are kept so entering the credentials again is quick.

Every reader and writer of the "cloud" row goes through config_store, which
calls protect() before writing and reveal() after reading, so the rest of the
backend only ever sees plaintext and never has to know about either rule.
"""
import copy
import os
import threading
from datetime import datetime, timedelta, timezone

from .base import STORAGE_BASE

# (section, field): the credentials. The AWS access key id is not secret on its
# own, but it is half of the credential, so it is protected and expired too.
FIELDS = (("aws", "access_key_id"), ("aws", "secret_access_key"),
          ("aws", "session_token"), ("azure", "client_secret"))
PREFIX = "enc:v1:"
TTL_KEY, SAVED_KEY, EXPIRED_KEY = "credentials_ttl_days", "credentials_saved_at", "credentials_expired_at"
DEFAULT_TTL_DAYS = 30
MAX_TTL_DAYS = 3650

_KEY_LOCK = threading.Lock()
_FERNET = [None]


def key_path() -> str:
    return os.environ.get("INTACT_CLOUD_KEY_PATH") or os.path.join(STORAGE_BASE, "state", "backend",
                                                                  "cloud_secrets.key")


def _fernet():
    """The box's Fernet, creating its key file the first time (0600, dir 0700)."""
    if _FERNET[0] is not None:
        return _FERNET[0]
    from cryptography.fernet import Fernet
    with _KEY_LOCK:
        if _FERNET[0] is None:
            path = key_path()
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
                # O_EXCL: two workers racing here cannot both write a key.
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(Fernet.generate_key())
                    print(f"[CLOUD] created the cloud-credential key {path}", flush=True)
                except FileExistsError:
                    pass
            with open(path, "rb") as f:
                _FERNET[0] = Fernet(f.read().strip())
    return _FERNET[0]


def _now():
    return datetime.now(timezone.utc)


def _fields(cfg):
    for section, field in FIELDS:
        sec = cfg.get(section) if isinstance(cfg, dict) else None
        if isinstance(sec, dict):
            yield sec, field


def ttl_days(cfg) -> int:
    try:
        n = int((cfg or {}).get(TTL_KEY, DEFAULT_TTL_DAYS))
    except (TypeError, ValueError):
        return DEFAULT_TTL_DAYS
    return min(max(n, 0), MAX_TTL_DAYS)


def has_credentials(cfg) -> bool:
    return any(sec.get(field) for sec, field in _fields(cfg))


def expires_at(cfg):
    """When the credentials go (aware datetime), or None: none saved / never."""
    days, saved = ttl_days(cfg), (cfg or {}).get(SAVED_KEY)
    if not days or not saved or not has_credentials(cfg):
        return None
    try:
        when = datetime.fromisoformat(str(saved))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when + timedelta(days=days)


def protect(new_plain, old_plain=None):
    """What to store for `new_plain`: credentials encrypted, saved-at stamped
    when a credential changed (old_plain: the plaintext stored before)."""
    cfg = copy.deepcopy(new_plain) if isinstance(new_plain, dict) else {}
    old = old_plain if isinstance(old_plain, dict) else {}
    cfg[TTL_KEY] = ttl_days(cfg)
    def val(c, s, f):
        sec = c.get(s)
        return str((sec.get(f) if isinstance(sec, dict) else "") or "")
    changed = any(val(cfg, s, f) != val(old, s, f) for s, f in FIELDS)
    if not has_credentials(cfg):
        cfg.pop(SAVED_KEY, None)
    elif changed or not old.get(SAVED_KEY):
        cfg[SAVED_KEY] = _now().isoformat(timespec="seconds")
        cfg.pop(EXPIRED_KEY, None)
    else:
        cfg[SAVED_KEY] = old.get(SAVED_KEY)
    f = None
    for sec, field in _fields(cfg):
        v = sec.get(field)
        if v and not str(v).startswith(PREFIX):
            f = f or _fernet()
            sec[field] = PREFIX + f.encrypt(str(v).encode()).decode()
    return cfg


def reveal(stored):
    """(plaintext config, needs_rewrite). Decrypts the credentials; a value that
    is still plaintext (stored before this existed) is returned as is and asks
    for a rewrite, so it gets encrypted. Expired credentials come back deleted,
    also asking for a rewrite."""
    if not isinstance(stored, dict):
        return stored, False
    cfg = copy.deepcopy(stored)
    rewrite = False
    for sec, field in _fields(cfg):
        v = sec.get(field)
        if not v:
            continue
        if str(v).startswith(PREFIX):
            try:
                sec[field] = _fernet().decrypt(str(v)[len(PREFIX):].encode()).decode()
            except Exception as e:             # noqa: BLE001 -- wrong/lost key, damaged value
                print(f"[CLOUD] cannot decrypt the stored {field} ({type(e).__name__}): "
                      f"enter the cloud credentials again", flush=True)
                sec[field] = ""
        else:
            rewrite = True                         # legacy plaintext: encrypt it now
    if has_credentials(cfg) and not cfg.get(SAVED_KEY):
        cfg[SAVED_KEY] = _now().isoformat(timespec="seconds")   # legacy: the clock starts today
        rewrite = True
    exp = expires_at(cfg)
    if exp and _now() >= exp:
        for sec, field in _fields(cfg):
            sec[field] = ""
        cfg.pop(SAVED_KEY, None)
        cfg[EXPIRED_KEY] = _now().isoformat(timespec="seconds")
        print(f"[CLOUD] cloud credentials deleted: older than {ttl_days(cfg)} day(s) "
              f"(Settings -> Cloud)", flush=True)
        rewrite = True
    return cfg, rewrite


def status(cfg) -> dict:
    """What Settings -> Cloud shows: never a credential, only its dates."""
    exp = expires_at(cfg)
    return {TTL_KEY: ttl_days(cfg), SAVED_KEY: (cfg or {}).get(SAVED_KEY) or "",
            "credentials_expire_at": exp.isoformat(timespec="seconds") if exp else "",
            EXPIRED_KEY: (cfg or {}).get(EXPIRED_KEY) or ""}
