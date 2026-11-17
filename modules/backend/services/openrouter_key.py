#!/usr/bin/env python3
"""One OpenRouter API key for Case Analysis, the decision model and Timesketch.

2026-11-17: one key, entered once, for all three (the models stay per section).
Wherever it is saved -- Settings -> Agentic (model or decision model) or
Settings -> Timesketch -- it is the key of every OpenRouter user on the box:
  - Case Analysis's OpenRouter copy (online_llm.api_key) follows, an empty one
    included: setting the key turns OpenRouter on for Case Analysis too.
  - The decision model reads it directly (decision_model._key), no copy.
  - Timesketch: an Agentic save rewrites timesketch.conf through the Timesketch
    settings workflow (routes/timesketch_llm_routes.start_shared_key_sync), which
    restarts Timesketch's four processes in parallel and only when the file
    changed. Timesketch's own AI features stay off until a user turns them on.
Earlier rules (kept below for the history): the sharing was one-way and never
filled an empty Agentic key.

QA (2026-11): "enter openrouter api in agentic tab, move to timesketch: you
should enter it again". The two sections kept separate copies -- Agentic in
frontend_config (agentic.online_llm.api_key), Timesketch only inside the
timesketch.conf it renders -- and neither ever looked at the other. The models
stay per section; only the key is shared.

The shared copy lives in the `secrets` table, not frontend_config: that table
never enters export_db()/import_db() and the DB download blanks it, so the key
gets no new way off the box and an import cannot plant one.

The two section copies still exist, because that is what the runtimes read:
online_llm.api_key for Case Analysis (many readers), timesketch.conf for
Timesketch (read at container start). They follow the shared key like this:
  - Agentic Save (provider OpenRouter) sets the shared key. timesketch.conf is
    NOT rewritten: that needs a Timesketch restart, which an Agentic save must
    not cause. GET /api/timesketch/config/llm reports it as pending instead.
  - Timesketch Save (provider OpenRouter) sets the shared key and REPLACES an
    OpenRouter key Agentic already uses (rotation). It never fills an EMPTY
    Agentic key: that would turn Case Analysis's cloud AI on -- case data
    leaving the box, auto-generated reports billing tokens -- from the
    Timesketch tab. GET /api/config shows the shared key there, flagged, and
    the operator's next Agentic Save puts it in force.
  - An emptied field is "remove the key": one key, so it goes from the shared
    copy (and from an Agentic copy, on a Timesketch save) too.
"""

import re

from services.storage.config_store import load_frontend_config, save_frontend_config
from services.storage.secret_store import delete_secret, get_secret, set_secret

SECRET = "openrouter_api_key"
# Set once the one-time adoption below has run, so a key the operator later
# REMOVED is not re-adopted from a copy that still holds it (timesketch.conf
# keeps its key until Timesketch is saved).
_ADOPTED = "openrouter_api_key_adopted"
# What every GET substitutes for a saved key; anything sent back with this
# prefix means "keep the stored one".
MASK = "••••"
TIMESKETCH_CONF = "/app/config/timesketch/timesketch.conf"


def read_conf_value(content, ts_provider, conf_key):
    """Pull one provider field out of timesketch.conf, '' if absent.

    Find the provider dict, then the key inside it. `[^}]*` keeps the match
    from wandering past the end of that provider's block.
    """
    match = re.search(
        r"'" + re.escape(ts_provider) + r"':\s*\{[^}]*'"
        + re.escape(conf_key) + r"':\s*'([^']*)'",
        content)
    return match.group(1) if match else ""


def conf_key(path=None):
    """The OpenRouter key timesketch.conf holds now ('' if none / no file)."""
    try:
        with open(path or TIMESKETCH_CONF) as f:
            return read_conf_value(f.read(), "openrouter", "api_key")
    except OSError:
        return ""


def _agentic_online(cfg):
    ag = (cfg or {}).get("agentic")
    on = ag.get("online_llm") if isinstance(ag, dict) else None
    return on if isinstance(on, dict) else {}


def get():
    """The shared OpenRouter key, '' when there is none.

    The first call on a box that predates sharing adopts whichever section
    already has one. Both differ: Agentic's wins -- it is the copy the backend
    tests and Case Analysis runs on; timesketch.conf is a rendered file.
    Timesketch keeps running on its own key until its section is saved, and
    its GET says the key is pending until then.
    """
    key = get_secret(SECRET)
    if key or get_secret(_ADOPTED):
        return key or ""
    cfg = load_frontend_config() or {}
    on = _agentic_online(cfg)
    key = (on.get("api_key") or "").strip() if on.get("provider") == "openrouter" else ""
    if not key:                         # the decision model's own key (OpenRouter is its default)
        dm = ((cfg.get("agentic") or {}).get("decision_model") or {})
        if (dm.get("provider") or "openrouter") == "openrouter":
            key = (dm.get("api_key") or "").strip()
    if key.startswith(MASK):            # never adopt a mask as a key
        key = ""
    key = key or conf_key()
    if key:
        set_secret(SECRET, key)
    set_secret(_ADOPTED, "1")
    return key


def save(value, from_timesketch=False):
    """Apply what a Settings form sent as the OpenRouter key; returns the real key.

    Masked -> the stored key, unchanged. Anything else becomes the shared key
    ('' removes it) and every copy follows: Case Analysis's OpenRouter copy (an
    empty one too), and -- unless the Timesketch save itself is writing its
    file (from_timesketch) -- Timesketch.
    """
    current = get()
    if isinstance(value, str) and value.startswith(MASK):
        return current
    value = (value or "").strip() if isinstance(value, str) else ""
    if value == current:
        return current
    if value:
        set_secret(SECRET, value)
    else:
        delete_secret(SECRET)
    cfg = load_frontend_config() or {}
    on = _agentic_online(cfg)
    if on.get("provider") == "openrouter" and on.get("api_key") != value:
        on["api_key"] = value
        save_frontend_config({"agentic": cfg["agentic"]})
    if not from_timesketch:
        _sync_timesketch()
    return value


def _sync_timesketch():
    """Carry the key into timesketch.conf (a background settings run). Never fails
    the save that called it: Settings -> Timesketch shows the key as pending then."""
    try:
        from routes.timesketch_llm_routes import start_shared_key_sync
        start_shared_key_sync()
    except Exception as e:                                   # noqa: BLE001
        print(f"[OPENROUTER] could not hand the key to Timesketch: {e}", flush=True)


def mask(key):
    """Same shape GET /api/config uses: bullets plus the last four."""
    if not key:
        return ""
    return MASK * 2 + key[-4:] if len(key) > 4 else MASK * 2
