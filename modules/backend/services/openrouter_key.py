#!/usr/bin/env python3
"""One OpenRouter API key for Settings -> Agentic and Settings -> Timesketch.

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
    on = _agentic_online(load_frontend_config())
    key = (on.get("api_key") or "").strip() if on.get("provider") == "openrouter" else ""
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
    ('' removes it). from_timesketch: also carry the change into an Agentic
    OpenRouter key that is already set (see the module docstring for why an
    empty one is left alone).
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
    if from_timesketch:
        cfg = load_frontend_config() or {}
        on = _agentic_online(cfg)
        if on.get("provider") == "openrouter" and on.get("api_key") and on["api_key"] != value:
            on["api_key"] = value
            save_frontend_config({"agentic": cfg["agentic"]})
    return value


def mask(key):
    """Same shape GET /api/config uses: bullets plus the last four."""
    if not key:
        return ""
    return MASK * 2 + key[-4:] if len(key) > 4 else MASK * 2
