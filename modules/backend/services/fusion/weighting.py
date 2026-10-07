"""Fusion weighting: what a detection is WORTH, decided by a rules catalogue.

WHY THIS EXISTS. 2026-10-07, a real two-server admin case: 133 of 148 findings
were HIGH -- WinRAR installers as "renamed binaries", a security agent's own
updater as a "suspicious service" 45 times, every website the admins visited as
"shared C2" -- and the report built an "active compromise since 2022" on them.
Each fix was a hand-written exception in a different file. Patterns like these
keep turning up, so the decisions live in one catalogue instead:

    config/fusion_weighting.yaml          shipped with the release, re-read per fuse
    <data>/fusion_weighting.local.yaml    this box's own rules and switches (optional,
                                          survives upgrades; checked FIRST)

Two kinds of rule:

  entity_rules   applied to every mapped entity as the graph is assembled. `when`
                 matches artifact (glob), entity type, flags, words in an attribute,
                 an attribute regex and/or a named CHECK; `then` sets a severity or
                 an anomaly score and adds/removes flags. First match wins.
  pattern_rules  graph-level patterns over findings (e.g. recurring maintenance):
                 a function registered with @pattern(name), its thresholds in YAML.

Every change is stamped on the item (attrs["weighting"]: rule, from, to, reason),
so the UI and the report can say WHY something weighs what it does.

Safety, built in: a rule never lowers a CRITICAL unless it says
`allow_lower_critical: true`; a broken rule is skipped and reported, never the
fuse; a catalogue that cannot be read leaves everything as mapped and says so.
Each rule carries `examples:`; tests/test_fusion_weighting_catalogue.py runs
every one, so a new rule needs no new test file.
"""
from __future__ import annotations

import fnmatch
import functools
import ipaddress
import os
import re
import threading

from . import severity as sev

CATALOGUE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                         "config", "fusion_weighting.yaml")
LOCAL_NAMES = ("/app/data/fusion_weighting.local.yaml",)

_LOCK = threading.Lock()
_CACHE: dict = {"key": None, "rules": None, "error": None}
_PATTERNS: dict = {}


# ---------------------------------------------------------------- named checks
# The vocabulary `when: {check: ...}` can use. Each takes the entity's attribute
# VALUES named in the rule's `args` and answers True/False. Add one here when a
# pattern needs logic a word list or a regex cannot express.

def _stem(v) -> str:
    v = str(v or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    v = v.rsplit(".", 1)[0] if "." in v else v
    return "".join(c for c in v if c.isalnum())


def same_program(name, original) -> bool:
    """The on-disk name is the ORIGINAL name plus a version / installer / copy
    suffix (winrar-x64-611.exe <- WinRAR.exe). A masquerade renames to a different
    name; an original shorter than 4 characters (cmd, sc) never qualifies."""
    n, o = _stem(name), _stem(original)
    return len(o) >= 4 and n != o and n.startswith(o)


_INSTALLER_NAME = re.compile(r"setup|install|\d{3,}|\d+\.\d+", re.I)


def installer_of_same_program(name, original) -> bool:
    """A downloaded INSTALLER of the program: its own name plus a version number
    (3+ digits or dotted) or a setup/install word -- winrar-x64-611.exe,
    putty-64bit-0.81-installer.msi <- the program's original name. Narrower than
    same_program on purpose: procdump64.exe <- procdump is the same program but
    the tool itself, and dual-use tools stay as the detection rated them."""
    return same_program(name, original) and bool(_INSTALLER_NAME.search(_stem_raw(name)))


def _stem_raw(v) -> str:
    v = str(v or "").replace("\\", "/").rsplit("/", 1)[-1]
    return v.rsplit(".", 1)[0] if "." in v else v


def local_ip(value) -> bool:
    """A private, link-local, loopback or reserved address -- the local network."""
    try:
        ip = ipaddress.ip_address(str(value or "").split(":")[0])
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_reserved


_VOWELS = set("aeiou")


def random_label(domain) -> bool:
    """The registrable label reads like a generated string (lzqmjakbblmvy): long
    and nearly vowel-free. ponytail: vowel ratio, not a DGA model."""
    parts = [p for p in str(domain or "").lower().split(".") if p]
    label = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")
    letters = [c for c in label if c.isalpha()]
    return len(letters) >= 8 and sum(c in _VOWELS for c in letters) / len(letters) < 0.25


CHECKS = {"same_program": same_program, "installer_of_same_program": installer_of_same_program,
          "local_ip": local_ip, "random_label": random_label}


def pattern(name):
    """Register a graph-level pattern function `fn(g, params) -> int` (rows changed)."""
    def deco(fn):
        _PATTERNS[name] = fn
        return fn
    return deco


# ------------------------------------------------------------------- catalogue

def _load_yaml(path):
    import yaml
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load(paths=None) -> dict:
    """The merged catalogue: {"entity_rules": [...], "pattern_rules": [...],
    "error": str|None}. Local rules come first; `disable: [ids]` in the local
    file switches shipped rules off. Cached until a file changes."""
    paths = list(paths) if paths else [p for p in LOCAL_NAMES if os.path.exists(p)] + [CATALOGUE]
    key = tuple((p, os.path.getmtime(p) if os.path.exists(p) else None) for p in paths)
    with _LOCK:
        if _CACHE["key"] == key:
            return _CACHE["rules"]
        out = {"entity_rules": [], "pattern_rules": [], "error": None}
        disabled: set = set()
        for p in paths:
            try:
                doc = _load_yaml(p)
            except Exception as e:                    # noqa: BLE001 -- never the fuse
                out["error"] = f"{os.path.basename(p)}: {type(e).__name__}: {e}"[:300]
                continue
            disabled |= set(doc.get("disable") or [])
            out["entity_rules"] += [r for r in doc.get("entity_rules") or [] if isinstance(r, dict)]
            out["pattern_rules"] += [r for r in doc.get("pattern_rules") or [] if isinstance(r, dict)]
        for k in ("entity_rules", "pattern_rules"):
            out[k] = [r for r in out[k] if r.get("id") not in disabled and r.get("enabled", True)]
        _CACHE.update(key=key, rules=out)
        return out


# ---------------------------------------------------------------- entity rules

def _artifact_of(e) -> str:
    a = (e.attrs or {}).get("artifact")
    if a:
        return str(a)
    for ev in e.evidence or []:
        return str(ev.locator or "").split("/row=")[0]
    return ""


def _words(v):
    return [str(w).lower() for w in (v if isinstance(v, list) else [v])]


@functools.lru_cache(maxsize=256)
def _glob(pattern: str):
    return re.compile(fnmatch.translate(pattern.lower()))


def matches(rule: dict, e, art: str | None = None) -> bool:
    w = rule.get("when") or {}
    attrs = e.attrs or {}
    if "artifact" in w:
        art = (art if art is not None else _artifact_of(e)).lower()
        if not any(_glob(g).match(art) for g in _words(w["artifact"])):
            return False
    if "type" in w and e.type not in _words(w["type"]):
        return False
    if "flags_any" in w and not set(_words(w["flags_any"])) & {str(f).lower() for f in e.flags or []}:
        return False
    for attr, words in (w.get("attr_words") or {}).items():
        val = str(attrs.get(attr) or "").lower()
        if not val or not any(x in val for x in _words(words)):
            return False
    for attr, rx in (w.get("attr_regex") or {}).items():
        if not re.search(rx, str(attrs.get(attr) or ""), re.I):
            return False
    if "check" in w:
        fn = CHECKS[w["check"]]                         # unknown name: KeyError -> skipped
        if not fn(*[attrs.get(a) for a in w.get("args") or []]):
            return False
    return True


def apply_entity(e, rules=None, errors=None):
    """Weigh one entity by the first rule that matches it; returns the entity."""
    cat = rules if rules is not None else load()
    art = _artifact_of(e).lower()              # once per entity, not once per rule
    # Which rules can apply to this artifact at all, worked out once per artifact:
    # 204k logon rows then cost one dict lookup, not nine rule checks each.
    byart = cat.setdefault("_by_artifact", {})
    candidates = byart.get(art)
    if candidates is None:
        candidates = byart[art] = [r for r in cat.get("entity_rules") or []
                                   if "artifact" not in (r.get("when") or {})
                                   or any(_glob(g).match(art) for g in _words(r["when"]["artifact"]))]
    for rule in candidates:
        try:
            if not matches(rule, e, art):
                continue
        except Exception as x:                          # noqa: BLE001 -- a broken rule, not the fuse
            if errors is not None:
                errors.setdefault(rule.get("id", "?"), f"{type(x).__name__}: {x}"[:200])
            continue
        then = rule.get("then") or {}
        before = e.severity
        if "anomaly" in then:
            new_anom = int(then["anomaly"])
            new_sev = sev.from_anomaly(new_anom)
        else:
            new_anom, new_sev = e.anomaly, str(then.get("severity") or e.severity)
        if before == "critical" and sev.rank(new_sev) < sev.rank(before) \
                and not rule.get("allow_lower_critical"):
            return e
        e.anomaly, e.severity = new_anom, new_sev
        flags = [f for f in e.flags or [] if f not in set(then.get("remove_flags") or [])]
        e.flags = flags + [f for f in then.get("add_flags") or [] if f not in flags]
        e.attrs = dict(e.attrs or {})
        e.attrs["weighting"] = {"rule": rule.get("id"), "from": before, "to": new_sev,
                                "reason": rule.get("reason") or ""}
        return e
    return e


# --------------------------------------------------------------- pattern rules

def apply_patterns(g, rules=None, errors=None) -> dict:
    """Run every pattern rule over the graph; {rule id: rows changed}."""
    cat = rules if rules is not None else load()
    done = {}
    for rule in cat.get("pattern_rules") or []:
        try:
            done[rule.get("id")] = int(_PATTERNS[rule["pattern"]](g, dict(rule.get("params") or {})) or 0)
        except Exception as x:                          # noqa: BLE001
            if errors is not None:
                errors.setdefault(rule.get("id", "?"), f"{type(x).__name__}: {x}"[:200])
    return done
