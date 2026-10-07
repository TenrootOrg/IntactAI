"""Optional second-pass PII scrub with Presidio NER — catches the free-text
LEFTOVERS the deterministic DataAnonymizer cannot: person names, company/org
names, and the like, which have no stable shape for a regex/field rule.

WHY A SECOND PASS. DataAnonymizer is deterministic, reversible and air-gap-safe:
it nails the structured forensic identifiers (IPs, hosts, users, SIDs, paths,
known credential formats). What it CANNOT see is a human name or a company name
sitting inside a free-text field (a Hayabusa `Details`, a PowerShell
`ScriptBlockText`, a collected document body) — those are natural language, so
NER is the right tool and regex is not. This module runs AFTER the deterministic
mask, over the already-masked text, and scrubs what is left.

AIR-GAP / OPTIONALITY. Presidio pulls in spaCy and a language model (hundreds of
MB), which does not fit the "deterministic + air-gap is the default" rule. So
this is strictly OPTIONAL and OFF by default: with Presidio not installed, or the
toggle off, every entry point is a no-op and the pipeline behaves exactly as
before. Enable it (and accept the model dependency) only where it earns its keep.

REVERSIBILITY. Each entity Presidio finds is replaced with a stable pseudonym
(Person1, Org1, …) registered into the SAME DataAnonymizer mapping, so the
existing unmask/revert path restores it with no extra wiring.
"""
from __future__ import annotations

import functools
import os
import re

# Our own pseudonyms must never be re-masked by NER (Username1 reads as a PERSON).
_OUR_PSEUDO = re.compile(
    r"^(ExternalIP|InternalIP|Username|Hostname|Email|Domain|Guid|Credential|Person|Org|Loc)\d+$")

# NER routinely tags infrastructure and product names as PERSON/ORG. Masking them
# would strip the very context the report needs, so they pass through. Lowercased,
# matched whole-token. Extend from real false positives, not speculatively.
_KEEP = {
    "microsoft", "windows", "powershell", "defender", "azure", "office",
    "velociraptor", "sysmon", "hayabusa", "sigma", "mitre", "att&ck",
    "cobalt strike", "mimikatz", "chrome", "edge", "firefox", "linux", "system",
    "administrator", "administrators", "users", "guest", "nt authority",
}

# Default entity set: the two the deterministic masker genuinely cannot catch.
DEFAULT_ENTITIES = ("PERSON", "ORG")
DEFAULT_MIN_SCORE = 0.6

# NER tags forensic strings as PERSON/ORG at the SAME score as a real name (a
# base64 blob, a registry path \SAM\Domains\Account\Users\…, an identifier like
# ntpwd_hash all came back PERSON @0.85). A score threshold can't separate them;
# their SHAPE can. A human/company name is a few alphabetic words — no path or
# token characters, no digits, not one long opaque run. Everything else is a
# forensic identifier the deterministic layer already owns, so NER must not touch it.
_NON_NAME_CHARS = set("\\/=@:_|{}[]()<>$%*+#")


def _plausible_name(s: str) -> bool:
    if any(c in _NON_NAME_CHARS for c in s) or any(c.isdigit() for c in s):
        return False
    words = s.split()
    if not words or len(words) > 5:
        return False
    if len(words) == 1 and len(s) > 20:               # a single 20+ char token is a blob, not a name
        return False
    for w in words:
        core = w.strip("'-.").replace("'", "").replace("-", "")
        if not core or not core.isalpha():
            return False
    return True

_PSEUDO_PREFIX = {"PERSON": "Person", "ORG": "Org", "LOCATION": "Loc", "GPE": "Loc", "NRP": "Group"}


# Production runs Presidio in its OWN container (modules/presidio), ON DEMAND like
# plaso: the backend `docker run`s it when a report needs the NER pass, calls it
# over HTTP, and the container exits itself when idle (so it is "active only while
# used, then off"). In dev/tests Presidio may instead be importable in-process.
# Either path feeds the same scrub() below.
import threading

_CONTAINER = "intact_presidio"
_NETWORK = os.environ.get("INTACT_NETWORK", "intact_network")
_MEM = os.environ.get("PRESIDIO_MEMORY", "2g")
_SIDECAR_URL = os.environ.get("PRESIDIO_URL", f"http://{_CONTAINER}:3000")
_SIDECAR_STATE: dict = {"ok": None, "checked_at": 0.0}
_SIDECAR_TTL = 15.0                                    # re-probe health at most this often
_START_LOCK = threading.Lock()


def _image() -> str:
    """The intact-presidio image tag — versions.presidio via the backend config,
    else the env override, else the pinned default."""
    try:
        from config import get_presidio_image            # noqa: PLC0415
        img = get_presidio_image()
        if img:
            return img
    except Exception:                                    # noqa: BLE001 — config/dep absent
        pass
    return os.environ.get("PRESIDIO_IMAGE", "intact-presidio:2.2.364")


def _image_present() -> bool:
    try:
        import subprocess
        return subprocess.run(["docker", "image", "inspect", _image()],
                              capture_output=True, timeout=10).returncode == 0
    except Exception:                                    # noqa: BLE001
        return False


def available() -> bool:
    """True iff the NER engine can be reached/started — the sidecar is already up,
    its image is present (so we can start it on demand), or in-process (dev/tests)."""
    return _sidecar_ok() or _image_present() or (_analyzer() is not None)


def _ensure_sidecar() -> bool:
    """Make the sidecar healthy, starting it on demand if its image is present.
    Serialised so two concurrent reports don't both `docker run` it. Returns
    False (and the caller falls back) if it can't be reached or started."""
    if _sidecar_ok():
        return True
    if not _image_present():
        return False
    with _START_LOCK:
        if _sidecar_ok():                                # started while we waited
            return True
        try:
            import subprocess
            cmd = ["docker", "run", "-d", "--rm", "--name", _CONTAINER,
                   "--network", _NETWORK, "--memory", _MEM]
            model = os.environ.get("PRESIDIO_MODEL")
            if model:
                cmd += ["-e", f"PRESIDIO_MODEL={model}"]
            cmd.append(_image())
            # A name clash means it is already running (another worker won the race);
            # either way we then poll health below, so ignore the run's own result.
            subprocess.run(cmd, capture_output=True, timeout=30)
        except Exception:                                # noqa: BLE001
            pass
        import time
        for _ in range(45):                              # ~45s: cold model load + boot
            _SIDECAR_STATE["ok"] = None                  # force a fresh probe
            if _sidecar_ok():
                return True
            time.sleep(1)
        return False


def _sidecar_ok() -> bool:
    """Is the Presidio sidecar healthy? Cached for _SIDECAR_TTL so a disabled or
    down sidecar costs one probe per window, not one per call."""
    import time
    now = time.time()
    if _SIDECAR_STATE["ok"] is not None and (now - _SIDECAR_STATE["checked_at"]) < _SIDECAR_TTL:
        return _SIDECAR_STATE["ok"]
    ok = False
    try:
        import urllib.request
        with urllib.request.urlopen(_SIDECAR_URL.rstrip("/") + "/health", timeout=2) as r:
            ok = (r.status == 200)
    except Exception:                                  # noqa: BLE001 — not deployed / not reachable
        ok = False
    _SIDECAR_STATE.update(ok=ok, checked_at=now)
    return ok


def _detect_spans(text, entities, threshold):
    """Return [{entity_type,start,end,score}, …] via the sidecar, else in-process,
    else []. Never raises — a detection failure degrades to no masking."""
    # Sidecar first (the production path) — started on demand if needed.
    if _ensure_sidecar():
        try:
            import json
            import urllib.request
            data = json.dumps({"text": text, "entities": list(entities),
                               "score_threshold": threshold}).encode()
            req = urllib.request.Request(_SIDECAR_URL.rstrip("/") + "/analyze", data=data,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return (json.load(r) or {}).get("spans") or []
        except Exception:                              # noqa: BLE001 — fall through to in-process
            pass
    # In-process fallback (dev/tests).
    eng = _analyzer()
    if eng is None:
        return []
    try:
        res = eng.analyze(text=text, entities=list(entities), language="en")
    except Exception:                                  # noqa: BLE001
        return []
    return [{"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score}
            for r in res if r.score >= threshold]


def enabled(cfg: dict | None = None, mask=None) -> bool:
    """Off unless it is switched on AND the engine is actually available. The
    switch can come from the case masking config (`cfg["pii_ner"]`), from a flag
    stamped on the mask object (`mask._ner`, how the fusion flow passes it), or
    from the env var (the before/after harness, without touching settings)."""
    on = (bool((cfg or {}).get("pii_ner"))
          or bool(getattr(mask, "_ner", False))
          or os.environ.get("INTACT_PII_NER") == "1")
    return on and available()


@functools.lru_cache(maxsize=1)
def _analyzer():
    """Build the Presidio AnalyzerEngine once, or return None if unavailable.
    lru_cache so the (slow) model load happens at most once per process."""
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception:                                  # noqa: BLE001 — optional dep
        return None
    for model in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        try:
            prov = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            })
            return AnalyzerEngine(nlp_engine=prov.create_engine(), default_score_threshold=0.0)
        except Exception:                              # noqa: BLE001 — model not installed
            continue
    return None


def _register(mask, original: str, pseudo: str) -> None:
    """Wire the pseudonym into the DataAnonymizer so the existing revert works."""
    if mask is None:
        return
    for attr in ("mapping",):
        d = getattr(mask, attr, None)
        if isinstance(d, dict):
            d[original] = pseudo
    rev = getattr(mask, "reverse_mapping", None)
    if isinstance(rev, dict):
        rev[pseudo] = original
    atomic = getattr(mask, "_atomic_mappings", None)   # for the masking summary log
    if isinstance(atomic, dict):
        atomic[original] = (pseudo, "ner")


def scrub(text, mask=None, *, entities=DEFAULT_ENTITIES, min_score=DEFAULT_MIN_SCORE,
          cfg=None):
    """Second-pass scrub of residual free-text PII. Returns (scrubbed_text, hits).

    No-op (text, []) when disabled/unavailable or text is empty. Each detected
    span becomes a stable pseudonym registered in `mask` for reversibility; the
    same surface form always maps to the same pseudonym within this instance."""
    if not text or not isinstance(text, str):
        return text, []
    if not enabled(cfg, mask):
        return text, []
    spans = _detect_spans(text, entities, min_score)
    if not spans:
        return text, []

    # Keep the highest-scoring, non-overlapping spans, longest-first so we
    # substitute whole names before any sub-span.
    spans = sorted(spans, key=lambda s: (s["end"] - s["start"]), reverse=True)
    seen_ranges: list[tuple[int, int]] = []
    assigned: dict[str, str] = {}
    counters: dict[str, int] = {}
    hits = []
    for s in spans:
        start, end, etype, score = s["start"], s["end"], s["entity_type"], s["score"]
        surface = text[start:end].strip()
        low = surface.lower()
        if not surface or _OUR_PSEUDO.match(surface) or low in _KEEP:
            continue
        if not _plausible_name(surface):               # forensic string NER mis-tagged as a name
            continue
        if any(a < end and start < b for a, b in seen_ranges):
            continue                                   # overlaps a longer span already taken
        seen_ranges.append((start, end))
        if surface not in assigned:
            pre = _PSEUDO_PREFIX.get(etype, str(etype).title())
            counters[pre] = counters.get(pre, 0) + 1
            assigned[surface] = f"{pre}{counters[pre]}"
            _register(mask, surface, assigned[surface])
        hits.append({"text": surface, "type": etype, "score": round(float(score), 2),
                     "pseudo": assigned[surface]})

    # Replace longest surfaces first so "John Smith" goes before "John".
    out = text
    for surface in sorted(assigned, key=len, reverse=True):
        out = re.sub(r"\b" + re.escape(surface) + r"\b", assigned[surface], out)
    return out, hits


if __name__ == "__main__":  # tiny smoke test (no-op without presidio installed)
    sample = ("Analyst Sarah Johnson at Contoso Ltd reviewed Username3 on Hostname1; "
              "escalated to the Acme Corporation SOC.")
    scrubbed, found = scrub(sample, cfg={"pii_ner": True})
    if available():
        assert "Sarah Johnson" not in scrubbed, scrubbed
        assert any(h["type"] == "PERSON" for h in found), found
        print("scrubbed:", scrubbed)
        print("hits:", found)
    else:
        assert scrubbed == sample and found == []
        print("presidio not installed — no-op OK")
