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
import json
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
    # DFIR vocabulary NER keeps tagging as a PERSON/ORG in forensic text. These
    # are techniques, tooling, Windows internals and report words — never PII, and
    # masking them ("the model saw Person5 where the evidence said Critical")
    # degrades the narrative. Extended from REAL false positives on a lab run
    # (Procdump, Kerberoasting, Inveigh, Critical, SAM, Endpoints, Detections…).
    # Tools (also _TOOL_WORDS below):
    # Techniques / Windows internals:
    "kerberoasting", "kerberos", "dcsync", "lsass", "ntlm", "smb", "rdp", "winrm",
    "wmi", "wmiprvse", "srum", "amcache", "prefetch", "shimcache", "mft", "usn",
    "evtx", "sam", "ntds", "lsa", "asr", "mark-of-the-web", "named pipe",
    "hive", "hives", "registry", "hash", "hashes", "token", "ticket", "secret",
    "secrets", "credential", "credentials",
    # Report / severity words:
    "critical", "high", "medium", "low", "informational", "severity", "detection",
    "detections", "finding", "findings", "alert", "alerts", "exclusion",
    "exclusions", "antivirus", "malware", "ransomware", "exploit", "payload",
    "beacon", "implant", "endpoint", "endpoints", "persistence", "exfiltration",
    # More report/forensic vocabulary NER tagged as PERSON/ORG on a live lab run
    # (Bypass, Trojan, Firewall, Value, Creation ...). camelCase tokens like
    # LogonId / MethodPara are rejected by _plausible_name, not listed here.
    "bypass", "trojan", "firewall", "value", "values", "creation",
    "infrastructure", "parameter", "parameters", "method", "logon", "logoff",
    # Windows / Sysmon event-FIELD words. The model writes them as labels in its own
    # prose ("Account Name `x`, Domain Name `y`, Logon ID `z`") and NER took
    # "Domain Name" for a person. Only a span made ENTIRELY of kept words is
    # skipped, so a real name that contains one of these is still masked.
    "account", "domain", "name", "names", "id", "subject", "target", "user",
    "computer", "workstation", "process", "image", "path", "command", "line", "parent",
    "source", "destination", "address", "port", "network", "object", "type", "key",
    "field", "provider", "channel", "event", "record", "level", "task", "status",
    "reason", "service", "file", "share", "package", "privilege", "privileges",
    "member", "sid", "guid", "caller", "client", "session", "signature", "original",
    "description", "product", "version", "security",
}

# Security / admin tools. A "company" span naming one is the tool's publisher, a
# public vendor ("Nmap Software LLC" came back Org1 on a lab report).
_TOOL_WORDS = {
    "procdump", "inveigh", "bloodhound", "sharphound", "rubeus", "impacket",
    "psexec", "metasploit", "sliver", "winpeas", "seatbelt", "rclone", "adfind",
    "nltest", "procmon", "autoruns", "sysinternals", "nmap", "netcat", "ngrok",
    "anydesk", "teamviewer", "certutil", "bitsadmin", "lolbin", "lolbas", "wireshark",
}
_KEEP |= _TOOL_WORDS

# Public software vendors: a "company" span naming one is the vendor, not the
# customer ("Signed by Microsoft Corporation"). Kept apart from _KEEP on purpose:
# _KEEP is broad vocabulary matched ALL-words; this is matched ANY-word, and with
# _KEEP that would have made "First Security Bank" unmaskable.
_VENDOR_WORDS = {"microsoft", "windows", "defender", "azure", "office", "google",
                 "velociraptor", "sysmon", "hayabusa", "chrome", "firefox", "mozilla",
                 "linux", "apple", "amazon"}

# Default entity set: the two the deterministic masker genuinely cannot catch.
# Presidio names the company entity ORGANIZATION (spaCy's ORG is mapped to it).
# This said "ORG", which Presidio silently returns nothing for — so from the day
# Presidio was added, company names were NEVER masked, though the Log line said
# "person & company names". Measured 2026-10-11: 0 ORG spans at threshold 0.
DEFAULT_ENTITIES = ("PERSON", "ORGANIZATION")
DEFAULT_MIN_SCORE = 0.6

# NER tags forensic strings as PERSON/ORG at the SAME score as a real name (a
# base64 blob, a registry path \SAM\Domains\Account\Users\…, an identifier like
# ntpwd_hash all came back PERSON @0.85). A score threshold can't separate them;
# their SHAPE can. A human/company name is a few alphabetic words — no path or
# token characters, no digits, not one long opaque run. Everything else is a
# forensic identifier the deterministic layer already owns, so NER must not touch it.
_NON_NAME_CHARS = set("\\/=@:_|{}[]()<>$%*+#")


# A span containing one of these is a technical phrase, never a name ("Creating
# Scriptblock", the 4104 message text, came back PERSON @0.85). Kept to words no
# person or customer company is called -- broad ones (security, windows, defender)
# stay in _KEEP, which only drops a span made ENTIRELY of kept words.
_TECH_ANY = {"scriptblock", "powershell", "pwsh", "cmdlet", "commandlet", "evtx",
             "sysmon", "hayabusa", "velociraptor", "mimikatz", "lsass", "kerberos",
             "ntlm", "wmi", "rundll32", "svchost", "regedit"}

# An ORGANIZATION span must name a company the way a company is written: with a
# designator. Forensic text is full of Title-Case phrases NER calls companies --
# rule titles ("Important Windows Eventlog Cleared"), providers ("SCM Event
# Provider"), acronyms (SSH, IMPHASH): 16 of 16 ORG hits on the lab cases. None
# carries a designator; "Contoso Ltd", "Acme Corporation", "Fabrikam Inc" do.
# Ambiguous ones are left out on purpose: services ("Remote Desktop Services"),
# group ("Group Policy"), authority ("Certificate Authority"), systems.
_ORG_DESIGNATORS = {
    "ltd", "limited", "inc", "incorporated", "llc", "llp", "lp", "corp", "corporation",
    "co", "company", "gmbh", "ag", "sa", "sas", "sarl", "plc", "pty", "pte", "bv", "nv",
    "oy", "oyj", "ab", "asa", "spa", "srl", "kk", "kg", "holdings", "holding", "bank",
    "university", "college", "institute", "foundation", "association", "agency",
    "ministry", "council", "hospital", "clinic", "partners", "associates",
    "enterprises", "industries", "traders", "trading", "insurance", "airlines",
}


def _span_rejected(det: str, start: int, end: int, surface: str, etype: str,
                   tech_phrases=()) -> bool:
    """Position- and context-based checks that a NER span is not a name/company."""
    if not surface[:1].isupper():                      # ioc, param, icrosoft, lter'
        return True
    low = surface.lower()
    words = [w.strip(".,") for w in low.split()]
    if etype in ("ORGANIZATION", "ORG"):
        if not any(w in _ORG_DESIGNATORS for w in words):
            return True                                # a phrase, not a company
        if any(w in _VENDOR_WORDS or w in _TOOL_WORDS for w in words):
            return True                                # a public vendor ("Microsoft Corporation")
    if det[end:].lstrip(" ")[:1] in (":", "`"):
        return True                                    # "Possiblecause: x" / "Domain Name `y`" -- a field label
    if any(low in p for p in tech_phrases):
        return True                                    # part of this case's own rule names
    if len(words) == 1:
        rest = det[end:].split("\n", 1)[0]
        if not rest.strip() and re.search(re.escape(surface) + r"[a-z]", det):
            return True                                # "Microso" at a cut, "Microsoft" elsewhere
    return False


# Not < > @: an e-mail header ("From: Tom Becker <tbecker@corp.com>") is prose,
# and counting them as code hid the name on it.
_CODE_CHARS = frozenset("{}[]()=;$|`\\")


_PS_VAR = re.compile(r"\$[A-Za-z_{(]")


def _is_code(v: str) -> bool:
    """A line of script / command, not prose. NER reads code identifiers and
    Windows' cut-off scriptblock chunks ("...@{Name = 'Remot", "$false, 'Defau") as
    names. A $variable is code; otherwise it takes several code characters at a
    real density -- "Sarah (IT) said" keeps its parentheses and stays prose. The
    accounts/hosts/IPs inside code are still masked by the deterministic layer."""
    t = v.strip()
    if _PS_VAR.search(t):
        return True
    n = sum(c in _CODE_CHARS for c in t)
    return n >= 3 and n / max(len(t), 1) > 0.06


def _prose_values(text: str, skip=()) -> list:
    """The prose string values NER should read: a JSON document is decoded and
    its string values returned (code lines dropped, values in `skip` left out);
    any other text is one value."""
    if text.lstrip()[:1] not in ("{", "["):
        return [text]
    try:
        obj = json.loads(text)
    except ValueError:
        return [text]
    vals: list = []

    def walk(o):
        if isinstance(o, str):
            if o in skip:
                return
            keep = [ln for ln in o.splitlines() if ln.strip() and not _is_code(ln)]
            if keep:
                vals.append("\n".join(keep))
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                walk(v)
    walk(obj)
    return vals


def _detection_text(text: str, seen=None) -> str:
    """What NER reads. A report payload is json.dumps output: escapes glue words
    across fields -- "Sarah Johnson.\\nDavid" came back as ONE span, was dropped,
    and NEITHER name was masked -- and \\u escapes hide accented names. So decode
    it and give NER each DISTINCT prose value once, on its own line, code skipped.
    Values in `seen` (already read earlier in this report) are skipped. Text that
    isn't a JSON document (a chat question) is read as it is."""
    vals = [v for v in dict.fromkeys(_prose_values(text)) if not seen or v not in seen]
    return "\n\n".join(vals)


# Left edge of a name in the ORIGINAL text: no word char before it -- or a JSON
# escape (\\n, \\t, \\r) whose letter would otherwise glue to it. "\\bDavid" never
# matched "...Johnson.\\nDavid", so a name detected right after a line break was
# reported masked and LEAKED. The right edge is (?!\w) so "Ltd." still matches.
_NAME_EDGE_L = r"(?:(?<!\w)|(?<=\\[ntr]))"
_GLUE_BEFORE = set("._\\/")
_GLUE_AFTER = set("_\\/")


def _glued_to_token(text: str, start: int, end: int) -> bool:
    """True when the span is part of a LARGER token in the source text — a dotted
    code identifier, a path, or a word cut mid-way — so it can't be a name. A real
    name stands alone between spaces/punctuation. 2026-10-11, a lab report: Windows
    splits a PowerShell scriptblock into chunks, so labels carried
    "...Creating Scriptblock text (21 of 24):\\nft.Management.Infrastr" and NER
    tagged the cut-off tails Infrastr / Firewal / Valu as PERSON @0.85; the surface
    alone looks like a name, its position does not. Sentence-final '.', quotes and
    a JSON-escaped line break (\\n) stay boundaries, so prose names are kept."""
    raw = text[start:end]
    start += len(raw) - len(raw.lstrip())
    end -= len(raw) - len(raw.rstrip())
    b = text[start - 1] if start > 0 else " "
    if start >= 2 and text[start - 2] == "\\" and b in "ntr":
        b = " "                                    # JSON-escaped \n/\t/\r = line break
    a = text[end] if end < len(text) else " "
    return b.isalnum() or b in _GLUE_BEFORE or a.isalnum() or a in _GLUE_AFTER


def _plausible_name(s: str, allow_camel: bool = False) -> bool:
    if any(c in _NON_NAME_CHARS for c in s) or any(c.isdigit() for c in s):
        return False
    words = s.split()
    if not words or len(words) > 5:
        return False
    if len(words) == 1 and len(s) > 20:               # a single 20+ char token is a blob, not a name
        return False
    for w in words:
        if w.startswith("-"):                   # a PowerShell flag (-eq, -NoProfile), not a name
            return False
        # camelCase / internal capitals = a technical identifier (LogonId,
        # MethodPara, NoProfile, PSScriptPolicyTest), not a person's name. A real
        # name is Title-case or ALLCAPS; a lowercase letter immediately followed by
        # an uppercase one never occurs inside one. Checked on the ORIGINAL word so
        # a hyphen keeps the two sides apart ("Jean-Luc" stays a name). The rare
        # camelCase surname (McDonald) is the accepted cost -- the deterministic
        # masker still masks real account/host names; NER is only the free-text pass.
        if not allow_camel and re.search(r"[a-z][A-Z]", w):
            return False
        core = w.strip("'-.").replace("'", "").replace("-", "")
        if not core or not core.isalpha():
            return False
    return True

_PSEUDO_PREFIX = {"PERSON": "Person", "ORG": "Org", "ORGANIZATION": "Org", "LOCATION": "Loc", "GPE": "Loc", "NRP": "Group"}


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


def _log(msg, level="info", logfn=None):
    """Route a lifecycle/error line to the caller's logger (the case Log, when one
    is given) AND always to backend stdout, so `docker logs intact_backend` shows
    the Presidio container coming up even on a path with no case logger."""
    try:
        print(f"[Presidio] {msg}", flush=True)
    except Exception:                                    # noqa: BLE001
        pass
    if logfn:
        try:
            logfn(msg, level)   # the case-log action already names Presidio
        except Exception:                                # noqa: BLE001
            pass


def _ensure_sidecar(logfn=None) -> bool:
    """Make the sidecar healthy, starting it on demand if its image is present.
    Serialised so two concurrent reports don't both `docker run` it. Every outcome
    is logged. Returns False (and the caller falls back to the deterministic mask
    only) if it can't be reached or started — a NER failure never fails a report."""
    if _sidecar_ok():
        return True
    if not _image_present():
        _log(f"image {_image()} not present — skipping the NER pass "
             f"(deterministic masking still applies)", "warning", logfn)
        return False
    with _START_LOCK:
        if _sidecar_ok():                                # started while we waited
            return True
        import subprocess
        try:
            cmd = ["docker", "run", "-d", "--rm", "--name", _CONTAINER,
                   "--network", _NETWORK, "--memory", _MEM]
            model = os.environ.get("PRESIDIO_MODEL")
            if model:
                cmd += ["-e", f"PRESIDIO_MODEL={model}"]
            cmd.append(_image())
            _log(f"starting the PII NER container ({_image()})…", "info", logfn)
            r = subprocess.run(cmd, capture_output=True, timeout=60, text=True)
            # A name clash means it is already running (another worker won the race)
            # — not an error; we poll health below either way. Any OTHER non-zero is.
            err = (r.stderr or "").strip()
            if r.returncode != 0 and "already in use" not in err.lower():
                _log(f"could not start the container: {err[:200]} — skipping the NER "
                     f"pass (deterministic masking still applies)", "warning", logfn)
                return False
        except FileNotFoundError:
            _log("docker CLI not available in the backend — skipping the NER pass",
                 "warning", logfn)
            return False
        except subprocess.TimeoutExpired:
            _log("timed out launching the container — skipping the NER pass", "warning", logfn)
            return False
        except Exception as e:                           # noqa: BLE001
            _log(f"error launching the container: {e} — skipping the NER pass", "warning", logfn)
            return False
        import time
        for i in range(45):                              # ~45s: cold model load + boot
            _SIDECAR_STATE["ok"] = None                  # force a fresh probe
            if _sidecar_ok():
                _log("container is up and healthy", "info", logfn)
                return True
            time.sleep(1)
        _log("container did not become healthy within 45s — skipping the NER pass "
             "(deterministic masking still applies)", "warning", logfn)
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


# Characters per sidecar request. One request per report payload (up to ~330k
# chars on a 9-host case) ran past the 30 s client timeout on a loaded box; the
# timeout was swallowed as "no names", so Presidio silently checked NOTHING, and
# the abandoned request kept the single sidecar busy so the next ones timed out
# too. ~20k chars is about a second of work (measured: 120k chars = 4.6 s).
_CHUNK = 20000


def _chunks(text: str, size: int = _CHUNK) -> list:
    """(offset, piece) slices of at most `size` chars, cut at a line break (else a
    space) so a name is never split across two requests."""
    out, start, n = [], 0, len(text)
    while start < n:
        end = min(start + size, n)
        if end < n:
            cut = text.rfind("\n", start, end)
            if cut <= start:
                cut = text.rfind(" ", start, end)
            if cut > start:
                end = cut + 1
        out.append((start, text[start:end]))
        start = end
    return out


def _detect_spans(text, entities, threshold, logfn=None, errors=None):
    """Return [{entity_type,start,end,score}, …], reading `text` in chunks. A chunk
    nothing could read is skipped and its length appended to `errors` (when given)
    so the caller can say so -- a failure must never look like "no names found"."""
    spans = []
    for off, part in _chunks(text):
        got = _detect_chunk(part, entities, threshold, logfn)
        if got is None:
            if errors is not None:
                errors.append(len(part))
            continue
        spans += [{**sp, "start": sp["start"] + off, "end": sp["end"] + off} for sp in got]
    return spans


def _detect_chunk(text, entities, threshold, logfn=None):
    """Spans for one chunk via the sidecar, else in-process; None if neither could
    read it. Never raises."""
    # Sidecar first (the production path) — started on demand if needed.
    if _ensure_sidecar(logfn):
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
        return None
    try:
        res = eng.analyze(text=text, entities=list(entities), language="en")
    except Exception:                                  # noqa: BLE001
        return None
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
          cfg=None, logfn=None):
    """Second-pass scrub of residual free-text PII. Returns (scrubbed_text, hits).

    No-op (text, []) when disabled/unavailable or text is empty. Each detected
    span becomes a stable pseudonym registered in `mask` for reversibility; the
    same surface form always maps to the same pseudonym within this instance.
    `logfn(msg, level)` (optional) routes container lifecycle + result lines to
    the case Log."""
    if not text or not isinstance(text, str):
        return text, []
    if not enabled(cfg, mask):
        return text, []
    # Each report makes several model calls whose payloads overlap heavily (7 calls,
    # 20k values, 3k distinct on a 9-host case): read each distinct value once. A
    # name found earlier is already in the mapping, so the deterministic pass hides
    # it in every later payload before this runs.
    seen = mask.__dict__.setdefault("_ner_seen", set()) if mask is not None else None
    skip = getattr(mask, "_ner_skip", None) or () if mask is not None else ()
    vals = [v for v in dict.fromkeys(_prose_values(text, skip)) if seen is None or v not in seen]
    det = "\n\n".join(vals)
    errors: list = []
    spans = _detect_spans(det, entities, min_score, logfn, errors) if det.strip() else []
    if errors:
        if mask is not None:
            mask.__dict__["_ner_failed"] = True
        _log("could not read %s of %s characters — the NER engine did not answer; those "
             "parts were NOT checked for names (the custom-identity masking still applied)"
             % (f"{sum(errors):,}", f"{len(det):,}"), "warning", logfn)
    elif seen is not None:
        seen.update(vals)
    if not spans:
        _announce_clean(mask, logfn)
        return text, []

    # A name never crosses a line break. NER sometimes merges across the blank line
    # between two values ("Woodgrove Bank\n\nRemote Desktop Services" came back as
    # ONE ORG span): the joined surface never occurs in the original, so the real
    # company LEAKED. Split such a span and judge each line on its own.
    split = []
    for sp in spans:
        a = sp["start"]
        for ln in det[sp["start"]:sp["end"]].split("\n"):
            if ln.strip():
                split.append({**sp, "start": a, "end": a + len(ln)})
            a += len(ln) + 1
    spans = split
    # Keep the highest-scoring, non-overlapping spans, longest-first so we
    # substitute whole names before any sub-span.
    spans = sorted(spans, key=lambda s: (s["end"] - s["start"]), reverse=True)
    seen_ranges: list[tuple[int, int]] = []
    assigned: dict[str, str] = {}
    hits = []
    # Pseudonyms are PERSISTENT across every scrub call in one report (the payload,
    # the synthesis, …): counters live on the mask, and a name already mapped reuses
    # its pseudonym. So the same name is the same Person1 everywhere the model sees
    # it, and the single revert at the end restores it correctly.
    counters = mask.__dict__.setdefault("_ner_counters", {}) if mask is not None else {}
    existing = getattr(mask, "mapping", {}) or {}
    for s in spans:
        start, end, etype, score = s["start"], s["end"], s["entity_type"], s["score"]
        surface = det[start:end].strip().rstrip(".,;:")   # "Contoso Ltd." -> "Contoso Ltd"
        low = surface.lower()
        if not surface or _OUR_PSEUDO.match(surface) or low in _KEEP \
                or all(w in _KEEP for w in low.split()):   # e.g. "Critical Detection"
            continue
        if any(w in _TECH_ANY for w in low.split()):  # "Creating Scriptblock"
            continue
        # camelCase is allowed for a company (PayPal Inc, LinkedIn Corporation): an
        # ORG span already needs a designator, which no code identifier carries.
        if not _plausible_name(surface, allow_camel=etype in ("ORGANIZATION", "ORG")):
            continue                                   # forensic string NER mis-tagged as a name
        if _glued_to_token(det, start, end):           # tail of a code identifier / cut word
            continue
        if _span_rejected(det, start, end, surface, etype,
                          getattr(mask, "_tech_phrases", ()) if mask is not None else ()):
            continue
        if any(a < end and start < b for a, b in seen_ranges):
            continue                                   # overlaps a longer span already taken
        seen_ranges.append((start, end))
        if surface not in assigned:
            prior = existing.get(surface)              # already masked earlier in this report?
            if prior:
                assigned[surface] = prior
            else:
                pre = _PSEUDO_PREFIX.get(etype, str(etype).title())
                counters[pre] = counters.get(pre, 0) + 1
                assigned[surface] = f"{pre}{counters[pre]}"
                _register(mask, surface, assigned[surface])
        hits.append({"text": surface, "type": etype, "score": round(float(score), 2),
                     "pseudo": assigned[surface]})

    # Replace longest surfaces first so "John Smith" goes before "John".
    out = text
    for surface in sorted(assigned, key=len, reverse=True):
        # Detected on DECODED text, replaced in the original: a JSON payload carries
        # an accented name in its escaped form (Jos\u00e9), so replace both.
        for form in {surface, json.dumps(surface)[1:-1]}:
            out = re.sub(_NAME_EDGE_L + re.escape(form) + r"(?!\w)", assigned[surface], out)
    if assigned:
        # List WHAT was masked (name = pseudonym), like the deterministic mask's
        # pre-LLM mapping block, so the operator can see exactly what Presidio hid.
        # The Log is the trusted local view (the model gets only the pseudonyms).
        pairs = sorted(assigned.items(), key=lambda kv: kv[1])
        # Log each hidden name ONCE per report: scrub() runs on many text chunks
        # (payload, facts, synthesis) sharing one mask, so without this the same
        # name was re-logged on every chunk. New names first seen in a later chunk
        # still log. Masking itself is unchanged — only the audit line is deduped.
        if mask is not None:
            done = mask.__dict__.setdefault("_ner_logged", set())
            pairs = [(n, p) for n, p in pairs if n not in done]
            done.update(n for n, _ in pairs)
        if pairs:
            if mask is not None:
                mask.__dict__["_ner_announced"] = True
            _log("%d leftover name(s) Presidio caught — person & company names the "
                 "custom-identity masker can't catch (restored in the report):\n  %s"
                 % (len(pairs), "\n  ".join(f"{name} = {pseudo}" for name, pseudo in pairs)),
                 "info", logfn)
    else:
        _announce_clean(mask, logfn)
    return out, hits


def _announce_clean(mask, logfn) -> None:
    """Say ONCE per report that Presidio read the text and found no leftover names.
    The Log only listed names it hid, so "checked -- nothing to hide" and "never
    ran" looked the same, and an operator could not tell whether it worked."""
    if mask is None or mask.__dict__.get("_ner_announced") or mask.__dict__.get("_ner_failed"):
        return                                         # never "clean" after a part went unread
    mask.__dict__["_ner_announced"] = True
    _log("checked the text — no leftover person or company names to hide", "info", logfn)


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
