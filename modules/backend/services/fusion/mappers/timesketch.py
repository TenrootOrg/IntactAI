"""Timesketch mapper — Plaso/KAPE timeline events -> event entities + IOCs,
scoped to one asset (a timesketch run is per client). Timesketch's role is
the timeline glue + indicator extraction; it supplies time-anchored events
and any IPs/domains/hashes it observed (which then correlate cross-host).

Input: a list of event rows (datetime, message, parser, + fields). In
production these come window-bounded from Elasticsearch; here the mapper is
pure over whatever rows it's handed.
"""

from __future__ import annotations

import re

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..anomaly import score_row
from ..severity import from_anomaly
from . import fieldspec as F

MODULE = "timesketch"

# An analyzer TAG is a detection, and it is the reason fusion selected the event
# out of a 380k-event timeline at all (the fetch queries `_exists_:tag`). But
# anomaly scoring is keyword-matching over the row text, so a tagged event whose
# message happens to contain no scary words scores 0 -> "informational" -> and is
# then cut by the case's default `medium` severity floor. Measured: a real fuse
# pulled 382 tagged events and put ONE asset node in the graph, because every
# event had been selected for its tag and then thrown away for not mentioning
# mimikatz. Selecting by detection and ignoring the detection when scoring it is
# the same mistake twice.
#
# So a tag confers a severity FLOOR (the row's own score still wins if higher):
_TAG_FLOOR_HIGH = 20        # -> "high"
_TAG_FLOOR_MEDIUM = 10      # -> "medium", clears the default floor
# Routine bookkeeping tags that an analyzer emits for EVERY matching event, not
# because anything is wrong. These stay at whatever the row scores on its own —
# a case has thousands of logons (3,480 measured on one host), and promoting an
# arbitrary 5 of them to medium is noise wearing a detection's clothes. They
# still reach the graph when the operator drops the floor to informational,
# which is exactly the control that exists for this.
_ROUTINE_TAGS = {
    "logon-event", "logoff-event", "session-id", "known-domain",
    "browser-search", "browser-timeframe", "win-service",
    # `known-cdn` is the domain analyzer saying "this is Akamai/Google/etc" —
    # the OPPOSITE of a detection. It was surfacing as a medium-severity
    # "TimeSketch: known-cdn" finding on every host, which is noise wearing a
    # detection's clothes and exactly what the routine list is for.
    "known-cdn",
    # An application crash is timeline CONTEXT, not a finding. Measured on a
    # clean corporate desktop: win_crash raised five HIGH findings, and the
    # crashing programs were CalculatorApp.exe, setup.exe and Velociraptor.exe
    # (our own agent). Crashes do matter in DFIR — a process dying repeatedly
    # can mark a failed exploit — but that is a pattern an analyst reads off
    # the timeline, not a per-crash high-severity alert.
    "win_crash", "win-crash",
    # Off-hours activity is the same shape of signal: real on a compromised
    # host, pure noise on any machine whose owner works late. Worse, the
    # analyzer attaches whatever domain the event touched, so it produced
    # medium findings named "outside-active-hours (github.com)" — an innocent
    # indicator dressed as an actionable one. Keep the tag on the event so it
    # is visible in the timeline; do not raise it.
    "outside-active-hours",
    # --------------------------------------------------------------------
    # UBIQUITOUS FORENSIC ARTIFACTS from the Windows ATT&CK rule set. These
    # rules are pivot views, not alerts — the upstream author marks every one
    # `create_view: true`, i.e. "a saved search for an analyst to browse".
    #
    # MUICache / ShimCache / UserAssist / BAM record EVERY program ever run;
    # Run keys, firewall rules and TaskCache exist on every Windows install;
    # 4634 logoff fires on every session end. Measured on a clean corporate
    # desktop they produced 14 medium "win-execution" findings, 5 "win-autorun"
    # at HIGH and 5 "win-user-acc" — 20 findings on a machine with nothing
    # wrong with it, against a budget of five.
    #
    # They stay ON, keep their tags, and remain searchable in the timeline and
    # visible as graph context. They simply do not raise. A rule describing an
    # ANOMALY (win_firewalldisabled, win_uacbypass, win_eventlog_clear) uses a
    # different tag and is deliberately not listed here — verified: no tag
    # below is shared with a detection rule.
    "win-execution",        # execution_indicator / shimcache / userassist / bam
    "win-autorun",          # Run keys — present on every host
    "win-user-acc",         # includes 4634 logoff
    "win-firewall",         # the firewall RULE inventory, not firewalldisabled
    "win-rdp",              # session start/stop records; RDP-Tunnel is separate
    "powershell config",    # the ExecutionPolicy value, not its abuse
}
# Detections worth surfacing above the default floor.
# NOTE: "crash" deliberately absent — win_crash is routine context above, and
# leaving the hint in would fight that decision for any crash-named tag.
_HIGH_TAG_HINTS = ("sigma", "phishy", "timestomp", "bruteforce", "malware",
                   "suspicious")

# --------------------------------------------------------------------------
# The Windows ATT&CK rule set (modules/timesketch/config/tags.yaml) tags every
# hit with an EXPLICIT severity word and its ATT&CK codes, e.g.
#   ['win-mimikatz', 'T1003', 'Credential-Access', 'High']
# An author who wrote "High" on the rule has told us more than any substring
# guess can, so the explicit word wins; _HIGH_TAG_HINTS stays as the fallback
# for tags the built-in analyzers generate, which carry no severity at all.
# `context` is OURS, added to the vendored rule file — see tags.yaml. It marks a
# rule whose artifact exists on every healthy Windows host (MUICache, Run keys,
# TaskCache, firewall rules, RDP session records). Those rules are pivot views,
# not alerts: the event keeps its tags and stays searchable and visible in the
# graph, but raises nothing and is not a host fact either.
_SEVERITY_WORDS = {"high": None, "medium": None, "low": None, "info": None,
                   "context": None}

# ATT&CK technique codes: T1003, T1021.001, T1546.003.
_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)

# ATT&CK TACTIC names. These appear alongside the technique code on the same
# rule and are LABELS describing the technique, not detections of their own.
# Without this every rule hit would derive a second finding titled
# "TimeSketch: Credential-Access" sitting next to the real one.
_TACTIC_WORDS = frozenset((
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
    # Free-form descriptors the rule set uses next to the tactic.
    "user-execution", "macro-enabled", "base64", "double-encoded",
    "double-encoded-null-padding", "encoded-python", "encoded-gzip",
    "impacket", "bluekeep", "scan", "wireless", "applocker-denied",
    "applocker-allowed", "security log disabled", "event log disabled",
    # Generic descriptors that lose to a real name but win alphabetically, or
    # that belong to a Context rule co-matching a real one. "Software" beat
    # "SysInternals" on win_sysinternals; "Existence" (the ShimCache rule's
    # sub-tag) titled a HIGH finding raised by a different rule on the same
    # event; "end"/"start" are RDP session-record markers.
    "software", "existence", "end", "start",
    # `win` is the rule set's generic platform marker, carried by many rules.
    # It is not the name of anything. Left in the running it won titles and a
    # real run produced five findings all called "TimeSketch: win (T1070)",
    # which tells an analyst nothing and merges unrelated techniques.
    "win",
))


# Ordered worst-first. An event routinely matches SEVERAL rules — a ShimCache
# entry for a malicious binary hits both the execution-artifact rule (Context)
# and whatever detection named that binary — so the grade must be the MAXIMUM
# present, never the first one iteration happens to reach. Taking the first cost
# a real run its RDP-Tunnel (T1021.001) and named-pipe-privesc (T1134.001)
# findings, because both events also matched a Context rule.
_SEVERITY_ORDER = ("high", "medium", "low", "info", "context")


def _severity_word(tags):
    """The most severe explicit severity keyword on this event, or None."""
    found = {str(t).strip().lower() for t in (tags or [])} & set(_SEVERITY_ORDER)
    for word in _SEVERITY_ORDER:
        if word in found:
            return word
    return None


def _attack_codes(tags):
    """ATT&CK technique codes on this event, uppercased and de-duplicated."""
    out = []
    for t in tags or []:
        v = str(t).strip()
        if _ATTACK_RE.match(v) and v.upper() not in out:
            out.append(v.upper())
    return out


def _is_label(tag) -> bool:
    """True for tags that describe a detection rather than being one.

    Severity words, ATT&CK codes and tactic names all travel WITH a rule hit.
    Treating any of them as a detection in its own right would multiply one
    rule hit into three or four findings on the same event."""
    low = str(tag).strip().lower()
    return (low in _SEVERITY_WORDS or low in _TACTIC_WORDS
            or bool(_ATTACK_RE.match(str(tag).strip())))


def _summarise(msg: str) -> str:
    """A one-line label for a plaso event message.

    EVTX messages are multi-line records — "[4634] An account was logged
    off.\\n\\nSubject:\\n\\tSecurity ID:\\t\\tS-1-5-18\\n\\tAccount Name:..." — and the
    label was a raw 80-character slice of that. It reached the case timeline and
    the LLM payload with embedded newlines and tabs, which renders as broken
    text and spends tokens on whitespace. The FIRST line is the part a human
    wrote as the summary; everything after it is the field dump, which stays
    available in the evidence locator.
    """
    # plaso stores these as ONE physical line containing literal "\\n"
    # sequences, so unescape before splitting or there is nothing to split on.
    text = str(msg or "").replace("\\n", "\n").replace("\\t", "\t")
    lines = [" ".join(ln.split()) for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    out = lines[0]
    # The headline alone is often too thin to triage on — "[1001] Fault bucket
    # 1159357481657437299, type 5" says nothing about WHAT crashed, and the
    # answer ("Event Name: crashpad_log") is the very next line. Pull in the
    # first couple of populated "Key: value" lines, skipping bare section
    # headers like "Subject:" which carry no value of their own.
    for ln in lines[1:]:
        if len(out) >= 140:
            break
        if ":" not in ln:
            continue
        key, _, val = ln.partition(":")
        if not val.strip() or not key.strip():
            continue
        out += " · " + ln
    return out[:200]


def _tag_floor(tags) -> int:
    """Minimum anomaly a tagged event deserves, from its analyzer tags.

    An EXPLICIT severity word from the ATT&CK rule set wins outright — the rule
    author graded the detection and that beats our substring heuristics. `info`
    is host posture (hostname, OS version, timezone) and grades to nothing.
    Everything else falls back to the built-in analyzers' tag names, which
    carry no severity of their own."""
    word = _severity_word(tags)
    if word == "high":
        return _TAG_FLOOR_HIGH
    if word == "medium":
        return _TAG_FLOOR_MEDIUM
    if word in ("low", "info", "context"):
        return 0

    floor = 0
    for t in tags or []:
        low = str(t).strip().lower()
        if not low or low in _ROUTINE_TAGS or _is_label(t):
            continue
        if any(h in low for h in _HIGH_TAG_HINTS):
            return _TAG_FLOOR_HIGH          # can't be beaten by another tag
        floor = max(floor, _TAG_FLOOR_MEDIUM)
    return floor
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOM = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0, first=None,
         flags=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)], anomaly=anomaly,
                  severity=from_anomaly(anomaly), first_seen=first, last_seen=first,
                  flags=list(flags or []))


# Tags whose ENTIRE meaning is the indicator they point at. If no indicator on
# the event survives keys.classify_indicator, the tag has nothing to say and
# must not raise a finding. See the call site for the measured false positives.
_INDICATOR_TAGS = frozenset((
    "rare-domain", "phishy-domain", "phishy_domain", "known-domain",
    "suspicious-domain", "malicious-domain",
))


def _needs_indicator(tags) -> bool:
    """True when every non-routine tag on this event is indicator-only."""
    real = [str(t).strip() for t in (tags or []) if str(t).strip()]
    # Labels (severity word, ATT&CK code, tactic) are not tags that could
    # satisfy the gate; without dropping them a rare-domain event carrying a
    # severity word would look "not indicator-only" and skip the check.
    real = [t.lower() for t in real
            if t.lower() not in _ROUTINE_TAGS and not _is_label(t)]
    return bool(real) and all(t in _INDICATOR_TAGS for t in real)


def _detection_title(tags) -> str | None:
    """A human detection name for the analyzer tags on an event, or None.

    correlate._derive_findings groups NON-sigma detection events per
    (host, title) into one finding each — that is the mechanism by which a
    detection reaches the case timeline, the report and the LLM at all. It keys
    off the `detection` flag and `attrs["title"]`, and the TimeSketch mapper
    stamped neither, so every TimeSketch event landed in the graph as a bare
    entity that no finding ever referenced and no operator ever saw. A fuse of
    real tagged data produced 12 event entities and 0 findings.

    Routine bookkeeping tags deliberately do NOT produce a detection: a logon is
    context for a timeline, not something to raise. Same rule as the severity
    floor above, and for the same reason.
    """
    # `info` rules are deterministic host FACTS, not detections. They land as
    # attributes on the endpoint entity instead — see map_timesketch.
    if _severity_word(tags) in ("low", "info", "context"):
        return None

    names = [str(t).strip() for t in (tags or []) if str(t).strip()]
    # Drop the labels that travel with a rule hit (severity word, ATT&CK code,
    # tactic name). Keeping them would let "Credential-Access" or "T1003"
    # become the title of a finding instead of the rule that fired.
    real = [t for t in names
            if t.lower() not in _ROUTINE_TAGS and not _is_label(t)]
    codes = _attack_codes(tags)
    if not real:
        # 24 of the 116 rules carry no descriptive tag at all — only the
        # generic `win` marker plus their technique codes (win_uacbypass,
        # win_namedpipeprivesc, win_csbeaconexec, win_schtask_deleted…).
        # Dropping them because `win` is uninformative silenced real
        # detections; the technique IS a usable name, so title from it.
        if codes and _severity_word(tags) not in ("low", "info", "context"):
            return "TimeSketch: " + ", ".join(codes)
        return None
    # One title per event, so an event carrying two detections groups under the
    # more serious one rather than splitting arbitrarily.
    # Prefer the RULE that fired over an analyzer's tag when an event carries
    # both. The BITS-job rule and the domain analyzer hit the same a.uguu.se
    # event; "win-bitstransfer" names the technique that matched, "rare-domain"
    # only names how the domain analyzer felt about the hostname.
    _rule_first = lambda t: 0 if str(t).lower().startswith("win") else 1
    real.sort(key=lambda t: (_rule_first(t),
                             0 if any(h in t.lower() for h in _HIGH_TAG_HINTS) else 1,
                             t))
    title = f"TimeSketch: {real[0]}"
    # Name the technique. An analyst reading "TimeSketch: win_zero_logon
    # (T1068)" can pivot to ATT&CK without opening the rule file, and the LLM
    # gets a technique it can reason about rather than an opaque rule name.
    if codes:
        title = f"{title} ({', '.join(codes)})"
    return title


def map_timesketch(events, *, run_id: str, asset: str, hostname=None,
                   host_index=None) -> tuple[list, list]:
    """Map tagged TimeSketch events onto per-host entities.

    `host_index` maps an event's `__ts_timeline_id` to
    {"asset": <asset id>, "hostname": <name>}. A multi-client run imports one
    timeline per client into a shared sketch, so without it every event in a
    20-host collection is attributed to `asset` — the first client — and the
    graph claims one machine did everything. Events whose timeline is unknown
    fall back to `asset`, which is also the whole single-host path.
    """
    ents: list[Entity] = []
    rels: list[Relationship] = []
    host_index = host_index or {}

    def _host_for(e):
        tl = e.get("__ts_timeline_id")
        hit = host_index.get(str(tl)) if tl is not None else None
        if hit:
            return hit.get("asset") or asset, hit.get("hostname") or hostname
        # Second chance from the event itself: EVTX records carry
        # computer_name (plaso leaves `hostname` as the literal "N/A").
        cn = str(e.get("computer_name") or "").strip()
        if cn and cn.upper() != "N/A":
            for hit in host_index.values():
                if str(hit.get("hostname") or "").lower() == cn.lower():
                    return hit.get("asset") or asset, hit.get("hostname")
        return asset, hostname

    # Every asset that actually appears gets a node — declared up front for the
    # default one, and lazily below for any other host the events name.
    seen_assets = {asset}
    asset_ents = {}
    # Deterministic host FACTS from the `Info` rules — OS version, hostname,
    # timezone, proxy config, network adapters, user profiles. They are the
    # same shape of value a Velociraptor artifact returns, so they belong on
    # the endpoint entity where the report's host table and the LLM already
    # read, NOT in a finding. Collected during the loop, attached after it.
    posture = {}
    _a0 = Entity(id=asset, type="asset", label=str(hostname or asset.split(":")[-1]),
                 attrs={"hostname": hostname, "kind": "endpoint", "_assets": [asset]},
                 sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")])
    asset_ents[asset] = _a0
    ents.append(_a0)

    for i, e in enumerate(events or []):
        if not isinstance(e, dict):
            continue
        ev_asset, ev_host = _host_for(e)
        if ev_asset not in seen_assets:
            seen_assets.add(ev_asset)
            _an = Entity(
                id=ev_asset, type="asset",
                label=str(ev_host or ev_asset.split(":")[-1]),
                attrs={"hostname": ev_host, "kind": "endpoint", "_assets": [ev_asset]},
                sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")])
            asset_ents[ev_asset] = _an
            ents.append(_an)
        ts = keys.norm_ts(F.get(e, "datetime", "Timestamp", "TimeCreated", *F.TIMES))
        msg = str(F.get(e, "message", "Message", "description", default="") or "")
        # Score the EVIDENCE, never our own annotations. score_row concatenates
        # every value in the row and keyword-matches the blob, and "rwx" is a
        # three-character _CRIT keyword worth +100 — so a random OpenSearch
        # document id that happens to contain those letters (we inject it as
        # `_ts_id`) turns an ordinary logon into a CRITICAL finding. Reproduced:
        # {"message": "an ordinary logon", "_ts_id": "jXcZQqrwxBGKvPYSzpM7"}
        # scores 100. Underscore-prefixed keys are metadata we added — _ts_id,
        # __ts_timeline_id, __ts_emojis — and none of them are evidence.
        anom = score_row({k: v for k, v in e.items() if not str(k).startswith("_")})
        # Address the ORIGINAL TimeSketch event when the fetch kept its
        # OpenSearch id. `event/row=i` is an index into the *distilled* list,
        # so it renumbers whenever the analyzer tags change and points at a
        # different event on the next fetch — useless as evidence.
        ts_id = e.get("_ts_id")
        loc = f"sketch/event/{ts_id}" if ts_id else f"event/row={i}"
        eid = keys.event_id(ev_asset, ts, msg)
        # The analyzer tag is WHY this event was selected out of a 380k-event
        # timeline (fusion queries `_exists_:tag`), and it was being dropped
        # here — the graph recorded the event but never which analyzer flagged
        # it, so a 'rare-domain' hit and a routine logon looked identical.
        tags = e.get("tag") or []
        if not isinstance(tags, list):
            tags = [tags]
        tags = [str(t) for t in tags if t]
        anom = max(anom, _tag_floor(tags))

        # Host posture. An `Info` rule fired: record WHICH fact it established
        # and a one-line value, keyed by the rule's own descriptive tag. Capped
        # per host because a rule like win_usrprofile fires once per profile and
        # we want the fact, not an inventory dump in the graph.
        if _severity_word(tags) == "info":
            facts = posture.setdefault(ev_asset, {})
            for t in tags:
                low = str(t).strip().lower()
                if low in _ROUTINE_TAGS or _is_label(t):
                    continue
                vals = facts.setdefault(low, [])
                summary = _summarise(msg)
                if summary and summary not in vals and len(vals) < 5:
                    vals.append(summary)

        det_title = _detection_title(tags)
        ev_entity = _ent(eid, "event",
                         (_summarise(msg) or F.get(e, "parser", default="event")),
                         ev_asset, run_id, loc, anomaly=anom, first=ts,
                         flags=["detection"] if det_title else None,
                         parser=F.get(e, "parser", "source_name", default=None),
                         title=det_title,
                         attack=_attack_codes(tags) or None,
                         tags=tags or None)
        ents.append(ev_entity)

        # indicators from explicit fields + the message text.
        # UNESCAPE FIRST. plaso stores these records as one physical line
        # containing literal "\\n" / "\\t" sequences, and the domain regex is
        # happy to treat the "t" of a "\\t" as part of a hostname: a real fused
        # case carried an IOC called `tINTERNAL.CORP`, which is `\\tINTERNAL.CORP`
        # with the backslash eaten. Same normalisation the label uses.
        scan = str(msg).replace("\\n", " ").replace("\\t", " ")
        cand = set()
        named = {}
        for v in (F.get(e, "src_ip", "dst_ip", "ip", "RemoteAddr", "ipAddress", default=None),):
            if v:
                cand.add(str(v))
        # The analyzers that matter write their indicator to an explicit FIELD,
        # not into the message text: `domain`/`phishy_domains` set `domain`,
        # browser analyzers set `url`. Scanning only `message` meant the value
        # that JUSTIFIED the detection never became an IOC and never reached the
        # graph — a real run surfaced "TimeSketch: rare-domain" as high severity
        # while the domain behind it (a.uguu.se, a throwaway file-host used for
        # staging) existed nowhere in the case. classify_indicator still rejects
        # the NetBIOS names (WORKGROUP, IEWIN7) and CDNs the analyzer mislabels
        # as domains, so this adds signal without adding that noise.
        for v in (F.get(e, "domain", "url", "host", "hostname_query", default=None),):
            if v:
                cand.add(str(v))
        for m in _IP.findall(scan):
            cand.add(m)
        for h in _HASH.findall(scan):
            cand.add(h)
        # Domains too — the module docstring always promised them and the regex
        # was compiled but never used, so the `domain` / `phishy_domains`
        # analyzers in the curated set contributed tags with no IOC to
        # correlate against. keys.classify_indicator is what makes this safe on
        # Windows event text: it rejects filenames (svchost.exe is not a
        # domain) and benign update domains.
        for dm in _DOM.findall(scan):
            cand.add(dm)
        for val in cand:
            kind = keys.classify_indicator(val)
            if not kind:
                continue
            iid = keys.ioc_id(kind, val)
            ents.append(_ent(iid, "ioc", str(val), ev_asset, run_id, loc, anomaly=1,
                             ioc_kind=kind, first=ts))
            rels.append(Relationship(eid, iid, "event_about", sources=[MODULE], ts=ts))
            named.setdefault(kind, str(val))

        # NAME THE INDICATOR IN THE FINDING. _derive_findings groups per
        # (host, title), so a bare "TimeSketch: rare-domain" collapses every
        # flagged domain on a host into ONE finding whose text names none of
        # them — an operator reading the report cannot tell a.uguu.se from
        # WORKGROUP without opening TimeSketch. Appending the indicator both
        # makes the finding actionable and splits it per indicator, which is
        # how an analyst wants them: one finding per suspicious domain.
        if det_title:
            ind = named.get("domain") or named.get("url") or named.get("ip")
            if ind:
                ev_entity.attrs["title"] = f"{det_title} ({ind})"
            elif _needs_indicator(tags):
                # AN INDICATOR DETECTION WITH NO INDICATOR IS NOT A DETECTION.
                # These analyzers exist solely to point at a domain/URL, and
                # their false-positive rate on real endpoints is high: measured
                # on a clean corporate desktop, `phishy_domains` flagged the
                # private address 192.168.1.23 eight times and `domain` called
                # doubleclick.net / go.microsoft.com / clarity.ms rare. Each
                # would have raised a HIGH or medium finding naming nothing an
                # analyst could act on. classify_indicator already rejects
                # private IPs, NetBIOS names, private TLDs and known CDNs — so
                # "the tag fired but nothing survived classification" is
                # precisely the signature of a false positive. Keep the event
                # in the graph as timeline context; just do not raise it.
                ev_entity.attrs.pop("title", None)
                try:
                    ev_entity.flags = [f for f in (ev_entity.flags or [])
                                       if f != "detection"]
                except Exception:
                    pass

    # Attach the collected host facts. Stored under one `host_facts` key rather
    # than splattered across the asset's attrs, so a downstream reader can tell
    # what TimeSketch established from what the other modules did.
    for a_id, facts in posture.items():
        ent = asset_ents.get(a_id)
        if ent is None or not facts:
            continue
        ent.attrs["host_facts"] = {k: (v[0] if len(v) == 1 else v)
                                   for k, v in sorted(facts.items())}

    return ents, rels
