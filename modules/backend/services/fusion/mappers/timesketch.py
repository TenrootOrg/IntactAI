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
}
# Detections worth surfacing above the default floor.
_HIGH_TAG_HINTS = ("sigma", "phishy", "timestomp", "bruteforce", "malware",
                   "suspicious", "crash")


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
    """Minimum anomaly a tagged event deserves, from its analyzer tags."""
    floor = 0
    for t in tags or []:
        low = str(t).strip().lower()
        if not low or low in _ROUTINE_TAGS:
            continue
        if any(h in low for h in _HIGH_TAG_HINTS):
            return _TAG_FLOOR_HIGH          # can't be beaten by another tag
        floor = max(floor, _TAG_FLOOR_MEDIUM)
    return floor
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOM = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0, first=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)], anomaly=anomaly,
                  severity=from_anomaly(anomaly), first_seen=first, last_seen=first)


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
    ents.append(Entity(id=asset, type="asset", label=str(hostname or asset.split(":")[-1]),
                       attrs={"hostname": hostname, "kind": "endpoint", "_assets": [asset]},
                       sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    for i, e in enumerate(events or []):
        if not isinstance(e, dict):
            continue
        ev_asset, ev_host = _host_for(e)
        if ev_asset not in seen_assets:
            seen_assets.add(ev_asset)
            ents.append(Entity(
                id=ev_asset, type="asset",
                label=str(ev_host or ev_asset.split(":")[-1]),
                attrs={"hostname": ev_host, "kind": "endpoint", "_assets": [ev_asset]},
                sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))
        ts = keys.norm_ts(F.get(e, "datetime", "Timestamp", "TimeCreated", *F.TIMES))
        msg = str(F.get(e, "message", "Message", "description", default="") or "")
        anom = score_row(e)
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
        ents.append(_ent(eid, "event",
                         (_summarise(msg) or F.get(e, "parser", default="event")),
                         ev_asset, run_id, loc, anomaly=anom, first=ts,
                         parser=F.get(e, "parser", "source_name", default=None),
                         tags=tags or None))

        # indicators from explicit fields + the message text
        cand = set()
        for v in (F.get(e, "src_ip", "dst_ip", "ip", "RemoteAddr", "ipAddress", default=None),):
            if v:
                cand.add(str(v))
        for m in _IP.findall(msg):
            cand.add(m)
        for h in _HASH.findall(msg):
            cand.add(h)
        # Domains too — the module docstring always promised them and the regex
        # was compiled but never used, so the `domain` / `phishy_domains`
        # analyzers in the curated set contributed tags with no IOC to
        # correlate against. keys.classify_indicator is what makes this safe on
        # Windows event text: it rejects filenames (svchost.exe is not a
        # domain) and benign update domains.
        for dm in _DOM.findall(msg):
            cand.add(dm)
        for val in cand:
            kind = keys.classify_indicator(val)
            if not kind:
                continue
            iid = keys.ioc_id(kind, val)
            ents.append(_ent(iid, "ioc", str(val), ev_asset, run_id, loc, anomaly=1,
                             ioc_kind=kind, first=ts))
            rels.append(Relationship(eid, iid, "event_about", sources=[MODULE], ts=ts))

    return ents, rels
