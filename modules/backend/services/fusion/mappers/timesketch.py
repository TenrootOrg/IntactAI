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
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOM = re.compile(r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+){1,}\b")
_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0, first=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)], anomaly=anomaly,
                  severity=from_anomaly(anomaly), first_seen=first, last_seen=first)


def map_timesketch(events, *, run_id: str, asset: str, hostname=None) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    ents.append(Entity(id=asset, type="asset", label=str(hostname or asset.split(":")[-1]),
                       attrs={"hostname": hostname, "kind": "endpoint", "_assets": [asset]},
                       sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    for i, e in enumerate(events or []):
        if not isinstance(e, dict):
            continue
        ts = keys.norm_ts(F.get(e, "datetime", "Timestamp", "TimeCreated", *F.TIMES))
        msg = str(F.get(e, "message", "Message", "description", default="") or "")
        anom = score_row(e)
        loc = f"event/row={i}"
        eid = keys.event_id(asset, ts, msg)
        ents.append(_ent(eid, "event", (msg[:80] or F.get(e, "parser", default="event")),
                         asset, run_id, loc, anomaly=anom, first=ts,
                         parser=F.get(e, "parser", "source_name", default=None)))

        # indicators from explicit fields + the message text
        cand = set()
        for v in (F.get(e, "src_ip", "dst_ip", "ip", "RemoteAddr", "ipAddress", default=None),):
            if v:
                cand.add(str(v))
        for m in _IP.findall(msg):
            cand.add(m)
        for h in _HASH.findall(msg):
            cand.add(h)
        for val in cand:
            kind = keys.classify_indicator(val)
            if not kind:
                continue
            iid = keys.ioc_id(kind, val)
            ents.append(_ent(iid, "ioc", str(val), asset, run_id, loc, anomaly=1,
                             ioc_kind=kind, first=ts))
            rels.append(Relationship(eid, iid, "event_about", sources=[MODULE], ts=ts))

    return ents, rels
