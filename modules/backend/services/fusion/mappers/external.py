"""Attached log data (SIEM / firewall / EDR / IdP / proxy) -> entities.

Rows come normalized by external_logs ({"n": fields, "raw": original}). What
joins the case is what the rows NAME: hosts, public IPs, domains, hashes and
domain accounts become the same global nodes the endpoint mappers use, so a
firewall row to an address and a Velociraptor connection to it are one node.
Values the log alone names are pruned after the merge
(correlate._prune_external_only): a firewall export lists thousands of harmless
addresses, and only the ones that meet the case, or a vendor alert, belong in it.
All of them stay searchable in chat.

A vendor alert (a row with a stated severity of medium or above) becomes a
"detection" event, folded per host + rule + episode, so it reaches the Timeline
through the same pass as every other detection.
"""
from __future__ import annotations

import re

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef, map_skip
from .cloud import _account_key

MODULE = "external"
ALERT_LEVELS = ("medium", "high", "critical")
_RW = {"critical": 100, "high": 40, "medium": 10}
_LOCS = 6                      # evidence rows kept per entity (the drill-down shows them)


def _hostish(h) -> bool:
    s = str(h or "").strip()
    return bool(s) and len(s) <= 255 and not re.fullmatch(r"[\d.:]+", s)   # an IP is not a host name


def map_external(collected: dict, *, run_id: str, data_type: str, label: str) -> tuple[list, list]:
    from ..external_logs import DATA_TYPES, artifact_name
    art = artifact_name(data_type)
    rows = collected.get(art)
    if rows is None:
        rows = next((v for v in collected.values() if isinstance(v, list)), [])
    dt = DATA_TYPES.get(data_type, "Logs")
    anchor = f"asset:log_source:{run_id}"
    agg: dict = {}                  # id -> [type, label, attrs, first, last, count, locs]
    rels: dict = {}
    alerts: dict = {}

    def add(eid, etype, lab, attrs, ts, loc, assets):
        a = agg.get(eid)
        if a is None:
            a = agg[eid] = [etype, lab, dict(attrs, _assets=[]), ts, ts, 0, []]
        for x in assets:
            if x not in a[2]["_assets"]:
                a[2]["_assets"].append(x)
        if ts:
            a[3] = min(a[3] or ts, ts)
            a[4] = max(a[4] or ts, ts)
        a[5] += 1
        if len(a[6]) < _LOCS:
            a[6].append(loc)

    for i, r in enumerate(rows or []):
        try:
            n = (r or {}).get("n") or {}
            loc, ts = f"{art}/row={i}", n.get("ts")
            # Values are placed on a host only when the row NAMES one. Never on the
            # log itself: every address an endpoint talked to also crossed the
            # firewall, and "seen on the host and in the firewall log" would read
            # as two hosts -- a cross-host finding out of ordinary traffic.
            assets = []
            if _hostish(n.get("host")):
                hid = keys.asset_id_from_host(n["host"])
                add(hid, "asset", str(n["host"]).strip().split(".")[0], {"hostname": n["host"]}, ts, loc, [])
                assets = [hid]
            joins = []
            vals = [n.get("src_ip"), n.get("dst_ip"), n.get("domain"), n.get("hash")]
            vals += list(n.get("ips") or []) + list(n.get("domains") or []) + list(n.get("hashes") or [])
            if n.get("url"):
                host = str(n["url"]).split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                vals.append(host)
            for v in vals:
                kind = keys.classify_indicator(v) if v else None
                if kind:
                    iid = keys.ioc_id(kind, v)
                    add(iid, "ioc", str(v).strip().lower(), {"ioc_kind": kind}, ts, loc, assets)
                    joins.append(iid)
            for u in [n.get("user")] + list(n.get("users") or []):
                aid = _account_key(u) if u else None
                if aid and aid.startswith("account:domain:"):      # a bare name joins nothing
                    add(aid, "account", aid.split("\\")[-1], {}, ts, loc, assets)
                    joins.append(aid)
            sev = n.get("severity")
            if sev in ALERT_LEVELS:
                rule = n.get("rule") or n.get("action") or "alert"
                alerts.setdefault(((assets or [anchor])[0], str(rule)[:200], sev), []).append((ts, loc, n, joins))
        except Exception as e:                             # noqa: BLE001 -- one bad row, not the file
            map_skip(f"{art} rows", e)

    ents = [Entity(id=anchor, type="asset", label=f"{dt} log: {label}",
                   attrs={"kind": "log_source", "data_type": data_type, "_assets": [anchor]},
                   sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")])]
    for eid, (etype, lab, attrs, first, last, cnt, locs) in agg.items():
        if etype == "asset":
            attrs["_assets"] = [eid]
        attrs["external_rows"] = cnt
        ents.append(Entity(id=eid, type=etype, label=lab, attrs=attrs, sources=[MODULE],
                           evidence=[EvidenceRef(MODULE, run_id, x) for x in locs],
                           first_seen=first, last_seen=last))

    for (asset, rule, sev), hits in alerts.items():
        for ep in keys.split_episodes(hits, lambda h: h[0]):
            tss = sorted(h[0] for h in ep if h[0])
            n0 = ep[0][2]
            eid = keys.event_key(asset, MODULE, data_type, rule, sev, tss[0] if tss else "")
            title = f"{dt}: {rule}"
            attrs = {"_assets": [asset], "title": title, "detection": rule, "occurrences": len(ep),
                     "data_type": data_type}
            for k, f in (("ev_user", "user"), ("ev_tgtip", "dst_ip"), ("ev_proc", "process"),
                         ("ev_cmdline", "cmdline"), ("ev_sha256", "hash")):
                v = next((h[2].get(f) for h in ep if h[2].get(f)), None)
                if v:
                    attrs[k] = v
            if n0.get("message"):
                attrs["message"] = str(n0["message"])[:500]
            ents.append(Entity(id=eid, type="event", label=title, attrs=attrs, sources=[MODULE],
                               evidence=[EvidenceRef(MODULE, run_id, h[1]) for h in ep[:_LOCS]],
                               severity=sev, anomaly=_RW[sev], flags=["detection"],
                               first_seen=tss[0] if tss else None, last_seen=tss[-1] if tss else None))
            for j in {x for h in ep for x in h[3]}:
                kind = "executed" if j.startswith("account:") else "event_about"
                src, dst = (j, eid) if kind == "executed" else (eid, j)
                rels[(src, dst, kind)] = Relationship(src, dst, kind, sources=[MODULE],
                                                      ts=tss[0] if tss else None)
    return ents, list(rels.values())
