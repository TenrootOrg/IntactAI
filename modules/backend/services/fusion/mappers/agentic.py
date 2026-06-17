"""Agentic (Velociraptor) mapper — ``collected_data`` {artifact: [rows]} ->
entities + relationships. ONE agentic run spans N clients, so rows are
SPLIT by their ``_client_id`` tag into per-asset entities (1 run : N hosts).

Domain accounts and IOCs are keyed GLOBALLY (host-independent), so the
same account/IP seen on multiple assets collapses to one node whose
``_assets`` list then exposes lateral movement.
"""

from __future__ import annotations

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..anomaly import score_row
from ..severity import from_anomaly
from . import fieldspec as F

MODULE = "agentic"

_LOCAL_DOMAINS = {"", "nt authority", "workgroup", "builtin", "font driver host",
                  "window manager", "local service", "network service"}


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0, first=None,
         flags=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)], anomaly=anomaly,
                  severity=from_anomaly(anomaly), first_seen=first,
                  last_seen=first, flags=list(flags or []))


def _account_eid(asset, domain, user):
    """Domain accounts -> global node (cross-host); local -> asset-scoped."""
    d = (str(domain) if domain else "").strip().lower()
    u = (str(user) if user else "").strip().lower()
    if not u or u in ("-", "n/a"):
        return None, d, u
    if d and d not in _LOCAL_DOMAINS and not d.endswith("$"):
        return f"account:domain:{d}\\{u}", d, u          # GLOBAL
    return keys.account_id(asset, None, u), d, u          # local, asset-scoped


def map_agentic(collected_data: dict, *, run_id: str, hostnames: dict | None = None) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    hostnames = hostnames or {}

    def asset_of(row):
        cid = F.get(row, *F.CLIENT_ID)
        if cid:
            return keys.asset_id(cid), (hostnames.get(str(cid)) or F.get(row, *F.HOSTNAME))
        host = F.get(row, *F.HOSTNAME)
        return (keys.asset_id_from_host(host) if host else "asset:endpoint:unknown"), host

    assets_seen: dict[str, str] = {}
    proc_by_asset_pid: dict[tuple, str] = {}

    for artifact, rows in (collected_data or {}).items():
        an = artifact.lower()
        for i, r in enumerate(rows or []):
            if not isinstance(r, dict):
                continue
            asset, host = asset_of(r)
            if asset not in assets_seen:
                assets_seen[asset] = host
                ents.append(Entity(id=asset, type="asset", label=str(host or asset.split(":")[-1]),
                                   attrs={"hostname": host, "kind": "endpoint", "_assets": [asset]},
                                   sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))
            ts = F.first_ts(r)
            loc = f"{artifact}/row={i}"

            # ---- processes -------------------------------------------------
            if "pstree" in an or "pslist" in an or "processes" in an:
                pid = F.get(r, *F.PID)
                if pid is None:
                    continue
                name = F.get(r, *F.PROC_NAME) or "?"
                ct = F.get(r, *F.CREATETIME)
                eid = keys.process_id(asset, pid, ct, name)
                proc_by_asset_pid[(asset, str(pid))] = eid
                ents.append(_ent(eid, "process", f"{name} ({pid})", asset, run_id, loc,
                                 anomaly=score_row(r), first=keys.norm_ts(ct or ts),
                                 pid=str(pid), name=name, cmdline=F.get(r, *F.CMDLINE),
                                 createtime=keys.norm_ts(ct)))
                owner = F.get(r, *F.USER)
                if owner:
                    aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), owner)
                    if aeid:
                        ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset,
                                         run_id, loc, user=u, domain=d))
                        rels.append(Relationship(aeid, eid, "executed", sources=[MODULE], ts=ts))

            # ---- spawned (second pass would be cleaner; do inline by ppid) -
            # handled in finalize below

            # ---- logon / auth -> account authenticated to asset ----------
            elif "logon" in an or "rdpauth" in an or "authentication" in an:
                user = F.get(r, *F.USER)
                aeid, d, u = _account_eid(asset, F.get(r, *F.DOMAIN), user)
                if aeid:
                    ents.append(_ent(aeid, "account", (f"{d}\\{u}" if d else u), asset, run_id,
                                     loc, anomaly=score_row(r), first=ts, user=u, domain=d))
                    rels.append(Relationship(aeid, asset, "authenticated", sources=[MODULE],
                                             ts=ts, attrs={"logon_type": F.get(r, "LogonType", default=None)}))

            # ---- network -> netconn + ioc --------------------------------
            elif "netstat" in an or "network" in an:
                raddr = F.get(r, *F.REMOTE_ADDR)
                if not raddr:
                    continue
                kind = keys.classify_indicator(raddr)
                if kind:
                    iid = keys.ioc_id(kind, raddr)
                    ents.append(_ent(iid, "ioc", str(raddr), asset, run_id, loc,
                                     anomaly=1, ioc_kind=kind, first=ts))
                    pid = F.get(r, *F.PID)
                    src = proc_by_asset_pid.get((asset, str(pid))) if pid is not None else None
                    if src:
                        rels.append(Relationship(src, iid, "connected", sources=[MODULE], ts=ts))

            # ---- detections / yara ---------------------------------------
            elif "yara" in an:
                rule = F.get(r, "Rule", "rule", "RuleName", "name", default=None) or artifact
                pid = F.get(r, *F.PID)
                yid = keys.yarahit_id(asset, rule, pid or "")
                ents.append(_ent(yid, "yarahit", str(rule), asset, run_id, loc, anomaly=50,
                                 first=ts, rule=rule))
                if pid is not None and proc_by_asset_pid.get((asset, str(pid))):
                    rels.append(Relationship(yid, proc_by_asset_pid[(asset, str(pid))],
                                             "matched", sources=[MODULE], ts=ts))

            # ---- web / dns -> domain ioc ---------------------------------
            elif "dnscache" in an or "webhistory" in an or "history" in an or "download" in an:
                url = F.get(r, "Url", "URL", "Name", "Domain", "Host", default=None)
                kind = keys.classify_indicator(url) if url else None
                if kind:
                    iid = keys.ioc_id(kind, url)
                    ents.append(_ent(iid, "ioc", str(url), asset, run_id, loc, anomaly=1,
                                     ioc_kind=kind, first=ts))

            # ---- persistence: services / autoruns / scheduled tasks ------
            elif any(k in an for k in ("autoruns", "services", "scheduledtask",
                                       "taskscheduler", "scheduled")):
                sname = (F.get(r, "Name", "ServiceName", "TaskName", "Entry", "Rule", default=None)
                         or artifact)
                sid = keys.service_id(asset, sname)
                ents.append(_ent(sid, "service", str(sname), asset, run_id, loc,
                                 anomaly=score_row(r), first=ts, artifact=artifact,
                                 binary=F.get(r, "Binary", "BinaryPath", "ImagePath", "Command",
                                              *F.PATH, default=None)))

            # ---- execution evidence -> event (+ file + hash ioc) ---------
            elif any(k in an for k in ("amcache", "prefetch", "userassist", "shimcache",
                                       "appcompat", "srum", "bam")):
                path = F.get(r, *F.PATH) or F.get(r, "Name", default=artifact)
                eid = keys.event_id(run_id, ts, f"exec:{path}")
                ents.append(_ent(eid, "event", f"executed: {str(path)[:60]}", asset, run_id, loc,
                                 anomaly=score_row(r), first=ts, artifact=artifact))

            # ---- other high-signal detections -> event -------------------
            elif any(k in an for k in ("evtx", "eventlog", "hayabusa", "binaryrename",
                                       "untrusted", "lnk", "detection")):
                msg = F.get(r, "Message", "Description", "Name", *F.PATH, default=artifact)
                eid = keys.event_id(run_id, ts, f"{an}:{msg}")
                ents.append(_ent(eid, "event", f"{artifact}: {str(msg)[:80]}", asset, run_id,
                                 loc, anomaly=score_row(r), first=ts, artifact=artifact))

            # ---- hash extraction (ANY artifact) -> cross-host-capable IOC -
            h = F.get(r, *F.SHA256)
            if h and keys.classify_indicator(h) == "hash":
                iid = keys.ioc_id("hash", h)
                ents.append(_ent(iid, "ioc", str(h)[:16] + "…", asset, run_id, loc,
                                 anomaly=10, ioc_kind="hash", first=ts, full_hash=str(h)))

    # ---- spawned edges (ppid) across the processes we created -----------
    for artifact, rows in (collected_data or {}).items():
        an = artifact.lower()
        if not ("pstree" in an or "pslist" in an or "processes" in an):
            continue
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            asset, _ = asset_of(r)
            pid, ppid = F.get(r, *F.PID), F.get(r, *F.PPID)
            if pid is None or ppid is None:
                continue
            child = proc_by_asset_pid.get((asset, str(pid)))
            parent = proc_by_asset_pid.get((asset, str(ppid)))
            if child and parent and child != parent:
                rels.append(Relationship(parent, child, "spawned", sources=[MODULE]))

    return ents, rels
