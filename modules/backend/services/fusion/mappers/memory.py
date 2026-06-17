"""Memory (Volatility3 / VolWeb) mapper — Vol3 plugin rows + YARA hits ->
entities + relationships, scoped to ONE asset (memory is 1 run : 1 host).

Input payload (already-trimmed dicts the analyzer produces):
    {"plugins": {plugin_name: [row, ...]}, "yara": [hit, ...], "host": str}
"""

from __future__ import annotations

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..anomaly import score_row
from ..severity import from_anomaly
from . import fieldspec as F

MODULE = "memory"


def _ent(eid, etype, label, asset, run_id, locator, *, anomaly=0,
         first=None, last=None, flags=None, **attrs):
    a = {"_assets": [asset]}
    a.update({k: v for k, v in attrs.items() if v not in (None, "", [])})
    return Entity(id=eid, type=etype, label=label, attrs=a, sources=[MODULE],
                  evidence=[EvidenceRef(MODULE, run_id, locator)],
                  anomaly=anomaly, severity=from_anomaly(anomaly),
                  first_seen=first, last_seen=last, flags=list(flags or []))


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def map_memory(payload: dict, *, run_id: str, asset: str, hostname=None) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    plugins = (payload or {}).get("plugins") or {}
    yara = (payload or {}).get("yara") or []
    hostname = hostname or (payload or {}).get("host")

    # the asset node itself
    ents.append(Entity(id=asset, type="asset",
                       label=str(hostname or asset.split(":")[-1]),
                       attrs={"hostname": hostname, "kind": "endpoint", "_assets": [asset]},
                       sources=[MODULE],
                       evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    # index plugins by short name (pslist/psscan/...)
    by_short: dict[str, list] = {}
    for name, rows in plugins.items():
        by_short.setdefault(_short(name), []).extend(rows or [])

    # ---- processes (pslist/psscan/pstree) + spawned + cmdline -----------
    cmd_by_pid = {str(F.get(r, *F.PID)): F.get(r, *F.CMDLINE)
                  for r in by_short.get("cmdline", []) if F.get(r, *F.PID) is not None}
    seen_proc: dict[str, str] = {}            # pid -> entity id
    for src in ("pslist", "psscan", "pstree"):
        for r in by_short.get(src, []):
            pid = F.get(r, *F.PID)
            if pid is None:
                continue
            pid = str(pid)
            name = F.get(r, *F.PROC_NAME) or "?"
            ct = F.get(r, *F.CREATETIME)
            pid_eid = keys.process_id(asset, pid, ct, name)
            seen_proc[pid] = pid_eid
            anom = score_row(r)
            cmd = cmd_by_pid.get(pid)
            if cmd and score_row({"c": cmd}) > anom:
                anom = score_row({"c": cmd})
            ents.append(_ent(pid_eid, "process", f"{name} ({pid})", asset, run_id,
                             f"{src}/PID={pid}", anomaly=anom, first=keys.norm_ts(ct),
                             pid=pid, name=name, cmdline=cmd, createtime=keys.norm_ts(ct)))

    # spawned edges from PPID
    for src in ("pslist", "psscan", "pstree"):
        for r in by_short.get(src, []):
            pid, ppid = F.get(r, *F.PID), F.get(r, *F.PPID)
            if pid is None or ppid is None:
                continue
            child = seen_proc.get(str(pid))
            parent = seen_proc.get(str(ppid))
            if child and parent and child != parent:
                rels.append(Relationship(parent, child, "spawned", sources=[MODULE]))

    # ---- malfind -> injected processes ---------------------------------
    for r in by_short.get("malfind", []):
        pid = F.get(r, *F.PID)
        if pid is None:
            continue
        eid = seen_proc.get(str(pid))
        prot = str(F.get(r, "Protection", default="") or "")
        if eid:
            for e in ents:
                if e.id == eid:
                    e.flags = list(dict.fromkeys(e.flags + ["injected"]))
                    e.anomaly = max(e.anomaly, score_row(r), 100)
                    e.severity = from_anomaly(e.anomaly)
                    e.attrs["protection"] = prot or e.attrs.get("protection")
                    break
        else:
            name = F.get(r, *F.PROC_NAME) or "?"
            eid = keys.process_id(asset, pid, None, name)
            ents.append(_ent(eid, "process", f"{name} ({pid})", asset, run_id,
                             f"malfind/PID={pid}", anomaly=max(score_row(r), 100),
                             flags=["injected"], pid=str(pid), name=name, protection=prot))

    # ---- network (netscan/netstat) -> netconn + ioc --------------------
    for src in ("netscan", "netstat"):
        for r in by_short.get(src, []):
            raddr = F.get(r, *F.REMOTE_ADDR)
            laddr = F.get(r, *F.LOCAL_ADDR)
            rport = F.get(r, "RemotePort", "Rport", "ForeignPort", default="")
            lport = F.get(r, "LocalPort", "Lport", default="")
            state = F.get(r, *F.STATE)
            pid = F.get(r, *F.PID)
            nid = keys.netconn_id(asset, laddr, lport, raddr, rport)
            ents.append(_ent(nid, "netconn", f"{laddr}:{lport}->{raddr}:{rport}", asset,
                             run_id, f"{src}/{raddr}", anomaly=score_row(r),
                             state=state, raddr=raddr, laddr=laddr))
            if pid is not None and seen_proc.get(str(pid)):
                rels.append(Relationship(seen_proc[str(pid)], nid, "connected", sources=[MODULE]))
            kind = keys.classify_indicator(raddr)
            if kind:
                iid = keys.ioc_id(kind, raddr)
                ents.append(_ent(iid, "ioc", str(raddr), asset, run_id, f"{src}/{raddr}",
                                 anomaly=1, ioc_kind=kind))
                rels.append(Relationship(nid, iid, "connected", sources=[MODULE]))

    # ---- services ------------------------------------------------------
    for r in by_short.get("svcscan", []):
        name = F.get(r, "Name", "ServiceName", default=None)
        if not name:
            continue
        sid = keys.service_id(asset, name)
        ents.append(_ent(sid, "service", str(name), asset, run_id, f"svcscan/{name}",
                         anomaly=score_row(r), state=F.get(r, *F.STATE),
                         binary=F.get(r, "Binary", "BinaryPath", default=None)))
        pid = F.get(r, *F.PID)
        if pid is not None and seen_proc.get(str(pid)):
            rels.append(Relationship(seen_proc[str(pid)], sid, "ran_service", sources=[MODULE]))

    # ---- yara hits -> yarahit + matched --------------------------------
    for h in yara:
        rule = F.get(h, "rule", "Rule", "name", default=None)
        if not rule:
            continue
        pid = F.get(h, *F.PID)
        yid = keys.yarahit_id(asset, rule, pid or "")
        ents.append(_ent(yid, "yarahit", str(rule), asset, run_id, f"yara/{rule}",
                         anomaly=50, rule=rule, tags=F.get(h, "tags", default=None)))
        if pid is not None and seen_proc.get(str(pid)):
            rels.append(Relationship(yid, seen_proc[str(pid)], "matched", sources=[MODULE]))

    return ents, rels
