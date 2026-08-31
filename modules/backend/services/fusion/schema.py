"""Lean typed entity/relationship/finding schema for the fusion layer.

Plain dataclasses, JSON-serialisable, persisted in the workflow ``details``
blob (no new DB, no graph engine). A case graph is hundreds to a few
thousand nodes.

Merge policy lives here (``FusionGraph.upsert``) so it stays dependency-
free; the natural-KEY generation + higher-level correlation that decides
*which* entities are the same real-world thing lives in
``services.fusion.correlate`` (which imports this module, never the
reverse).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


ENTITY_TYPES: tuple[str, ...] = (
    "asset", "process", "file", "netconn", "account", "service",
    "module", "regkey", "event", "yarahit", "vuln", "ioc",
)

REL_KINDS: tuple[str, ...] = (
    "spawned", "loaded", "connected", "executed", "ran_service",
    "matched", "accessed", "runs_software", "has_cve", "event_about",
    "authenticated",
)

SCHEMA_VERSION = 1


def _wider(a: Optional[str], b: Optional[str], *, want_min: bool) -> Optional[str]:
    """Min/max of two timestamps, ignoring blanks. Compares as INSTANTS via
    keys.to_utc_dt (F2 fix) — lexicographic string compare is WRONG when the two
    sides use different notations that sort differently from their real order
    (a trailing 'Z' vs a fractional second; a float-epoch vs an ISO date). The
    ORIGINAL string is returned so the stored format is preserved; only the
    ordering decision uses instants. Falls back to string compare if unparseable."""
    vals = [x for x in (a, b) if x]
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    try:
        from . import keys
        da, db = keys.to_utc_dt(a), keys.to_utc_dt(b)
        if da and db:
            return a if ((da <= db) == want_min) else b
    except Exception:
        pass
    return min(vals) if want_min else max(vals)


def _union(dst: list, src: list) -> None:
    """In-place order-preserving set-union of two lists of hashables."""
    seen = set(dst)
    for x in src:
        if x not in seen:
            dst.append(x)
            seen.add(x)


def _union_evidence(dst: list, src: list) -> None:
    """Order-preserving union of EvidenceRefs, keyed on (module, run_id, locator).

    Sources and flags were unioned and evidence was extend()ed unconditionally.
    That was invisible for as long as every fuse rebuilt the graph from nothing —
    the same entity was only ever built once per fuse.

    It stopped being invisible when fusion became incremental. "Fetch results"
    drops a run from fused_run_ids so the case treats it as new; on a case with
    OTHER members the additive path stays alive, seeds from the stored graph —
    which still holds that run's entities — and maps the run onto itself.
    Measured on a two-run case, re-fetching one of them three times:

        59,047 -> 59,412 -> 59,777 -> 60,142     (+365 every time)

    +365 is precisely that run's whole evidence trail, appended again. Entities,
    relationships and findings were all stable; only the evidence grew, which is
    the bulk of a stored graph and what the report cites per finding. An operator
    pressing the button twice would have seen a finding gain corroboration it
    never earned.
    """
    seen = {(e.module, e.run_id, e.locator) for e in dst}
    for e in src:
        k = (e.module, e.run_id, e.locator)
        if k not in seen:
            dst.append(e)
            seen.add(k)


@dataclass
class EvidenceRef:
    module: str          # "memory" | "agentic" | "timesketch" | "cve"
    run_id: str
    locator: str         # e.g. "PsScan/PID=7740", "Windows.Sys.Processes/row=42"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceRef":
        return cls(module=d.get("module", ""), run_id=d.get("run_id", ""),
                   locator=d.get("locator", ""))


@dataclass
class Entity:
    id: str                                          # deterministic natural key
    type: str                                        # one of ENTITY_TYPES
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)         # modules that observed it
    evidence: list[EvidenceRef] = field(default_factory=list)
    anomaly: int = 0                                 # memory._row_severity style score
    severity: str = "informational"                  # unified 5-level (see severity.py)
    first_seen: Optional[str] = None                 # ISO8601
    last_seen: Optional[str] = None
    flags: list[str] = field(default_factory=list)   # "pid_reused", "injected", ...

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [e.to_dict() if isinstance(e, EvidenceRef) else e
                         for e in self.evidence]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Entity":
        return cls(
            id=d["id"], type=d["type"], label=d.get("label", ""),
            attrs=dict(d.get("attrs") or {}),
            sources=list(d.get("sources") or []),
            evidence=[EvidenceRef.from_dict(e) for e in (d.get("evidence") or [])],
            anomaly=int(d.get("anomaly") or 0),
            severity=d.get("severity", "informational"),
            first_seen=d.get("first_seen"), last_seen=d.get("last_seen"),
            flags=list(d.get("flags") or []),
        )

    def assets(self) -> list[str]:
        """The asset id(s) this entity is scoped to (for cross-host detection)."""
        out = list(self.attrs.get("_assets") or [])
        if self.type == "asset":
            _union(out, [self.id])
        return out


@dataclass
class Relationship:
    src: str
    dst: str
    kind: str
    attrs: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    ts: Optional[str] = None

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.dst, self.kind)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Relationship":
        return cls(src=d["src"], dst=d["dst"], kind=d["kind"],
                   attrs=dict(d.get("attrs") or {}),
                   sources=list(d.get("sources") or []), ts=d.get("ts"))


@dataclass
class Finding:
    """The cross-module / cross-host finding representation missing today."""

    id: str
    title: str
    severity: str        # critical | high | medium | low | informational
    confidence: str      # high | medium | low
    summary: str
    entity_ids: list[str] = field(default_factory=list)
    asset_ids: list[str] = field(default_factory=list)       # which hosts (cross-host > 1)
    sources: list[str] = field(default_factory=list)         # corroborating modules
    evidence: list[EvidenceRef] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    ts: Optional[str] = None                                 # primary time (for ordering)
    kind: str = "single"                                     # "single" | "cross_host" | "derived"
    # Occurrence watermark: how many times this finding fired + the latest time it
    # did. A triage verdict (Known/False-positive) covers exactly this watermark;
    # when a later re-fuse yields MORE occurrences or a NEWER one, the verdict is
    # "stale" and the finding re-opens to Pending (see correlate._apply_dispositions
    # + store.get_timeline). occ_latest defaults to ts; occ_count defaults to 1.
    occ_count: int = 1
    occ_latest: Optional[str] = None

    def watermark(self) -> str:
        """Comparable signature of the occurrences this finding covers."""
        return f"{int(self.occ_count or 1)}|{self.occ_latest or self.ts or ''}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [e.to_dict() if isinstance(e, EvidenceRef) else e
                         for e in self.evidence]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d["id"], title=d.get("title", ""), severity=d.get("severity", ""),
            confidence=d.get("confidence", ""), summary=d.get("summary", ""),
            entity_ids=list(d.get("entity_ids") or []),
            asset_ids=list(d.get("asset_ids") or []),
            sources=list(d.get("sources") or []),
            evidence=[EvidenceRef.from_dict(e) for e in (d.get("evidence") or [])],
            mitre=list(d.get("mitre") or []), ts=d.get("ts"),
            kind=d.get("kind", "single"),
            occ_count=int(d.get("occ_count") or 1), occ_latest=d.get("occ_latest"),
        )


@dataclass
class FusionGraph:
    case_id: str
    entities: dict[str, Entity] = field(default_factory=dict)        # id -> Entity
    relationships: list[Relationship] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    run_ids: list[str] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION
    _rel_index: dict[tuple[str, str, str], int] = field(default_factory=dict, repr=False)
    _src_index: dict[str, list] = field(default_factory=dict, repr=False)
    _dst_index: dict[str, list] = field(default_factory=dict, repr=False)

    # -- entity merge (forensic-integrity preserving) ----------------------
    def upsert(self, e: Entity) -> Entity:
        cur = self.entities.get(e.id)
        if cur is None:
            self.entities[e.id] = e
            return e
        _union(cur.sources, e.sources)
        _union(cur.flags, e.flags)
        _union_evidence(cur.evidence, e.evidence)
        cur.anomaly = max(cur.anomaly, e.anomaly)
        cur.first_seen = _wider(cur.first_seen, e.first_seen, want_min=True)
        cur.last_seen = _wider(cur.last_seen, e.last_seen, want_min=False)
        if e.label and len(e.label) > len(cur.label or ""):
            cur.label = e.label
        # cross-host accounting: union the asset list
        cur_assets = list(cur.attrs.get("_assets") or [])
        _union(cur_assets, e.attrs.get("_assets") or [])
        for k, v in e.attrs.items():
            if k == "_assets":
                continue
            if v in (None, "", []):
                continue
            if k in cur.attrs and cur.attrs[k] != v:
                # FORENSIC INTEGRITY: conflicting values from different
                # observations are kept with provenance, never overwritten.
                obs = cur.attrs.setdefault(f"{k}_observations", [])
                vals = {o.get("value") for o in obs if isinstance(o, dict)}
                if cur.attrs[k] not in vals:
                    obs.append({"value": cur.attrs[k], "source": "prior"})
                if v not in vals:
                    obs.append({"value": v, "source": (e.sources[0] if e.sources else "?")})
                _union(cur.flags, ["conflict"])
            else:
                cur.attrs[k] = v
        if cur_assets:
            cur.attrs["_assets"] = cur_assets
        return cur

    # -- relationship dedup ------------------------------------------------
    def relate(self, r: Relationship) -> Relationship:
        k = r.key()
        idx = self._rel_index.get(k)
        if idx is None:
            self._rel_index[k] = len(self.relationships)
            self.relationships.append(r)
            self._src_index.setdefault(r.src, []).append(r)
            self._dst_index.setdefault(r.dst, []).append(r)
            return r
        cur = self.relationships[idx]
        _union(cur.sources, r.sources)
        for kk, vv in r.attrs.items():
            if vv not in (None, "", []):
                cur.attrs[kk] = vv
        if r.ts and (cur.ts is None or r.ts < cur.ts):
            cur.ts = r.ts
        return cur

    def add_finding(self, f: Finding) -> None:
        self.findings.append(f)

    def note_run(self, run_id: str) -> None:
        if run_id and run_id not in self.run_ids:
            self.run_ids.append(run_id)

    # -- queries -----------------------------------------------------------
    def by_type(self, etype: str) -> list[Entity]:
        return [e for e in self.entities.values() if e.type == etype]

    def out_edges(self, eid: str) -> list[Relationship]:
        return self._src_index.get(eid, [])

    def in_edges(self, eid: str) -> list[Relationship]:
        return self._dst_index.get(eid, [])

    def rebuild_indexes(self) -> None:
        self._rel_index, self._src_index, self._dst_index = {}, {}, {}
        for i, r in enumerate(self.relationships):
            self._rel_index[r.key()] = i
            self._src_index.setdefault(r.src, []).append(r)
            self._dst_index.setdefault(r.dst, []).append(r)

    def pruned(self, max_entities: int = 2500) -> "FusionGraph":
        """A storage-bounded copy: keep all findings + their entities + the
        high-value types (assets/IOCs/accounts/vulns/yara), fill the rest of
        the budget with top-anomaly entities. Keeps the SQLite blob small on
        big multi-host cases without losing the signal."""
        if len(self.entities) <= max_entities:
            return self
        keep: set[str] = set()
        for e in self.entities.values():
            if e.type in ("asset", "ioc", "account", "vuln", "yarahit"):
                keep.add(e.id)
        for f in self.findings:
            keep.update(f.entity_ids)
        for e in sorted((e for e in self.entities.values() if e.id not in keep),
                        key=lambda e: -e.anomaly):
            if len(keep) >= max_entities:
                break
            keep.add(e.id)
        g = FusionGraph(case_id=self.case_id, schema_version=self.schema_version)
        g.run_ids = list(self.run_ids)
        for eid in keep:
            if eid in self.entities:
                g.upsert(self.entities[eid])
        for r in self.relationships:
            if r.src in keep and r.dst in keep:
                g.relate(r)
        g.findings = list(self.findings)
        return g

    # -- (de)serialisation -------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "schema_version": self.schema_version,
            "entities": {eid: e.to_dict() for eid, e in self.entities.items()},
            "relationships": [r.to_dict() for r in self.relationships],
            "findings": [f.to_dict() for f in self.findings],
            "run_ids": list(self.run_ids),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FusionGraph":
        g = cls(case_id=d.get("case_id", ""))
        g.schema_version = int(d.get("schema_version") or SCHEMA_VERSION)
        for eid, ed in (d.get("entities") or {}).items():
            g.entities[eid] = Entity.from_dict(ed)
        for rd in (d.get("relationships") or []):
            g.relate(Relationship.from_dict(rd))
        for fd in (d.get("findings") or []):
            g.findings.append(Finding.from_dict(fd))
        g.run_ids = list(d.get("run_ids") or [])
        return g
