"""CVE mapper — NVD findings -> vuln entities + asset has_cve edges.

Accepts either a flat list of rows (Hostname/Product/Version/CVE/CVSS) or the
cve_scan ``findings.json`` shape ({by_severity:{...}, by_host:{host:[...]}}).
"""

from __future__ import annotations

import re

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..severity import from_cvss
from . import fieldspec as F

MODULE = "cve"
_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _rows(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        bh = payload.get("by_host")
        if isinstance(bh, dict):
            out = []
            for host, items in bh.items():
                for it in (items or []):
                    it = dict(it)
                    it.setdefault("Hostname", host)
                    out.append(it)
            return out
        for k in ("findings", "rows", "results"):
            if isinstance(payload.get(k), list):
                return payload[k]
    return []


def map_cve(payload, *, run_id: str) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    for i, r in enumerate(_rows(payload)):
        if not isinstance(r, dict):
            continue
        host = F.get(r, *F.HOSTNAME) or r.get("Hostname") or r.get("host")
        asset = keys.asset_id_from_host(host) if host else "asset:endpoint:unknown"
        cve = F.get(r, "CVE", "cve_id", "CVE_ID", "cve", default=None)
        if not cve:
            link = F.get(r, "CVE_Link", "cve_url", "url", default="")
            m = _CVE.search(str(link))
            cve = m.group(0) if m else None
        if not cve:
            continue
        cvss = F.get(r, "CVSS_Score", "CVSS", "cvss", "cvss_score", "score", default=None)
        product = F.get(r, "Product", "Name", "product", default=None)
        version = F.get(r, "Version", "version", default=None)
        vid = keys.vuln_id(cve)
        ents.append(Entity(
            id=vid, type="vuln", label=cve.upper(),
            attrs={"_assets": [asset], "cvss": cvss, "product": product, "version": version,
                   "status": F.get(r, "Status", "status", default=None)},
            sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, f"cve/{cve}")],
            severity=from_cvss(cvss)))
        ents.append(Entity(
            id=asset, type="asset", label=str(host or asset.split(":")[-1]),
            attrs={"hostname": host, "kind": "endpoint", "_assets": [asset]},
            sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))
        rels.append(Relationship(asset, vid, "has_cve", sources=[MODULE],
                                 attrs={"product": product, "version": version}))
    return ents, rels
