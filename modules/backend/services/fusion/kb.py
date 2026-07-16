"""Cross-case knowledge base — index case entities into Elasticsearch and enrich
new cases with PRIOR sightings of the same IOC/account/hash/yarahit.

Reuses the already-running ES (no new infra). STRICTLY enrichment: it can only
RAISE confidence on an existing finding, never create one — so it can't add false
positives. Degrades silently to "no prior sightings" whenever ES is unavailable
(airgapped installs, ELK module off), so the KB is never a dependency.
"""

from __future__ import annotations

INDEX = "intact_fusion_entities"
KB_TYPES = ("ioc", "account", "yarahit")

_client = None
_failed_at = None
_FAILURE_COOLDOWN_S = 60.0


def _es():
    """Lazy ES client; caches a failure for a cooldown window so we don't
    reconnect on every fuse — but retries after it, rather than latching
    permanently. Previously a single transient failure (e.g. ES still in its
    ~60s cold-start window when the first fuse ran) disabled cross-case
    enrichment for the rest of the backend process's lifetime, even once ES
    became healthy."""
    global _client, _failed_at
    import time as _time
    if _client is not None:
        return _client
    if _failed_at is not None and (_time.time() - _failed_at) < _FAILURE_COOLDOWN_S:
        return None
    try:
        from config import is_module_enabled
        if not is_module_enabled('elk'):
            _failed_at = _time.time()
            return None
    except Exception:
        pass
    try:
        from elasticsearch import Elasticsearch
        c = Elasticsearch(["http://elasticsearch:9200"], request_timeout=3, max_retries=1)
        if not c.ping():
            _failed_at = _time.time()
            return None
        if not c.indices.exists(index=INDEX):
            c.indices.create(index=INDEX, body={"mappings": {"properties": {
                "case_id": {"type": "keyword"}, "type": {"type": "keyword"},
                "label": {"type": "keyword"}, "severity": {"type": "keyword"},
                "hosts": {"type": "keyword"}, "sources": {"type": "keyword"},
                "first_seen": {"type": "keyword"}}}})
        _client = c
        _failed_at = None
        return c
    except Exception:
        _failed_at = _time.time()
        return None


def index_case_entities(case_id, graph) -> int:
    """Persist this case's IOC/account/yarahit entities for future cross-case lookup.
    Best-effort; returns count indexed (0 if ES down)."""
    es = _es()
    if not es:
        return 0
    from .correlate import _assets_of, _host_label
    import hashlib
    n = 0
    for e in graph.entities.values():
        if e.type not in KB_TYPES or not e.label:
            continue
        try:
            # A plain f"{case_id}:{e.id}" string-concat can collide across
            # cases if either id contains a colon (entity ids frequently do —
            # e.g. "process:client_id:pid:createtime" style composite keys).
            # Hash the pair instead of concatenating them raw.
            doc_id = hashlib.sha1(f"{case_id}\x00{e.id}".encode()).hexdigest()
            es.index(index=INDEX, id=doc_id, document={
                "case_id": case_id, "type": e.type, "label": e.label,
                "severity": e.severity,
                "hosts": [_host_label(graph, a) for a in _assets_of(e)],
                "sources": list(e.sources), "first_seen": e.first_seen or ""})
            n += 1
        except Exception:
            pass
    return n


def lookup_sightings(labels) -> dict:
    """{label: [prior-sighting docs]} for labels present in the KB. Empty if ES down."""
    es = _es()
    if not es:
        return {}
    out: dict = {}
    for label in {x for x in labels if x}:
        try:
            r = es.search(index=INDEX, query={"term": {"label": label}}, size=10)
            hits = [h["_source"] for h in r.get("hits", {}).get("hits", [])]
            if hits:
                out[label] = hits
        except Exception:
            pass
    return out


def enrich(graph, *, current_case_id=None) -> int:
    """Raise confidence on findings whose IOC/account/hash was seen in a PRIOR case.
    Enrichment only — never creates findings. Returns count enriched (0 if ES down)."""
    labels = {e.label for e in graph.entities.values()
              if e.type in KB_TYPES and e.label}
    sightings = lookup_sightings(labels)
    if not sightings:
        return 0
    n = 0
    for f in graph.findings:
        priors = []
        for eid in f.entity_ids:
            e = graph.entities.get(eid)
            if e and e.label in sightings:
                priors += [s for s in sightings[e.label] if s.get("case_id") != current_case_id]
        if priors:
            cases = sorted({s.get("case_id") for s in priors})
            if f.confidence != "high":
                f.confidence = "high"
            f.summary += f" [cross-case: this indicator was seen in {len(cases)} prior case(s)]"
            n += 1
    return n
