"""Cross-case KB — enrichment-only, degrades silently without ES.

Proves (a) when ES is down everything no-ops without raising, (b) a prior sighting
raises a finding's confidence + annotates it, and (c) the KB never CREATES findings.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import kb  # noqa: E402
import tests.fusion.test_fusion as T  # noqa: E402


def test_degrades_silently_without_es():
    """Force ES absent rather than assuming it.

    This used to open with "Real environment here has no ES" and simply call
    through. On any box with ELK enabled that premise is false: `kb._es()`
    returns a live client, `index_case_entities` indexes for real and returns a
    non-zero count, and the test fails while asserting nothing about the
    degrade path it is named for.

    Worse, it was WRITING. Every run put this fixture's IOCs, accounts and YARA
    hits into the production `intact_fusion_entities` index under case_id "c",
    where `enrich()` then surfaces them as "prior sightings" in unrelated real
    cases. Four such documents were found and removed. The fusion runner's
    INTACT_STORAGE_BASE isolation only redirects SQLite, so ES has to be shut
    off here, in the test.
    """
    saved = kb._es
    kb._es = lambda: None
    try:
        g = T.build()
        n_findings = len(g.findings)
        assert kb.index_case_entities("c", g) == 0
        assert kb.lookup_sightings({"5.100.251.10"}) == {}
        assert kb.enrich(g, current_case_id="c") == 0
        assert len(g.findings) == n_findings, "KB must never create or drop findings"
    finally:
        kb._es = saved


def test_enrichment_raises_confidence_on_prior_sighting():
    g = T.build()
    # pick a finding that cites an IOC/account/yarahit entity
    target = None
    for f in g.findings:
        for eid in f.entity_ids:
            e = g.entities.get(eid)
            if e and e.type in kb.KB_TYPES and e.label:
                target, label = f, e.label
                break
        if target:
            break
    assert target, "fixture should have a finding citing an IOC/account"

    saved = kb.lookup_sightings
    kb.lookup_sightings = lambda labels: {label: [{"case_id": "OLD-CASE", "hosts": ["DC01"]}]}
    try:
        n_before = len(g.findings)
        enriched = kb.enrich(g, current_case_id="NEW-CASE")
    finally:
        kb.lookup_sightings = saved
    assert enriched >= 1
    assert target.confidence == "high"
    assert "cross-case" in target.summary
    assert len(g.findings) == n_before, "enrichment must not create findings"


def test_prior_sighting_in_same_case_is_ignored():
    g = T.build()
    saved = kb.lookup_sightings
    # only sighting is the CURRENT case -> not a prior sighting -> no enrichment
    kb.lookup_sightings = lambda labels: {lbl: [{"case_id": "SAME"}] for lbl in labels}
    try:
        enriched = kb.enrich(g, current_case_id="SAME")
    finally:
        kb.lookup_sightings = saved
    assert enriched == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
