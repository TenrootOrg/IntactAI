"""Robustness — every mapper must survive malformed input and assemble must never
raise. Real Velociraptor/Vol3/cloud payloads are messy (None fields, wrong types,
nested junk, huge strings); a bad row must degrade to fewer entities, not a crash.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate, keys  # noqa: E402
from services.fusion.mappers import (  # noqa: E402
    map_memory, map_agentic, map_timesketch, map_cloud)

ASSET = keys.asset_id("C.fuzz")

# A spread of hostile inputs reused across mappers.
JUNK_ROWS = [
    {}, {"Pid": None}, {"Pid": "notanint", "Name": None},
    {"Name": {"nested": "dict"}}, {"CreateTime": 123456},
    {"x" * 200: "y" * 5000}, {"Level": object()},
    {"Raddr.IP": None}, {"Hash": {"SHA256": None}}, {"Authenticode": "notadict"},
]


def _safe(fn, *a, **k):
    ents, rels = fn(*a, **k)
    assert isinstance(ents, list) and isinstance(rels, list)
    # the contribution must assemble without raising
    correlate.assemble("fuzz", [(ents, rels)], ["r"])
    return ents, rels


def test_map_agentic_survives_junk():
    _safe(map_agentic, {"Generic.System.Pstree": JUNK_ROWS,
                        "Windows.Hayabusa.Rules": JUNK_ROWS,
                        "Windows.System.Services": JUNK_ROWS,
                        "Windows.Network.Netstat": JUNK_ROWS},
          run_id="r", hostnames={"C.fuzz": "H"})
    _safe(map_agentic, {}, run_id="r", hostnames=None)
    _safe(map_agentic, {"X": None, "Y": "notalist"}, run_id="r", hostnames={})


def test_map_memory_survives_junk():
    _safe(map_memory, {"host": None, "plugins": {"pslist": JUNK_ROWS, "malfind": JUNK_ROWS,
                                                 "netscan": JUNK_ROWS}, "yara": JUNK_ROWS},
          run_id="r", asset=ASSET, hostname=None)
    _safe(map_memory, {}, run_id="r", asset=ASSET)
    _safe(map_memory, {"plugins": None, "yara": None}, run_id="r", asset=ASSET)


def test_map_timesketch_survives_junk():
    _safe(map_timesketch, JUNK_ROWS, run_id="r", asset=ASSET, hostname=None)
    _safe(map_timesketch, [], run_id="r", asset=ASSET)
    _safe(map_timesketch, [None, "string", 42], run_id="r", asset=ASSET)



def test_map_cloud_survives_junk():
    _safe(map_cloud, JUNK_ROWS, run_id="r", provider="aws", account=None)
    _safe(map_cloud, [], run_id="r", provider="azure")
    _safe(map_cloud, [None, 3, "x"], run_id="r", provider="aws", account={"weird": 1})


def test_assemble_with_mixed_junk_contributions():
    contribs = [
        map_agentic({"Generic.System.Pstree": JUNK_ROWS}, run_id="a", hostnames={"C.fuzz": "H"}),
        map_memory({"plugins": {"pslist": JUNK_ROWS}}, run_id="m", asset=ASSET),
    ]
    g = correlate.assemble("mixed", contribs, ["a", "m"])
    assert isinstance(g.findings, list)  # produced a graph, didn't crash


def test_large_graph_pruning_keeps_signal():
    """A >2500-entity case must prune to the budget while keeping every finding +
    its entities + all high-value types, with the serialized blob bounded."""
    from services.fusion.schema import FusionGraph, Entity, Finding
    g = FusionGraph(case_id="big")
    g.upsert(Entity(id=ASSET, type="asset", label="BIGHOST",
                    attrs={"_assets": [ASSET]}))
    # 3000 low-signal process entities (noise)
    for i in range(3000):
        g.upsert(Entity(id=f"process:{ASSET}:{i}:t", type="process", label=f"p{i}",
                        attrs={"_assets": [ASSET], "pid": str(i)}, anomaly=i % 5))
    # a handful of high-value entities + one high-anomaly process a finding cites
    hv = []
    for t, lab in [("ioc", "5.6.7.8"), ("account", "corp\\admin"), ("vuln", "CVE-2024-1"),
                   ("yarahit", "REDLEAVES")]:
        e = Entity(id=f"{t}:{lab}", type=t, label=lab, attrs={"_assets": [ASSET]}, anomaly=1)
        g.upsert(e); hv.append(e.id)
    g.upsert(Entity(id="process:lead", type="process", label="evil", anomaly=100,
                    attrs={"_assets": [ASSET]}))
    g.add_finding(Finding(id="f1", title="Lead", severity="critical", confidence="high",
                          summary="x", entity_ids=["process:lead"], asset_ids=[ASSET]))

    p = g.pruned(max_entities=2500)
    assert len(p.entities) <= 2500 + 1, "pruned to budget (+asset)"
    assert len(p.findings) == len(g.findings), "all findings retained"
    assert ASSET in p.entities
    for eid in hv:
        assert eid in p.entities, "high-value type dropped"
    for f in p.findings:
        for eid in f.entity_ids:
            assert eid in p.entities, "finding-referenced entity dropped"
    import json
    assert len(json.dumps(p.to_dict())) < len(json.dumps(g.to_dict())), "blob bounded"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            f += 1; print(f"FAIL {fn.__name__}: {e!r}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
