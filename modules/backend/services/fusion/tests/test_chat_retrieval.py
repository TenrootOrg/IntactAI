"""Subgraph chat retrieval — keeps chat tokens flat as cases grow, without
retrieving-away escalation-critical facts.
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import render, budget  # noqa: E402
import services.fusion.tests.test_fusion as T  # noqa: E402


def test_subgraph_contains_asked_ioc_and_all_high_findings():
    g = T.build()
    sub = render.chat_subgraph(g, "what about 5.100.251.10?", window=T.WINDOW, min_severity="low")
    labels = " ".join(e["label"] for e in sub["top_entities"])
    assert "5.100.251.10" in labels, "the asked-about IOC must be in the subgraph"
    # every >=high finding is always present (never retrieved away)
    from services.fusion import severity as sev
    high_titles = {f.title for f in g.findings if sev.at_least(f.severity, "high")}
    sub_titles = {f["title"] for f in sub["findings"]}
    assert high_titles <= sub_titles, "all >=high findings must be retained in chat subgraph"


def test_subgraph_smaller_than_full_distilled():
    g = T.build()
    full = render.distilled(g, window=T.WINDOW, min_severity="low",
                            max_entities=budget.REPORT_MAX_ENTITIES)
    sub = render.chat_subgraph(g, "tell me about the persistence", window=T.WINDOW,
                               min_severity="low", max_entities=budget.CHAT_MAX_ENTITIES)
    assert len(sub["top_entities"]) <= budget.CHAT_MAX_ENTITIES
    assert len(json.dumps(sub)) <= len(json.dumps(full)), "subgraph must not balloon past full distilled"
    assert sub.get("question_scope") is True


def test_subgraph_persistence_intent_pulls_service_findings():
    g = T.build()
    sub = render.chat_subgraph(g, "how do they persist?", window=T.WINDOW, min_severity="low")
    # if the case has a service/persistence finding it should be selected by intent
    persist = [f for f in g.findings
               if any(k in f.title.lower() for k in ("service", "persist", "task"))]
    if persist:
        sub_titles = {f["title"] for f in sub["findings"]}
        assert any(p.title in sub_titles for p in persist)


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
