"""Token-budget + facts/narrative-split assertions.

Guards the two free token levers: (1) the distilled payload sent to the LLM stays
within tier budgets, (2) deterministic fact tables (IOCs, MITRE, per-host bullets)
are NEVER in the LLM-narrated payload — so they can't be hallucinated and don't cost
tokens.
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import render, budget, calibrate  # noqa: E402
import services.fusion.tests.test_fusion as T  # noqa: E402


def test_distilled_within_report_budget_synthetic():
    g = T.build()
    p = render.distilled(g, window=T.WINDOW, min_severity="low",
                         max_entities=budget.REPORT_MAX_ENTITIES,
                         budget_chars=budget.REPORT_BUDGET_CHARS)
    assert not budget.over_budget(p, budget.REPORT_BUDGET_CHARS)


def test_distilled_within_report_budget_real_fixtures():
    for name in ("clean", "attack"):
        g = calibrate.fuse(name)
        p = render.distilled(g, max_entities=budget.REPORT_MAX_ENTITIES,
                             budget_chars=budget.REPORT_BUDGET_CHARS)
        assert not budget.over_budget(p, budget.REPORT_BUDGET_CHARS), name
        # the real distilled payload must be a small fraction of the raw rows
        raw = calibrate.load_fixture(name)["collected_data"]
        assert budget.approx_tokens(p) * 10 < budget.approx_tokens(raw), \
            f"{name}: distilled must be <<10% of raw tokens"


def test_fact_tables_absent_from_llm_payload():
    # The LLM only ever sees narrative_md + distilled(); IOC/MITRE/per-host tables
    # live only in facts_md.
    g = T.build()
    narr = render.narrative_md(g, window=T.WINDOW, min_severity="low")
    payload = narr + "\n" + json.dumps(render.distilled(g, window=T.WINDOW, min_severity="low"))
    for marker in ("## 4. Key Indicators", "## 5. MITRE", "| Indicator | Type |"):
        assert marker not in payload, f"fact-table marker leaked into LLM payload: {marker}"
    facts = render.facts_md(g, window=T.WINDOW, min_severity="low")
    assert "Key Indicators" in facts and "MITRE" in facts, "facts_md must hold the tables"


def test_budget_stepdown_is_bounded():
    g = T.build()
    full = render.distilled(g)
    tiny = render.distilled(g, max_entities=budget.REPORT_MAX_ENTITIES, budget_chars=300)
    # step-down only trims the ranked tail; findings/assets are always preserved
    assert len(tiny["top_entities"]) <= len(full["top_entities"])
    assert len(tiny["findings"]) == len(full["findings"])
    assert len(tiny["assets"]) == len(full["assets"])


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
