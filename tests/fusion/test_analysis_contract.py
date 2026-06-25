"""Grounded analyst pass — contract, grounding gate, additive-only invariant.
Deterministic tests for an LLM pass: mock the call_llm seam, no network.
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import llm_sim, calibrate  # noqa: E402
import tests.fusion.test_fusion as T  # noqa: E402
from tests.fusion.test_llm_contract import real_mode  # noqa: E402  (reuse ctx)


def test_analysis_sends_distilled_not_facts_and_threads_run_id():
    g = T.build()
    seen = {}

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        seen.update(prompt=prompt, system=system_prompt, run_id=run_id)
        return json.dumps({"incident_groups": [], "hypotheses": []})

    with real_mode(stub):
        llm_sim.analyze(g, window=T.WINDOW, min_severity="low", run_id="case_7")
    assert "findings" in seen["prompt"] and "case_id" in seen["prompt"], "distilled payload sent"
    assert "Key Indicators" not in seen["prompt"], "fact tables must NOT be sent"
    assert "ANALYST" in seen["system"].upper() or "incident_groups" in seen["system"]
    assert seen["run_id"] == "case_7"


def test_grounding_gate_rejects_ungrounded():
    g = T.build()
    real_fid = g.findings[0].id
    real_eid = next(iter(g.entities))

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        return json.dumps({
            "incident_groups": [{"name": "X", "finding_ids": [real_fid, "f_bogus"]}],
            "hypotheses": [
                {"title": "real", "entity_ids": [real_eid], "confidence": "low"},
                {"title": "hallucinated", "entity_ids": ["does:not:exist"], "confidence": "high"},
            ]})

    with real_mode(stub):
        a = llm_sim.analyze(g, window=T.WINDOW, min_severity="low", run_id="c")
    grp = a["incident_groups"][0]
    assert grp["finding_ids"] == [real_fid] and grp["ungrounded_refs_removed"] == ["f_bogus"]
    titles = [h["title"] for h in a["hypotheses"]]
    assert "real" in titles and "hallucinated" not in titles, "ungrounded hypothesis dropped"
    assert a["hypotheses"][0]["status"] == "for_analyst_verification"


def test_analyze_never_mutates_findings():
    g = T.build()
    before = [(f.id, f.severity, f.confidence) for f in g.findings]

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        return json.dumps({"incident_groups": [{"name": "Z", "finding_ids": [g.findings[0].id]}],
                           "hypotheses": []})

    with real_mode(stub):
        llm_sim.analyze(g, window=T.WINDOW, min_severity="low")
    after = [(f.id, f.severity, f.confidence) for f in g.findings]
    assert before == after, "the advisory pass must NOT mutate the deterministic findings"


def test_simulated_mode_is_deterministic_and_grounded():
    g = T.build()  # default mode = simulated (no _use_real)
    a = llm_sim.analyze(g, window=T.WINDOW, min_severity="low")
    assert a.get("simulated") is True
    valid = {f.id for f in g.findings}
    for grp in a["incident_groups"]:
        assert all(i in valid for i in grp["finding_ids"]), "simulated groups cite real findings"


def test_incident_grouping_over_real_attack_fixture():
    g = calibrate.fuse("attack")
    real = {f.id for f in g.findings}

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        return json.dumps({"incident_groups": [
            {"name": "Defender campaign", "finding_ids": list(real)}], "hypotheses": []})

    with real_mode(stub):
        a = llm_sim.analyze(g, run_id="c")
    assert a["incident_groups"][0]["finding_ids"], "groups real attack findings"
    assert all(i in real for i in a["incident_groups"][0]["finding_ids"])


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
