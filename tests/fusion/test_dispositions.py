"""Interactive FP-triage / operator dispositions — the human-in-the-loop that kills the
benign IT/employee false-positive long tail.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate, llm_sim, severity as sev  # noqa: E402
from services.fusion.schema import FusionGraph, Entity, Finding  # noqa: E402


def _graph_with_finding(severity="high", fid="f_psexec", eid="account:domain:corp\\admin"):
    g = FusionGraph(case_id="c")
    g.upsert(Entity(id="asset:endpoint:C.a", type="asset", label="DC01",
                    attrs={"_assets": ["asset:endpoint:C.a"]}))
    g.upsert(Entity(id=eid, type="account", label="corp\\admin",
                    attrs={"_assets": ["asset:endpoint:C.a"]}))
    g.add_finding(Finding(id=fid, title="Suspicious PsExec on DC01", severity=severity,
                          confidence="medium", summary="PsExec service install on DC01.",
                          entity_ids=[eid], asset_ids=["asset:endpoint:C.a"], mitre=["T1569"]))
    return g


def test_benign_disposition_downranks_and_annotates():
    g = _graph_with_finding("high")
    correlate._apply_dispositions(g, [{"target": "f_psexec", "verdict": "benign",
                                       "attribution": "it_admin", "reason": "scheduled patching"}])
    f = g.findings[0]
    assert f.severity == "informational" and f.kind == "dispositioned"
    assert "it_admin" in f.summary and "scheduled patching" in f.summary


def test_disposition_by_entity_id_applies():
    g = _graph_with_finding("high")
    correlate._apply_dispositions(g, [{"target": "account:domain:corp\\admin",
                                       "verdict": "benign", "attribution": "it_admin"}])
    assert g.findings[0].severity == "informational"  # matched via cited entity


def test_critical_never_silently_suppressed():
    g = _graph_with_finding("critical")
    correlate._apply_dispositions(g, [{"target": "f_psexec", "verdict": "benign",
                                       "attribution": "it_admin"}])
    f = g.findings[0]
    assert f.severity == "critical", "≥critical must NOT be downgraded by a disposition"
    assert "surfaced anyway" in f.summary


def test_malicious_disposition_raises_confidence():
    g = _graph_with_finding("medium")
    correlate._apply_dispositions(g, [{"target": "f_psexec", "verdict": "malicious",
                                       "reason": "operator confirmed"}])
    assert g.findings[0].confidence == "high"


def test_chat_detects_grounded_disposition_and_ignores_ungrounded():
    g = _graph_with_finding("high")
    d = llm_sim.detect_disposition(g, "the PsExec on DC01 was our IT admin doing patching")
    assert d and d["verdict"] == "benign" and d["attribution"] == "it_admin"
    assert d["target"] in ("f_psexec", "account:domain:corp\\admin")
    # an attribution about something NOT in the graph must not ground
    assert llm_sim.detect_disposition(g, "the mimikatz on FS99 was benign") is None


def test_chat_detects_environment_scope():
    g = _graph_with_finding("high")
    d = llm_sim.detect_disposition(g, "PsExec is always our IT — benign on every host")
    assert d and d["scope"] == "environment"


def test_chat_surfaces_dispositions():
    g = _graph_with_finding("high")
    # deterministic fallback path (a live LLM would phrase this its own way)
    from tests.fusion.test_fusion import force_sim
    with force_sim():
        out = llm_sim.chat(g, "what have I marked benign?",
                           dispositions=[{"target": "f_psexec", "verdict": "benign",
                                          "attribution": "it_admin", "scope": "case"}])
    assert "f_psexec" in out and "it_admin" in out


def test_disposition_does_not_change_calibration():
    # no dispositions on the fixtures -> macro-F1 must be untouched
    from services.fusion import calibrate
    res = calibrate.evaluate(verbose=False)
    assert res["clean"]["precision"] == 1.0 and res["attack"]["recall"] == 1.0


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


# ---------------------------------------------------------------------------
# Regression: a QUESTION must never be read as a triage command.
# ---------------------------------------------------------------------------
# 2026-07-26 — "who is the most malicious user" silently marked a finding benign,
# suppressed it and re-fused the case; the operator never saw a model answer,
# only a canned "Noted — marked X as benign". Two faults combined: "is the" was a
# benign-verdict keyword, and grounding anchored on the word "malicious" from the
# question itself against a finding titled "SIGMA: Malicious PowerShell ...", so
# the word that triggered the verdict also chose its target.
#
# The original 8 tests only asserted that real attributions ARE detected. Nothing
# asserted what must NOT be. In a case chat the overwhelming majority of messages
# are questions, so that is the input class most worth pinning down.

def _graph_with_malicious_titled_finding():
    """A finding whose TITLE contains the verdict words, which is what made the
    question ground to it. Deliberately mirrors a real Sigma rule name."""
    g = FusionGraph(case_id="c")
    eid = "account:domain:corp\\kobia"
    g.upsert(Entity(id="asset:endpoint:C.b", type="asset", label="WS1",
                    attrs={"_assets": ["asset:endpoint:C.b"]}))
    g.upsert(Entity(id=eid, type="account", label="corp\\kobia",
                    attrs={"_assets": ["asset:endpoint:C.b"]}))
    g.add_finding(Finding(id="f_ps", title="SIGMA: Malicious PowerShell Commandlets - ScriptBlock on WS1",
                          severity="high", confidence="medium",
                          summary="Encoded PowerShell.", entity_ids=[eid],
                          asset_ids=["asset:endpoint:C.b"], mitre=["T1059"]))
    return g


def test_questions_never_produce_a_disposition():
    g = _graph_with_malicious_titled_finding()
    questions = [
        "who is the most malicious user",          # the exact message that broke it
        "what is the most malicious user",
        '"what is the most malicious use',         # stray leading quote, as typed
        "which host is the worst?",
        "who else ?",
        "show me the malicious powershell finding",
        "what was the initial access vector",
        "is there anything malicious on WS1?",
        "explain the powershell scriptblock alert",
        "how many findings are benign",            # names a verdict word outright
    ]
    for q in questions:
        assert llm_sim.detect_disposition(g, q) is None, \
            f"question was read as a triage command: {q!r}"


def test_verdict_words_alone_cannot_ground_a_disposition():
    """The word that triggers a verdict must not also be the anchor that grounds
    it — otherwise any sentence mentioning 'malicious' targets every finding with
    'Malicious' in its title."""
    g = _graph_with_malicious_titled_finding()
    # a statement (not a question) whose ONLY overlap with the title is 'malicious'
    assert llm_sim.detect_disposition(g, "nothing here is malicious, ignore it") is None


def test_real_attributions_still_detected():
    """The guard must not cost the feature its purpose."""
    g = _graph_with_malicious_titled_finding()
    d = llm_sim.detect_disposition(g, "the powershell scriptblock alert is benign, it is our admin")
    assert d and d["verdict"] == "benign", "a genuine triage command stopped being detected"
    assert "scriptblock" in (d["label"] or "").lower() or "powershell" in (d["label"] or "").lower()
