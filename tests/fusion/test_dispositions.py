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


# ---------------------------------------------------------------------------
# The operators here are native Hebrew speakers writing imperfect English, so
# the chat must survive: missing question marks, non-native word order,
# transliterated Hebrew, Hebrew script, and — above all — descriptions of an
# ATTACK that happen to contain words the triage keywords treat as benign
# ("backup", "expected", "legitimate"). A keyword matcher cannot be made
# correct for that input; these tests therefore pin the property that MATTERS:
# a message can never mutate the case on its own. Triage is propose-then-apply.
# ---------------------------------------------------------------------------

def _graph_backup_finding():
    g = FusionGraph(case_id="c")
    g.upsert(Entity(id="a1", type="asset", label="SRV-BACKUP", attrs={"_assets": ["a1"]}))
    g.upsert(Entity(id="acc", type="account", label="corp\\kobia", attrs={"_assets": ["a1"]}))
    g.add_finding(Finding(id="f_bk", title="Veeam backup agent spawned encoded PowerShell on SRV-BACKUP",
                          severity="high", confidence="medium", summary="x",
                          entity_ids=["acc"], asset_ids=["a1"], mitre=[]))
    return g


BROKEN_ENGLISH_AND_HEBREW = [
    # questions without a question mark / non-native word order
    "who the most malicious user", "what kobia did", "kobia did what",
    "the most malicious user who", "why powershell is malicious",
    "what happen in the backup server", "the backup server what happened",
    "explain me the scriptblock", "i want to know about malicious powershell",
    "give me the malicious findings", "malicious user list",
    # descriptions of an attack that contain benign-flavoured words
    "the backup server was compromised", "ransomware deleted the backup catalog",
    "attacker used the backup account", "the backup job is the initial access vector",
    "this is not expected behaviour", "the legitimate account was stolen",
    # Hebrew script
    "מי המשתמש הכי זדוני", "מה קרה בשרת הגיבוי", "תסביר לי על הפאוורשל",
    # transliterated / mixed Hebrew-English
    "ma kara ba backup server", "mi ze kobia", "the backup shel hamachshev nifga",
]


def test_no_message_ever_applies_a_disposition_by_itself():
    """THE load-bearing property. detect_disposition may still guess wrong on
    broken English — it is a keyword matcher — but chat_case treats its output
    as a PROPOSAL only, so nothing here can suppress a finding without an
    explicit yes on the following turn."""
    from services.fusion import store
    src = _code_of(store.chat_case)
    # the proposal must never be applied in the same turn it is detected
    detect_at = src.index("detect_disposition")
    applied_after_detect = src.find("set_disposition(", detect_at)
    assert applied_after_detect == -1, \
        "chat_case applies a disposition in the same turn it detects one — " \
        "a misread message would silently mutate the case"
    # and the model must be reached regardless of what the matcher decided
    assert "llm_sim.chat(" in src, "chat_case no longer always calls the model"


def _code_of(fn) -> str:
    """Source of `fn` with comments stripped — a rule about what the CODE does
    must not be satisfied or broken by prose in a comment."""
    import inspect
    out = []
    for ln in inspect.getsource(fn).split("\n"):
        stripped = ln.strip()
        if stripped.startswith("#"):
            continue
        out.append(ln.split("  #")[0])
    return "\n".join(out)


def test_broken_english_and_hebrew_never_blocks_the_answer():
    """A guess must never REPLACE the operator's answer. Before this, a matched
    message returned a canned reply and the model was never called, so the same
    wrong sentence came back no matter how the question was rephrased."""
    from services.fusion import store
    src = _code_of(store.chat_case)
    assert "Noted" not in src, "the canned triage reply still short-circuits the chat"


def test_confirmation_vocabulary_covers_hebrew():
    assert llm_sim.is_affirmative("yes") and llm_sim.is_affirmative("כן")
    assert llm_sim.is_affirmative("ok") and llm_sim.is_affirmative("confirm")
    assert llm_sim.is_negative("no") and llm_sim.is_negative("לא")
    # a long sentence merely containing 'ok' must not confirm anything
    assert not llm_sim.is_affirmative(
        "ok so what happened on the backup server and who did it")
    assert not llm_sim.is_affirmative("")


def test_attack_descriptions_do_not_read_as_confirmation():
    """The confirm step is the only thing standing between a wrong guess and a
    mutated case, so it must not fire on ordinary prose."""
    for msg in BROKEN_ENGLISH_AND_HEBREW:
        assert not llm_sim.is_affirmative(msg), f"treated as a yes: {msg!r}"
