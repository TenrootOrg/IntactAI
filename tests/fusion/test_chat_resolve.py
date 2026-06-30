"""Chat entity resolution — partial/case-insensitive host matching with safety.

'desktop-566' must resolve to DESKTOP-566AT85; an ambiguous name must ASK; a
typo must offer 'did you mean'; a partial hash/IP must NOT match; and a resolved
host's full context must get pinned. Guards services/fusion/resolve.py + the
chat() wiring in llm_sim.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import resolve as R, llm_sim          # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402


def _asset(label, attrs=None):
    return Entity(id=f"asset:endpoint:C.{label.lower()}", type="asset", label=label, attrs=attrs or {})


def _acct(label):
    return Entity(id=f"account:{label.lower()}", type="account", label=label)


def _ioc(label):
    return Entity(id=f"ioc:{label}", type="ioc", label=label)


def _finding(fid, severity, asset_ids):
    return Finding(id=fid, title=fid, severity=severity, confidence="high",
                   summary="s", asset_ids=list(asset_ids))


def _graph(*entities):
    g = FusionGraph("c:test")
    for e in entities:
        g.upsert(e)
    return g


# -- resolve() ---------------------------------------------------------------
def test_partial_unique_host_resolves():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("ALDC02"))
    r = R.resolve(g, "why is desktop-566 the most malicious host?")
    assert [e.label for e in r["resolved"]] == ["DESKTOP-566AT85"]
    assert not r["ambiguous"] and not r["typos"]


def test_exact_and_case_insensitive():
    g = _graph(_asset("DESKTOP-566AT85"))
    assert R.resolve(g, "what happened on desktop-566at85")["resolved"][0].label == "DESKTOP-566AT85"


def test_ambiguous_partial_asks_not_guesses():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    r = R.resolve(g, "why is desktop-566 malicious")
    assert not r["resolved"]
    assert len(r["ambiguous"]) == 1 and len(r["ambiguous"][0]["candidates"]) == 2
    msg = R.clarify_text(r)
    assert "matches multiple identities" in msg and "DESKTOP-566AT85" in msg and "DESKTOP-566B12" in msg


def test_pure_numeric_token_never_pins():
    g = _graph(_asset("DESKTOP-566AT85"))
    assert not R.resolve(g, "show 566")["resolved"]


def test_account_partial_resolves():
    g = _graph(_acct("adatumlab\\almogs"))
    assert R.resolve(g, "what did almog do")["resolved"][0].label == "adatumlab\\almogs"


def test_ioc_needs_exact_partial_hash_is_ignored():
    g = _graph(_ioc("842737b5c36f624c9a1f"))
    assert R.resolve(g, "is 842737b5c36f624c9a1f bad")["resolved"], "full hash must match"
    r = R.resolve(g, "is 842737 bad")
    assert not r["resolved"] and not r["typos"], "a partial hash must never match an IOC"


def test_typo_offers_did_you_mean():
    g = _graph(_asset("DESKTOP-566AT85"))
    r = R.resolve(g, "anything on desktop-556?")
    assert not r["resolved"] and len(r["typos"]) == 1
    assert "did you mean" in R.clarify_text(r).lower()


def test_alias_client_id_resolves():
    g = _graph(_asset("DESKTOP-566AT85"))
    # the entity id is asset:endpoint:C.desktop-566at85 -> client-id alias
    assert R.resolve(g, "what about c.desktop-566at85")["resolved"][0].label == "DESKTOP-566AT85"


def test_no_entity_named_resolves_nothing():
    g = _graph(_asset("DESKTOP-566AT85"))
    r = R.resolve(g, "which hosts are critical")
    assert not r["resolved"] and not r["ambiguous"] and not r["typos"]


# -- follow-up ('both' / pick) ----------------------------------------------
def test_followup_both_pins_all_candidates():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    clar = R.clarify_text(R.resolve(g, "why is desktop-566 malicious"))
    hist = [{"role": "assistant", "content": clar}]
    assert {e.label for e in R.resolve_followup(g, "both", hist)} == {"DESKTOP-566AT85", "DESKTOP-566B12"}
    assert [e.label for e in R.resolve_followup(g, "DESKTOP-566B12", hist)] == ["DESKTOP-566B12"]


def test_followup_only_fires_after_a_clarify_prompt():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    # a NORMAL prior answer (no clarify marker) must NOT turn 'both' into pin-all
    hist = [{"role": "assistant", "content": "Here is a summary of DESKTOP-566AT85 and DESKTOP-566B12."}]
    assert R.resolve_followup(g, "both", hist) is None


# -- chat() wiring -----------------------------------------------------------
def test_chat_asks_on_ambiguity():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    out = llm_sim.chat(g, "why is desktop-566 malicious")
    assert "matches multiple identities" in out


def test_chat_pins_resolved_host_in_fallback():
    g = _graph(_asset("DESKTOP-566AT85"))
    g.add_finding(_finding("Code injection — powershell_ise", "high", ["asset:endpoint:C.desktop-566at85"]))
    out = llm_sim.chat(g, "why is desktop-566 bad?")
    assert out.startswith("On DESKTOP-566AT85:"), out[:60]
    assert "Code injection" in out


# -- collision: a host + its OWN local accounts must collapse to the host --------
def _local_acct(label, host_id):
    return Entity(id=f"account:{label.lower()}", type="account", label=label,
                  attrs={"_assets": [host_id]})


def test_host_and_its_local_account_collapse_to_host():
    host = _asset("DESKTOP-566AT85")
    acct = _local_acct("DESKTOP-566AT85\\vagrant", host.id)   # local user on the SAME box
    g = _graph(host, acct)
    r = R.resolve(g, "why is desktop-566 the most malicious host?")
    assert [e.label for e in r["resolved"]] == ["DESKTOP-566AT85"], "must collapse to the host"
    assert not r["ambiguous"], "a host + its own local account is NOT ambiguous"


def test_collapse_does_not_hide_real_cross_machine_ambiguity():
    # a token hitting two DIFFERENT machines stays ambiguous
    a = _asset("DESKTOP-566AT85")
    b = _asset("DESKTOP-566B12")
    assert R._collapse_same_host([a, b], _graph(a, b)) is None
    # a domain account spanning two hosts + one of those hosts -> >1 anchor -> no collapse
    host = _asset("WS-01")
    dom = Entity(id="account:corp\\svc", type="account", label="corp\\svc",
                 attrs={"_assets": [host.id, "asset:endpoint:C.ws-02"]})
    assert R._collapse_same_host([host, dom], _graph(host, dom)) is None


# -- never-stuck guarantees -----------------------------------------------------
def test_no_match_proceeds_never_clarifies():
    g = _graph(_asset("DESKTOP-566AT85"), _acct("adatumlab\\almogs"))
    for q in ["", "   ", "hello", "what is going on", "summarize the case",
              "show me the worst host", "what about nonexistent-999", "asdfqwer",
              "the dc", "566"]:
        r = R.resolve(g, q)
        # nothing falsely resolved, and NO clarify on a question that names no entity
        assert R.clarify_text(r) is None, f"{q!r} should not block the user"


def test_chat_always_returns_a_usable_string():
    g = _graph(_asset("DESKTOP-566AT85"))
    g.add_finding(_finding("F1", "high", ["asset:endpoint:C.desktop-566at85"]))
    for q in ["", "hello", "what is going on", "summarize", "asdfqwer", "why desktop-566"]:
        out = llm_sim.chat(g, q)
        assert isinstance(out, str) and out.strip(), f"empty answer for {q!r}"


def test_ambiguity_is_always_escapable():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    r = R.resolve(g, "desktop-566 status")
    assert r["ambiguous"]                                   # blocked this turn...
    clar = R.clarify_text(r)
    hist = [{"role": "assistant", "content": clar}]
    assert R.resolve_followup(g, "both", hist)              # ...escape via 'both'
    assert R.resolve_followup(g, "DESKTOP-566AT85", hist)   # ...or by full name
    # ...or just ask a different question entirely (not a follow-up -> normal resolve)
    assert R.resolve_followup(g, "tell me about desktop-566at85", hist)


# -- bypass flag (escape hatch) -------------------------------------------------
def test_bypass_flag_disables_clarify():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    g.add_finding(_finding("F", "high", ["asset:endpoint:C.desktop-566at85"]))
    orig = llm_sim._agentic_cfg
    llm_sim._agentic_cfg = lambda: {"chat_send_full_context": True}
    try:
        out = llm_sim.chat(g, "why is desktop-566 malicious")   # ambiguous normally
        assert "matches multiple identities" not in out, "bypass must not clarify"
        assert isinstance(out, str) and out.strip()
    finally:
        llm_sim._agentic_cfg = orig


def test_per_case_full_context_param_bypasses():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    g.add_finding(_finding("F", "high", ["asset:endpoint:C.desktop-566at85"]))
    out = llm_sim.chat(g, "why is desktop-566 malicious", full_context=True)
    assert "matches multiple identities" not in out


def test_per_case_false_overrides_global_on():
    g = _graph(_asset("DESKTOP-566AT85"), _asset("DESKTOP-566B12"))
    orig = llm_sim._agentic_cfg
    llm_sim._agentic_cfg = lambda: {"chat_send_full_context": True}   # global ON
    try:
        out = llm_sim.chat(g, "why is desktop-566 malicious", full_context=False)
        assert "matches multiple identities" in out, "explicit per-case False must win"
    finally:
        llm_sim._agentic_cfg = orig
