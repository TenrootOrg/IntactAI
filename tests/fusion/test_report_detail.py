"""report_detail: per-case explicitness control (Auto / Explicit / Summary).

The fusion ontology is intentionally lossy — per-event evidence (real cmdline /
path / user / full hash) is parsed but not surfaced in the abstracted summary
view. report_detail lets the operator surface it for small/specific cases:
  * _resolve_detail: auto -> explicit for few-host/bounded-finding cases, else summary;
    explicit/summary honored verbatim;
  * EXPLICIT facts_md + distilled carry the real cmdline + full hash per high finding;
    SUMMARY does not;
  * evidence is capped (events-per-finding + chars-per-line) for budget safety;
  * masking is extended over the evidence free-text so a host/user that appears ONLY
    in a surfaced cmdline (not its own entity) is still scrubbed before the LLM.

Guards services/fusion/render._resolve_detail/_finding_evidence/facts_md/distilled +
llm_sim._build_mask_mapping evidence scan.
"""

import json
import re
import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import render, llm_sim                # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402
from services.data_anonymizer import DataAnonymizer        # noqa: E402

_TS = "2026-05-19T10:00:00Z"
_CMD = (r"powershell -enc SQBFAFgA ; net use \\ALDC99\c$ /user:adatumlab\srv01 P@ss "
        r"; 1.2.3.4")
_SHA = "a" * 64


def _graph(*, hosts=2, findings=1, with_event=True):
    g = FusionGraph("case:rd")
    aids = []
    for i in range(hosts):
        aid = f"asset:endpoint:C.host{i}"
        g.upsert(Entity(id=aid, type="asset", label=f"HOST{i}"))
        aids.append(aid)
    # one org account so 'adatumlab' is a known org domain (gate for DOMAIN\user scan)
    g.upsert(Entity(id="account:adatumlab\\almogs", type="account",
                    label="adatumlab\\almogs", attrs={"_assets": [aids[0]]}))
    for n in range(findings):
        eids = []
        if with_event:
            eid = f"event:e{n}"
            g.upsert(Entity(id=eid, type="event", label=f"SIGMA: rule {n}",
                            severity="high", first_seen=_TS,
                            attrs={"_assets": [aids[0]], "ev_cmdline": _CMD,
                                   "ev_user": "adatumlab\\almogs", "ev_sha256": _SHA,
                                   "ev_tgtip": "10.0.0.9"}))
            eids = [eid]
        g.add_finding(Finding(id=f"f{n}", title=f"SIGMA: Suspicious PowerShell {n}",
                              severity="high", confidence="high",
                              summary="payload executed", asset_ids=[aids[0]],
                              entity_ids=eids, ts=_TS))
    return g


# ---- _resolve_detail -------------------------------------------------------

def test_resolve_auto_small_is_explicit():
    mode, reason = render._resolve_detail(_graph(hosts=3), "auto")
    assert mode == "explicit", (mode, reason)
    assert "3 host" in reason


def test_resolve_auto_many_hosts_is_summary():
    g = _graph(hosts=render.EXPLICIT_MAX_HOSTS + 1, findings=1)
    mode, _ = render._resolve_detail(g, "auto")
    assert mode == "summary"


def test_resolve_auto_many_findings_is_summary():
    g = _graph(hosts=2, findings=render.EXPLICIT_MAX_FINDINGS + 1, with_event=False)
    mode, _ = render._resolve_detail(g, "auto")
    assert mode == "summary"


def test_resolve_forced_modes_honored():
    g = _graph(hosts=999) if False else _graph(hosts=3)
    assert render._resolve_detail(g, "explicit")[0] == "explicit"
    assert render._resolve_detail(g, "summary")[0] == "summary"
    # a big case forced explicit stays explicit; unknown value -> auto
    big = _graph(hosts=render.EXPLICIT_MAX_HOSTS + 5)
    assert render._resolve_detail(big, "explicit")[0] == "explicit"
    assert render._resolve_detail(g, "garbage")[0] == "explicit"   # auto on small


# ---- evidence surfaced in explicit, absent in summary ----------------------

def test_facts_explicit_has_cmdline_and_full_hash():
    g = _graph(hosts=2, findings=1)
    md = render.facts_md(g, detail="explicit")
    assert "powershell -enc" in md
    assert _SHA in md                                  # FULL hash, not truncated
    assert "Report detail: **explicit**" in md


def test_facts_summary_hides_evidence():
    g = _graph(hosts=2, findings=1)
    md = render.facts_md(g, detail="summary")
    assert "powershell -enc" not in md
    assert _SHA not in md
    assert "Report detail: **summary**" in md


def test_distilled_explicit_findings_carry_evidence():
    g = _graph(hosts=2, findings=1)
    p = render.distilled(g, detail="explicit")
    assert p["report_detail"] == "explicit"
    ev = p["findings"][0].get("evidence")
    assert ev and any("powershell -enc" in line for line in ev)
    # summary: no per-finding evidence
    ps = render.distilled(g, detail="summary")
    assert "evidence" not in ps["findings"][0]


# ---- caps ------------------------------------------------------------------

def test_evidence_is_single_line_and_backtick_safe():
    """Raw details can carry newlines + backticks (e.g. a multi-line Defender message
    + URL). Evidence must flatten to ONE line with backticks neutralised, else the
    markdown inline-code span breaks and corrupts the whole report."""
    g = FusionGraph("case:san")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H0"))
    g.upsert(Entity(id="event:s", type="event", label="e", severity="high",
                    first_seen=_TS,
                    attrs={"_assets": [aid],
                           "details": "Defender removed item.\nMore info:\r\nhttp://x/`bad`"}))
    f = Finding(id="fs", title="SIGMA: defender", severity="high", confidence="high",
                summary="x", asset_ids=[aid], entity_ids=["event:s"], ts=_TS)
    g.add_finding(f)
    lines = render._finding_evidence(g, f)
    assert lines, "expected evidence from the details fallback"
    for l in lines:
        assert "\n" not in l and "\r" not in l, "evidence must be a single line"
        assert "`" not in l, "backticks must be neutralised"
    # and it must render balanced inside facts_md
    md = render.facts_md(g, detail="explicit")
    assert md.count("`") % 2 == 0, "unbalanced backticks corrupt the report"


def test_evidence_skips_placeholder_values():
    g = FusionGraph("case:ph")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H0"))
    g.upsert(Entity(id="event:p", type="event", label="e", severity="high",
                    first_seen=_TS,
                    attrs={"_assets": [aid], "ev_proc": "Unknown", "ev_user": "-"}))
    f = Finding(id="fp", title="SIGMA: x", severity="high", confidence="high",
                summary="x", asset_ids=[aid], entity_ids=["event:p"], ts=_TS)
    g.add_finding(f)
    assert render._finding_evidence(g, f) == []   # all placeholders -> no noise line


def test_evidence_caps_events_and_chars():
    g = FusionGraph("case:caps")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H0"))
    n_events = render.EXPLICIT_EVENTS_PER_FINDING + 4
    eids = []
    for i in range(n_events):
        eid = f"event:c{i}"
        g.upsert(Entity(id=eid, type="event", label=f"e{i}", severity="high",
                        first_seen=_TS,
                        attrs={"_assets": [aid], "ev_cmdline": f"cmd{i}-" + ("X" * 500)}))
        eids.append(eid)
    f = Finding(id="fc", title="SIGMA: many events", severity="high",
                confidence="high", summary="x", asset_ids=[aid],
                entity_ids=eids, ts=_TS)
    g.add_finding(f)
    lines = render._finding_evidence(g, f)
    assert len(lines) <= render.EXPLICIT_EVENTS_PER_FINDING
    assert all(len(line) <= render.EXPLICIT_EVIDENCE_CHARS for line in lines)


# ---- masking extends over evidence free-text (the leak case) ---------------

def test_masking_scrubs_tokens_only_in_cmdline():
    """ALDC99 (UNC host) and srv01 (DOMAIN\\user) appear ONLY inside a cmdline, not
    as their own entities — explicit mode would leak them to the LLM. The evidence
    scan must mask them, and revert must restore the real values."""
    g = _graph(hosts=2, findings=1)
    payload = json.dumps(render.distilled(g, detail="explicit"))
    assert "ALDC99" in payload and "srv01" in payload      # present pre-mask

    mask = DataAnonymizer()
    llm_sim._build_mask_mapping(g, mask)
    masked = llm_sim._apply_mask(payload, mask)
    assert "ALDC99" not in masked, "UNC host leaked through masking"
    assert "srv01" not in masked, "DOMAIN\\user leaked through masking"

    restored = llm_sim._revert_mask(masked, mask)
    assert "ALDC99" in restored and "srv01" in restored   # operator gets real values


def test_masking_keeps_benign_path_token():
    """A benign 'Users\\Public' style path token must NOT be mistaken for an account
    (its 'domain' root is not a known org domain)."""
    g = FusionGraph("case:benign")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H0"))
    g.upsert(Entity(id="account:adatumlab\\almogs", type="account",
                    label="adatumlab\\almogs", attrs={"_assets": [aid]}))
    g.upsert(Entity(id="event:b", type="event", label="e", severity="high",
                    first_seen=_TS,
                    attrs={"_assets": [aid],
                           "ev_cmdline": r"copy C:\Users\Public\x.txt Temp\Public"}))
    mask = DataAnonymizer()
    llm_sim._build_mask_mapping(g, mask)
    # 'Users' / 'Temp' are not org domains -> never registered as identities
    assert not any(k.lower().startswith(("users\\", "temp\\")) for k in mask.mapping)


# ---- IOC high-confidence / validated filter (#4) ---------------------------

def _ioc_graph():
    g = FusionGraph("case:ioc")
    a, b = "asset:endpoint:C.h", "asset:endpoint:C.h2"
    g.upsert(Entity(id=a, type="asset", label="H0"))
    g.upsert(Entity(id=b, type="asset", label="H1"))
    g.upsert(Entity(id="ioc:hash:noise", type="ioc", label="n" * 64,        # seen once
                    attrs={"ioc_kind": "hash", "_assets": [a]}))
    g.upsert(Entity(id="ioc:hash:xh", type="ioc", label="x" * 64, flags=["cross_host"],
                    attrs={"ioc_kind": "hash", "_assets": [a, b]}))
    g.upsert(Entity(id="ioc:hash:cited", type="ioc", label="c" * 64,
                    attrs={"ioc_kind": "hash", "_assets": [a]}))
    g.add_finding(Finding(id="f1", title="SIGMA: yara hit", severity="high",
                          confidence="high", summary="x", asset_ids=[a],
                          entity_ids=["ioc:hash:cited"], ts=_TS))
    return g


def test_ioc_filter_keeps_high_confidence_drops_noise():
    g = _ioc_graph()
    kept, supp = render._high_confidence_iocs(g)
    ids = {i.id for i, _ in kept}
    assert "ioc:hash:noise" not in ids and supp >= 1     # merely-seen hash dropped
    assert "ioc:hash:xh" in ids and "ioc:hash:cited" in ids
    md = render.facts_md(g, detail="summary")
    assert "n" * 64 not in md and "x" * 64 in md          # noise gone from report


def test_ioc_filter_marks_validated():
    g = _ioc_graph()
    kept, _ = render._high_confidence_iocs(
        g, validations=[{"finding_id": "f1", "status": "real"}])
    reason = {i.id: r for i, r in kept}
    assert reason.get("ioc:hash:cited") == "validated"    # operator-confirmed -> 'by us'


# ---- Attack Assessment prose (#1) + exec-summary storytelling (#2) ----------

def _story_graph():
    g = FusionGraph("case:story")
    a = "asset:endpoint:C.h"
    g.upsert(Entity(id=a, type="asset", label="WS1", severity="critical",
                    attrs={"risk_score": 90}))
    g.add_finding(Finding(id="e", title="SIGMA: Encoded PowerShell", severity="critical",
                          confidence="high", summary="x", asset_ids=[a], ts=_TS))
    g.add_finding(Finding(id="c", title="SIGMA: LSASS Credential Dump", severity="high",
                          confidence="high", summary="x", asset_ids=[a], ts=_TS))
    return g


def test_attack_assessment_is_natural_language():
    g = _story_graph()
    md = render._attack_assessment(g, g.by_type("asset"), list(g.findings))
    assert "the adversary" in md                          # prose, not a title dump
    assert "executed code" in md and "harvested credentials" in md
    assert "_Execution:_" not in md and "(SIGMA" not in md  # no raw title list / wrapper


def test_attack_assessment_is_one_campaign_story():
    """The assessment must read as ONE infrastructure-wide campaign — entry point,
    lateral movement via shared creds/tooling, and a chronological progression —
    not isolated per-host bullets."""
    g = FusionGraph("case:campaign")
    a, b = "asset:endpoint:C.a", "asset:endpoint:C.b"
    g.upsert(Entity(id=a, type="asset", label="WS1", severity="critical",
                    attrs={"risk_score": 90}))
    g.upsert(Entity(id=b, type="asset", label="WS2", severity="high",
                    attrs={"risk_score": 65}))
    g.upsert(Entity(id="account:adatumlab\\srv", type="account", label="adatumlab\\srv",
                    flags=["cross_host"], attrs={"_assets": [a, b]}))
    g.add_finding(Finding(id="f1", title="SIGMA: Encoded PowerShell", severity="critical",
                          confidence="high", summary="x", asset_ids=[a],
                          ts="2025-01-01T00:00:00Z"))
    g.add_finding(Finding(id="f2", title="SIGMA: LSASS Credential Dump", severity="high",
                          confidence="high", summary="x", asset_ids=[b],
                          ts="2025-01-02T00:00:00Z"))
    md = render._attack_assessment(g, g.by_type("asset"), list(g.findings))
    assert "single campaign" in md and "Reconstructed progression" in md
    assert "pivoted between systems" in md and "adatumlab\\srv" in md   # lateral story
    assert md.index("WS1") < md.index("WS2")                            # chronological


def test_focal_host_consistent_with_risk_order():
    """Exec summary 'most affected' and Attack Assessment 'focal point' must both name
    the highest RISK-SCORE host (matching the Identity Risk table) — not diverge because
    exec summary tie-broke on severity alone."""
    g = FusionGraph("case:focal")
    a, b = "asset:endpoint:C.a", "asset:endpoint:C.b"
    g.upsert(Entity(id=a, type="asset", label="LOWRISK", severity="critical",
                    attrs={"risk_score": 80}))
    g.upsert(Entity(id=b, type="asset", label="HIGHRISK", severity="critical",
                    attrs={"risk_score": 98}))
    g.add_finding(Finding(id="a0", title="SIGMA: Encoded PowerShell", severity="critical",
                          confidence="high", summary="x", asset_ids=[a], ts=_TS))
    g.add_finding(Finding(id="b0", title="SIGMA: LSASS Credential Dump", severity="critical",
                          confidence="high", summary="x", asset_ids=[b], ts=_TS))
    assets, finds = g.by_type("asset"), list(g.findings)
    s = render._exec_summary(g, assets, finds)
    ma = s[max(0, s.find("most affected") - 140):s.find("most affected")]
    assert "HIGHRISK" in ma and "LOWRISK" not in ma
    aa = render._attack_assessment(g, assets, finds)
    fp = aa[max(0, aa.find("focal point") - 140):aa.find("focal point")]
    assert "HIGHRISK" in fp


def test_mitre_names_have_no_blank_dangling():
    g = FusionGraph("case:mitre")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H0", severity="high"))
    g.add_finding(Finding(id="m", title="Shared binary seen on 2 hosts", severity="high",
                          confidence="high", summary="x", asset_ids=[aid],
                          mitre=["T1570", "T1574"], ts=_TS))
    md = render.facts_md(g, detail="summary")
    assert "T1570 — Lateral Tool Transfer" in md
    assert re.search(r"\*\*T\d+ —\s*\*\*", md) is None       # no dangling blank name


def test_exec_summary_tells_a_story():
    g = _story_graph()
    s = render._exec_summary(g, g.by_type("asset"), list(g.findings), window=None)
    assert "the adversary" in s and "Bottom line" in s and "most affected" in s
    assert len(s) > 300                                   # substantive, not one-liner


# ---- section order: Identity Risk moved to the bottom (#3) ------------------

def test_identity_risk_is_near_the_bottom():
    g = _ioc_graph()
    g.upsert(Entity(id="asset:endpoint:C.h", type="asset", label="H0", severity="high"))
    md = render.facts_md(g, detail="summary")
    i_ioc = md.find("## Indicators of Compromise")
    i_idn = md.find("## 🎯 Identity Risk")
    i_rec = md.find("## Recommendations")
    assert i_ioc != -1 and i_idn != -1 and i_rec != -1
    assert i_ioc < i_idn < i_rec                          # IOCs ... Identity ... Recommendations
