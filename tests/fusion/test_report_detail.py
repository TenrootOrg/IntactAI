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
