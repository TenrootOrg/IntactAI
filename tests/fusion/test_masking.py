"""Masking protects CUSTOMER-IDENTITY in transit to the LLM, then REVERTS.

Model (operator-agreed):
  * mask hosts, users, the org/AD domain, internal IPs on the LLM INPUT — dynamic,
    read from the data, works for any company (nothing hardcoded);
  * KEEP threat-intel IOCs (file hashes, external/malicious domains) so the LLM can
    recognise + correlate them — they're the attacker's infra, not the customer's;
  * REVERT in the LLM's output so the operator always gets the real report back;
  * Windows system accounts are never masked;
  * runs only when a mask is supplied (= masking enabled in the case config).

Guards services/fusion/llm_sim._build_mask_mapping / _apply_mask / _revert_mask.
"""

import json
import re
import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import llm_sim, render               # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402
from services.data_anonymizer import DataAnonymizer       # noqa: E402


def _present(v, blob):
    if not v:
        return False
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(v) + r"(?![A-Za-z0-9])",
                     blob, re.IGNORECASE) is not None


def _company_graph(c):
    g = FusionGraph("case:" + c["dom"])
    aid = f"asset:endpoint:C.{c['hosts'][0].lower()}"
    for h in c["hosts"]:
        g.upsert(Entity(id=f"asset:endpoint:C.{h.lower()}", type="asset", label=h))
    for u in c["users"]:
        g.upsert(Entity(id=f"account:{u.lower()}", type="account", label=u,
                        attrs={"_assets": [aid]}))
    for val, kind in c["iocs"]:
        g.upsert(Entity(id=f"ioc:{kind}:{val}", type="ioc", label=val,
                        attrs={"ioc_kind": kind}))
    h0, h1, u0 = c["hosts"][0], c["hosts"][-1], c["users"][0]
    iocd = next((v for v, k in c["iocs"] if k == "domain"), None)
    iochash = next((v for v, k in c["iocs"] if k == "hash"), None)
    g.add_finding(Finding(id="f1", title=f"SIGMA: Suspicious PowerShell on {h0}",
                          severity="high", confidence="high",
                          summary=f"{u0} ran a payload on {h0.lower()} beaconing to "
                                  f"{iocd or 'n/a'} (hash {iochash or 'n/a'}); also on {h1}.",
                          asset_ids=[aid]))
    g.add_finding(Finding(id="f2", title=f"Account '{u0}' used across 2 hosts",
                          severity="high", confidence="high",
                          summary=f"{u0} authenticated to {h1}.", asset_ids=[aid],
                          kind="cross_host"))
    return g


_COMPANIES = [
    {"dom": "adatumlab", "hosts": ["ALDC02", "WS-01"],
     "users": ["adatumlab\\almogs", "jdoe@adatumlab.local"],
     "iocs": [("evil-c2.com", "domain"), ("a" * 32, "hash"), ("203.0.113.5", "ip")]},
    {"dom": "contoso", "hosts": ["FIN-PC01", "SRV-DB02"],
     "users": ["contoso\\jsmith"],
     "iocs": [("bad-domain.net", "domain"), ("b" * 64, "hash")]},
    {"dom": "globex", "hosts": ["GLX-WEB1"],
     "users": ["globex\\admin1"],
     "iocs": [("malware.io", "domain"), ("198.51.100.7", "ip")]},
]


def _mask_input(c, g):
    """Mirror what generate_report sends to the LLM: build mapping, mask the input.
    Uses an explicit blob of every value (reliable, unlike distilled() which trims)."""
    mask = DataAnonymizer(custom_patterns=[])
    llm_sim._build_mask_mapping(g, mask)
    parts = list(c["hosts"]) + [h.lower() for h in c["hosts"]] + list(c["users"]) \
        + [c["dom"]] + [v for v, _ in c["iocs"]]
    raw = " | ".join(f"value={p}" for p in parts)
    return mask, raw, llm_sim._apply_mask(raw, mask)


def test_identity_masked_iocs_kept_and_reversible_for_any_company():
    for c in _COMPANIES:
        g = _company_graph(c)
        mask, raw, masked = _mask_input(c, g)
        tag = c["dom"]
        # 1) customer-identifying values are GONE from the LLM input (+ variants)
        for h in c["hosts"]:
            assert not _present(h, masked), f"[{tag}] host leaked to LLM: {h}"
            assert not _present(h.lower(), masked), f"[{tag}] lowercase host leaked: {h}"
        for u in c["users"]:
            assert not _present(u, masked), f"[{tag}] account leaked to LLM: {u}"
            assert not _present(u.split('\\')[-1].split('@')[0], masked), f"[{tag}] bare user leaked"
        assert not _present(tag, masked), f"[{tag}] org domain leaked to LLM"
        # 2) threat-intel IOCs are KEPT (LLM needs them to correlate/recognise)
        for val, kind in c["iocs"]:
            if kind in ("domain", "hash"):
                assert _present(val, masked), f"[{tag}] IOC {kind} should be KEPT for the LLM: {val}"
        # 3) revert restores the real values (operator gets the real report back)
        reverted = llm_sim._revert_mask(masked, mask)
        for h in c["hosts"]:
            assert _present(h, reverted), f"[{tag}] revert lost host: {h}"
        for u in c["users"]:
            assert _present(u, reverted), f"[{tag}] revert lost account: {u}"
        assert _present(tag, reverted), f"[{tag}] revert lost org domain"


def test_masking_preserves_correlation_consistency():
    # a value that appears N times maps to ONE stable pseudonym (so the LLM can still
    # correlate 'same host/user across events')
    c = _COMPANIES[0]
    g = _company_graph(c)
    mask, raw, masked = _mask_input(c, g)
    host = c["hosts"][0]
    n_before = len(re.findall(re.escape(host), raw, re.IGNORECASE))   # canonical + lowercase = 2
    pseudo = mask.mapping.get(host)
    assert pseudo, "host must be in the mapping"
    assert n_before >= 2 and masked.count(pseudo) == n_before, \
        "same value -> same pseudonym, every occurrence (correlation preserved)"
    assert not _present(host, masked)


def test_system_accounts_are_not_masked():
    g = FusionGraph("case:sys")
    aid = "asset:endpoint:C.box1"
    g.upsert(Entity(id=aid, type="asset", label="BOX1"))
    g.upsert(Entity(id="account:nt", type="account", label="NT AUTHORITY\\SYSTEM",
                    attrs={"_assets": [aid]}))
    mask = DataAnonymizer(custom_patterns=[])
    llm_sim._build_mask_mapping(g, mask)
    assert "NT AUTHORITY\\SYSTEM" not in mask.mapping, "system account must not enter the mask map"
    out = llm_sim._apply_mask("svc as NT AUTHORITY\\SYSTEM on BOX1", mask)
    assert "NT AUTHORITY\\SYSTEM" in out, "system accounts must NOT be masked"
    assert "BOX1" not in out, "a real host alongside it is still masked"


def test_no_llm_report_is_real_values():
    # deterministic path sends nothing to a provider -> operator gets real values
    c = _COMPANIES[0]
    g = _company_graph(c)
    md = llm_sim.generate_report(g, mask=DataAnonymizer(custom_patterns=[]),
                                 prefer_llm=False, min_severity="informational", case_name="X")
    assert _present(c["hosts"][0], md), "no-LLM report must contain real values"


def test_apply_mask_respects_token_boundaries():
    mask = DataAnonymizer(custom_patterns=[])
    mask.mapping = {"ALDC02": "Hostname1"}
    out = llm_sim._apply_mask("aldc02 and ALDC02$ but not ALDC020", mask)
    # case-insensitive variant + $-suffixed are masked; the larger token ALDC020 is NOT
    assert out == "Hostname1 and Hostname1$ but not ALDC020", out


def test_audit_logger_is_safe_without_run_id():
    g = _company_graph(_COMPANIES[0])
    mask = DataAnonymizer(custom_patterns=[])
    llm_sim._build_mask_mapping(g, mask)
    assert mask.mapping, "mapping should be populated"
    llm_sim._log_mask_audit(None, mask)   # no run_id -> no-op, must not raise
