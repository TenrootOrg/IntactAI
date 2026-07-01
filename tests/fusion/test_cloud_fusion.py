"""AWS (CloudTrail) scan -> fusion case wiring.

The AWS pipeline is collect-only: it persists SIGMA findings (keyed by
source/rule) to the run file, and Case Analysis fuses them via the cloud mapper.
This guards the store-side wiring added with the Prowler->CloudTrail migration:

  * `_flatten_cloud_findings` normalises the persisted dict-by-source (and the
    findings_by_severity fallback, and an already-flat list) into a flat list;
  * `_cloud_contribution` reads findings inline from the run details OR from the
    persisted /data/aws_runs/<rid>.json file, derives the account for the asset
    anchor, and produces account/event/ioc/asset entities;
  * an `aws_scan` run passes the case fusion gate only when the case enables the
    'aws' module, which is now selectable in the picker.

Regression guard for services/fusion/store.py (_cloud_contribution) +
services/fusion/mappers/cloud.py (map_cloud).
"""

import json
import os
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import store as S  # noqa: E402
from services.fusion.mappers.cloud import _mitre_ids, map_cloud  # noqa: E402

_ACCT = "137050702114"


def _backdoor_findings_by_source():
    """Shape the AWS pipeline actually persists: {source_or_rule: [finding, ...]}."""
    return {
        "aws_iam_backdoor_keys": [{
            "rule_title": "AWS IAM Backdoor Access Key",
            "_severity": "high",
            "mitre_attack": ["T1098"],
            "_timestamp": "2026-06-01T12:00:00Z",
            "matched_record": {
                "eventName": "CreateAccessKey",
                "recipientAccountId": _ACCT,
                "sourceIPAddress": "8.8.8.8",
                "userIdentity": {"userName": "nofl-attacker", "accountId": _ACCT},
            },
        }],
        "aws_attach_admin_policy": [{
            "rule_title": "AWS Attach Admin Policy",
            "_severity": "critical",
            "matched_record": {
                "eventName": "AttachUserPolicy",
                "recipientAccountId": _ACCT,
                "sourceIPAddress": "8.8.8.8",
                "userIdentity": {"userName": "nofl-attacker"},
            },
        }],
    }


def _by_type(ents):
    out = {}
    for e in ents:
        out.setdefault(e.type, []).append(e)
    return out


# ---------------------------------------------------------------- flatten

def test_flatten_dict_by_source():
    finds = S._flatten_cloud_findings(_backdoor_findings_by_source())
    assert len(finds) == 2, finds
    assert all(isinstance(f, dict) and "matched_record" in f for f in finds)


def test_flatten_already_flat_list_passthrough():
    lst = [{"rule_title": "x", "matched_record": {"eventName": "e"}}]
    assert S._flatten_cloud_findings(lst) == lst


def test_flatten_findings_by_severity_dict():
    fb = {"high": [{"rule_title": "a", "matched_record": {}}],
          "critical": [{"rule_title": "b", "matched_record": {}}],
          "low": []}
    assert len(S._flatten_cloud_findings(fb)) == 2


def test_flatten_garbage_is_empty():
    assert S._flatten_cloud_findings(None) == []
    assert S._flatten_cloud_findings("nope") == []
    # non-dict members are dropped, not crashed on
    assert S._flatten_cloud_findings({"s": [1, 2, {"matched_record": {}}]}) == [{"matched_record": {}}]


# ---------------------------------------------------------------- mitre

def test_mitre_ids_normalizes_sigma_dicts():
    # SIGMA's real shape: a list of {type, id|name} dicts.
    m = [{"type": "tactic", "name": "Persistence"}, {"type": "technique", "id": "T1098"}]
    assert _mitre_ids(m) == ["Persistence", "T1098"]


def test_mitre_ids_handles_str_list_and_none():
    assert _mitre_ids(None) == []
    assert _mitre_ids("T1078") == ["T1078"]
    assert _mitre_ids(["T1078", "T1098"]) == ["T1078", "T1098"]
    assert _mitre_ids({"type": "technique", "id": "T1550"}) == ["T1550"]


def test_dict_mitre_findings_produce_hashable_event_mitre():
    # Regression: real SIGMA mitre_attack (list of dicts) must not reach the graph
    # as dicts — render._phase does set(f.mitre), so it has to be hashable strings.
    finds = [{
        "rule_title": "AWS IAM Backdoor Users Keys", "_severity": "high",
        "mitre_attack": [{"type": "tactic", "name": "Persistence"},
                         {"type": "technique", "id": "T1098"}],
        "matched_record": {"eventName": "CreateAccessKey", "recipientAccountId": _ACCT,
                           "userIdentity": {"userName": "nofl"}},
    }]
    ents, _ = map_cloud(finds, run_id="r-mitre", provider="aws", account=_ACCT)
    ev = [e for e in ents if e.type == "event"][0]
    mitre = ev.attrs.get("mitre")
    assert mitre == ["Persistence", "T1098"], mitre
    set(mitre)  # must not raise (would raise on dict members)


# ---------------------------------------------------------------- account

def test_account_from_recipient_account_id():
    finds = S._flatten_cloud_findings(_backdoor_findings_by_source())
    assert S._cloud_account({}, finds) == _ACCT


def test_account_explicit_detail_wins():
    assert S._cloud_account({"account": "999"}, []) == "999"


def test_account_from_user_identity_when_no_recipient():
    finds = [{"matched_record": {"eventName": "e",
                                 "userIdentity": {"accountId": "555"}}}]
    assert S._cloud_account({}, finds) == "555"


# ------------------------------------------------ IAM principal -> account (mask)

def test_iam_state_principal_becomes_account_entity():
    # IAM-posture STATE findings name their subject in ResourceName, not in a
    # userIdentity block. It must still become an account entity so it correlates
    # AND gets masked (otherwise the username only lives in the event label and
    # leaks to the LLM). Regression guard for the AWS masking gap.
    finds = [{
        "rule_title": "State: User intactai-test-backdoor has admin privileges",
        "_severity": "critical",
        "matched_record": {
            "_source": "iam_principals", "EventSource": "AWS.IAM", "Service": "iam",
            "ResourceType": "AWS::IAM::User", "ResourceName": "intactai-test-backdoor",
            "ResourceUid": "arn:aws:iam::137050702114:user/intactai-test-backdoor",
            "IsAdmin": True,
        },
    }]
    ents, _ = map_cloud(finds, run_id="r-iam", provider="aws", account="137050702114")
    accts = [e for e in ents if e.type == "account"]
    assert any(e.label == "intactai-test-backdoor" for e in accts), \
        f"IAM principal must be an account entity, got {[e.label for e in accts]}"


# ---------------------------------------------------- contribution (inline)

def test_contribution_inline_dict_findings_builds_graph():
    det = {"findings": _backdoor_findings_by_source()}
    ents, rels = S._cloud_contribution("rid-inline", det, "aws")
    t = _by_type(ents)
    # 1 cloud-account asset, 2 events, account principal(s), source-IP ioc(s)
    assert len(t.get("asset", [])) == 1
    assert t["asset"][0].id == f"asset:cloud_account:aws:{_ACCT}"
    assert len(t.get("event", [])) == 2
    assert t.get("account"), "attacker principal must be an account entity"
    assert any(e.label == "nofl-attacker" for e in t["account"])
    assert any(e.type == "ioc" and e.label == "8.8.8.8" for e in ents)
    # account -> event (executed) and account -> asset (authenticated) links exist
    kinds = {(r.kind) for r in rels}
    assert "executed" in kinds and "authenticated" in kinds


def test_contribution_findings_by_severity_fallback():
    det = {"findings_by_severity": {
        "critical": [{"rule_title": "AttachAdmin",
                      "matched_record": {"eventName": "AttachUserPolicy",
                                         "recipientAccountId": _ACCT,
                                         "userIdentity": {"userName": "evil"}}}]}}
    ents, _ = S._cloud_contribution("rid-fb", det, "aws")
    assert any(e.type == "account" and e.label == "evil" for e in ents)
    assert any(e.type == "event" for e in ents)


def test_contribution_empty_is_noop():
    assert S._cloud_contribution("rid-empty", {}, "aws") == ([], [])


# ---------------------------------------------------- contribution (file)

def test_contribution_reads_persisted_run_file():
    rid = "rid-file-cloudtest"
    d = "/app/data/aws_runs"
    os.makedirs(d, exist_ok=True)
    fp = f"{d}/{rid}.json"
    try:
        with open(fp, "w") as f:
            json.dump({"findings": _backdoor_findings_by_source()}, f)
        # details carry NO findings -> loader must fall back to the file
        ents, _ = S._cloud_contribution(rid, {}, "aws")
        assert any(e.id == f"asset:cloud_account:aws:{_ACCT}" for e in ents)
        assert any(e.type == "event" for e in ents)
    finally:
        if os.path.exists(fp):
            os.remove(fp)


# ---------------------------------------------------------------- gate/catalog

def test_aws_module_is_selectable_in_catalog():
    cat = {c["name"]: c for c in S.fusion_modules_catalog()}
    assert cat["aws"]["available"] is True
    assert cat["aws"]["label"] == "AWS (CloudTrail)"
    # off by default: not every case is a cloud case
    assert cat["aws"]["default"] is False


def test_aws_scan_passes_gate_only_when_aws_enabled():
    run = {"automation_type": "aws_scan", "details": {}}
    assert S._run_passes_gate(run, {"fusion_modules": ["aws"]}) is True
    assert S._run_passes_gate(run, {"fusion_modules": ["memory"]}) is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} passed")
