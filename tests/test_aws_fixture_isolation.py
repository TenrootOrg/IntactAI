"""Bundled AWS demo data must never be mistaken for a customer's evidence.

The AWS collectors ship hand-curated fixtures under `services/aws/fake_data/`.
They are deliberately attack-shaped — a Tor exit node (185.220.101.45), an IAM
backdoor sequence, a GuardDuty `UnauthorizedAccess:IAMUser/MaliciousIPCaller`
at severity 8.5 — because they exist to make SIGMA fire during development.

They used to load whenever a live collector returned nothing. Three triggers
reached that fallback: no boto3, an exception, and **an empty result**. The
third is the dangerous one: an empty result is exactly what a CLEAN ACCOUNT
returns. So a real, fully-credentialed scan of a tenant with nothing wrong
produced invented critical findings, in a run persisted as `mode: online` with
no field distinguishing them from real ones.

It did not stop at the run. `services/fusion/mappers/cloud.py` turns a
finding's `sourceIPAddress` into an `ioc:ip` entity, and those are GLOBAL — the
same node an endpoint NetScan hit collapses into. A fictional Tor address could
therefore cross-correlate against real evidence in a live case.

Azure already fails closed when its credentials are missing. These tests pin
AWS to the same contract:

  * fixtures load ONLY when an operator explicitly opts in
  * when they do load, every record and the run are marked synthetic
  * a synthetic run is refused by Case fusion

Run: docker exec intact_backend python3 /app/workdir/tests/test_aws_fixture_isolation.py
"""

import os
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.aws import collectors as C          # noqa: E402
from services.fusion import store as S            # noqa: E402


class _Env:
    """Set/clear the opt-in for the duration of a block."""

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.saved = os.environ.get(C._DEMO_FIXTURES_ENV)
        if self.value is None:
            os.environ.pop(C._DEMO_FIXTURES_ENV, None)
        else:
            os.environ[C._DEMO_FIXTURES_ENV] = self.value
        return self

    def __exit__(self, *a):
        if self.saved is None:
            os.environ.pop(C._DEMO_FIXTURES_ENV, None)
        else:
            os.environ[C._DEMO_FIXTURES_ENV] = self.saved


def _collect(source, logs=None):
    """Drive _stub_collect with no aws_config — i.e. the fallback path."""
    def log(msg, level="info"):
        if logs is not None:
            logs.append((level, msg))
    return C._stub_collect(source, log, aws_config=None)


# --- the opt-in -------------------------------------------------------------


def test_fixtures_do_not_load_by_default():
    """THE finding. Absent an explicit opt-in, no demo record may appear."""
    with _Env(None):
        assert C.demo_fixtures_enabled() is False
        for source in C.LOG_SOURCES:
            recs = _collect(source)
            assert recs == [], (
                f"{source} produced {len(recs)} record(s) with fixtures off — "
                f"a clean account would be reported as compromised")


def test_the_optin_is_explicit_not_truthy_junk():
    for value in ("0", "false", "no", "", "off", "maybe"):
        with _Env(value):
            assert C.demo_fixtures_enabled() is False, f"{value!r} enabled fixtures"
    for value in ("1", "true", "TRUE", "yes", "on"):
        with _Env(value):
            assert C.demo_fixtures_enabled() is True, f"{value!r} did not enable fixtures"


def test_an_empty_live_result_is_reported_as_empty():
    """A clean account is a real answer. Substituting demo findings for it is
    the worst version of this bug, because nothing looks wrong."""
    logs = []
    with _Env(None):
        recs = _collect("cloudtrail_iam", logs)
    assert recs == []
    joined = " ".join(m for _l, m in logs)
    assert "demo fixtures are off" in joined, joined
    assert C._DEMO_FIXTURES_ENV in joined, "the log must name the opt-in switch"


# --- when demo data IS requested -------------------------------------------


def test_opted_in_fixtures_are_marked_on_every_record():
    with _Env("1"):
        recs = _collect("cloudtrail_iam")
    assert recs, "opting in should produce the bundled records"
    for r in recs:
        assert r.get(C.SYNTHETIC_KEY) is True, f"unmarked demo record: {r!r}"


def test_opted_in_run_says_so_in_the_log():
    logs = []
    with _Env("1"):
        _collect("guardduty_findings", logs)
    joined = " ".join(m for _l, m in logs)
    assert "SYNTHETIC" in joined, joined
    assert any(lvl == "warning" for lvl, _m in logs), "must warn, not whisper at info"


# --- fusion refuses it ------------------------------------------------------


def test_case_fusion_refuses_a_synthetic_run():
    """The blast radius. cloud.py turns sourceIPAddress into a GLOBAL ioc:ip
    node, so a fixture address would collapse with real NetScan evidence."""
    det = {
        "synthetic": True,
        "findings": {"high": [{"rule": "aws_iam_backdoor_users_keys",
                               "severity": "high",
                               "matched_record": {"sourceIPAddress": "185.220.101.45",
                                                  "userIdentity": {"userName": "admin.user"},
                                                  "recipientAccountId": "123456789012"}}]},
    }
    ents, rels = S._cloud_contribution("aws_scan_synthetic", det, "aws")
    assert ents == [] and rels == [], (
        f"a synthetic run contributed {len(ents)} entities to a case")


def test_case_fusion_still_accepts_a_real_run():
    """The guard must not swallow genuine cloud evidence."""
    det = {
        "findings": {"high": [{"rule": "aws_iam_backdoor_users_keys",
                               "severity": "high",
                               "matched_record": {"sourceIPAddress": "203.0.113.9",
                                                  "userIdentity": {"userName": "real.user"},
                                                  "recipientAccountId": "123456789012"}}]},
    }
    ents, _rels = S._cloud_contribution("aws_scan_real", det, "aws")
    assert ents, "a real AWS run must still fuse into the case"
    labels = " ".join(str(e.label) for e in ents)
    assert "203.0.113.9" in labels, labels


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
