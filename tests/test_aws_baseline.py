"""The account baseline flags the FIRST new network / sensitive change / region -- only
for identities with history, once each, and the same again when the days are re-scanned."""
import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws import baseline  # noqa: E402

ACCT = "111122223333"


def ev(day, name="ListUsers", ip="198.51.100.7", src="iam", ro=True, region="us-east-1", user="alice", hour=10):
    return {"eventTime": f"2026-10-{day:02d}T{hour:02d}:00:00Z", "eventName": name, "eventSource": f"{src}.amazonaws.com",
            "sourceIPAddress": ip, "readOnly": ro, "awsRegion": region, "recipientAccountId": ACCT,
            "userAgent": "aws-cli/2", "userIdentity": {"type": "IAMUser", "userName": user,
                                                       "arn": f"arn:aws:iam::{ACCT}:user/{user}"}}


def history():
    """Two weeks of alice from two home networks, with one IAM change; us-east-1 and eu-west-1."""
    out = []
    for d in range(1, 15):
        out.append(ev(d, ip="198.51.100.7" if d % 2 else "203.0.113.9"))
    out.append(ev(3, "CreateUser", ro=False))
    out.append(ev(4, "RunInstances", src="ec2", ro=False, region="eu-west-1"))
    return out


class Baseline(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._old = baseline.BASE_DIR
        baseline.BASE_DIR = self.dir

    def tearDown(self):
        baseline.BASE_DIR = self._old
        shutil.rmtree(self.dir)

    def titles(self, recs, **kw):
        return sorted((f["rule_title"], f["severity"]) for f in baseline.detect(recs, **kw))

    def test_normal_history_is_quiet(self):
        self.assertEqual(self.titles(history()), [])

    def test_a_sensitive_change_from_a_new_network(self):
        attack = [ev(20, "CreateAccessKey", ip="192.0.2.50", ro=False)]
        got = self.titles(history() + attack)
        self.assertIn(("AWS Person Active From A New Network", "medium"), got)
        self.assertIn(("AWS Identity Made A Sensitive Change It Never Made Before", "low"), got)

    def test_a_new_region(self):
        got = self.titles(history() + [ev(20, "RunInstances", src="ec2", ro=False, region="ap-southeast-1")])
        self.assertIn(("AWS Account Used In A New Region", "medium"), got)

    def test_no_normal_yet_no_finding(self):
        """A brand-new identity (or account) has no history to differ from."""
        fresh = [ev(1, user="bob"), ev(2, "CreateAccessKey", ip="192.0.2.50", ro=False, user="bob")]
        self.assertEqual(self.titles(fresh), [])

    def test_each_new_thing_once(self):
        attack = [ev(20, "ListRoles", ip="192.0.2.50", hour=h) for h in range(10, 15)]
        got = self.titles(history() + attack)
        self.assertEqual(got.count(("AWS Person Active From A New Network", "low")), 1)

    def test_a_rescan_of_the_same_days_finds_the_same(self):
        recs = history() + [ev(20, "CreateAccessKey", ip="192.0.2.50", ro=False)]
        first = self.titles(recs)
        self.assertTrue(os.listdir(self.dir), "the baseline is kept for the next scan")
        self.assertEqual(first, self.titles(recs))

    def test_the_stored_baseline_carries_history_into_a_short_window(self):
        baseline.detect(history())                                  # an earlier scan learned two weeks
        later = [ev(25, "CreateAccessKey", ip="192.0.2.50", ro=False)]
        self.assertIn(("AWS Person Active From A New Network", "medium"), self.titles(later))

    def test_roles_are_not_judged_by_network(self):
        role = ev(20, ip="192.0.2.50")
        role["userIdentity"] = {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/app/s1",
                                "sessionContext": {"sessionIssuer": {"arn": f"arn:aws:iam::{ACCT}:role/app"}}}
        self.assertEqual(self.titles(history() + [role]), [])

    def test_an_unreadable_baseline_is_not_fatal(self):
        with open(os.path.join(self.dir, f"{ACCT}.json"), "w") as fh:
            fh.write("{not json")
        logs = []
        baseline.detect(history(), log=lambda m, l="info": logs.append(m))
        self.assertTrue(any("unreadable" in m for m in logs))


if __name__ == "__main__":
    unittest.main()
