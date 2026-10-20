"""Sigma correlation rules: a count over a time window (event_count / value_count).

About 190 of Splunk's detections are "stats count by user | where count > N" --
password spray, MFA floods, mass share access -- and none could be translated, so
they detected nothing. Sigma's correlation spec expresses them; these tests pin the
engine to it: rules load from multi-document files, a base rule alone is not a
detection, and the window slides.
"""
import os
import sys
import tempfile
import textwrap
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import sigma_eval as S  # noqa: E402

RULES = textwrap.dedent("""\
    title: Failed logon
    name: failed_logon
    id: 11111111-0000-0000-0000-000000000001
    level: informational
    logsource: {product: windows, service: security}
    detection:
      sel: {EventID: 4625}
      condition: sel
    ---
    title: Many failed logons for one account
    id: 11111111-0000-0000-0000-000000000002
    level: medium
    tags: [attack.t1110.001]
    correlation:
      type: event_count
      rules: [failed_logon]
      group-by: [TargetUserName]
      timespan: 10m
      condition: {gte: 10}
    ---
    title: One source failing against many accounts
    id: 11111111-0000-0000-0000-000000000003
    level: high
    tags: [attack.t1110.003]
    correlation:
      type: value_count
      rules: [failed_logon]
      group-by: [IpAddress]
      timespan: 30m
      condition: {gte: 5, field: TargetUserName}
    ---
    title: Ordered pair (not supported)
    id: 11111111-0000-0000-0000-000000000004
    level: high
    correlation:
      type: temporal
      rules: [failed_logon]
      group-by: [IpAddress]
      timespan: 5m
    """)


def logon(user, ip="10.0.0.9", eid=4625):
    return {"EventID": eid, "Channel": "Security", "Provider": "Microsoft-Windows-Security-Auditing",
            "TargetUserName": user, "IpAddress": ip}


class Correlations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        with open(os.path.join(cls.dir, "brute.yml"), "w") as fh:
            fh.write(RULES)
        S._CACHE["key"] = None
        cls.loaded = S.load(dirs=(cls.dir,), min_level="low")

    def titles(self, items):
        return sorted(h["rule"]["title"] for h in S.correlate(items, self.loaded["correlations"]))

    def test_load_from_a_multi_document_file(self):
        self.assertEqual(["Many failed logons for one account", "One source failing against many accounts"],
                         sorted(c["title"] for c in self.loaded["correlations"]))
        self.assertEqual(1, self.loaded["skipped"].get("correlation-temporal"), self.loaded["skipped"])
        c = next(c for c in self.loaded["correlations"] if c["type"] == "value_count")
        self.assertEqual((c["timespan"], c["n"], c["field"], c["mitre"]), (1800, 5, "TargetUserName", ["T1110.003"]))

    def test_a_base_rule_alone_is_not_a_detection(self):
        self.assertEqual([], [r for r in self.loaded["rules"] if r["title"] == "Failed logon"])

    def test_count_needs_the_window(self):
        ten_fast = [(1000 + i * 30, logon("alice")) for i in range(10)]          # 10 in 4.5 min
        self.assertEqual(["Many failed logons for one account"], self.titles(ten_fast))
        nine = ten_fast[:9]
        self.assertEqual([], self.titles(nine), "one short of the threshold")
        ten_slow = [(1000 + i * 120, logon("alice")) for i in range(10)]         # 10 over 18 min
        self.assertEqual([], self.titles(ten_slow), "spread past the 10 min window")

    def test_groups_are_counted_apart(self):
        mixed = [(1000 + i * 10, logon("alice" if i % 2 else "bob")) for i in range(18)]   # 9 + 9
        self.assertEqual([], self.titles(mixed))

    def test_distinct_values_per_group(self):
        spray = [(2000 + i * 60, logon(f"user{i}")) for i in range(5)]
        hits = S.correlate(spray, self.loaded["correlations"])
        self.assertEqual(["One source failing against many accounts"], [h["rule"]["title"] for h in hits])
        h = hits[0]
        self.assertEqual((h["count"], h["group"], h["members"]), (5, {"IpAddress": "10.0.0.9"}, [0, 1, 2, 3, 4]))
        same_user = [(2000 + i * 60, logon("user0")) for i in range(5)]
        self.assertEqual([], self.titles(same_user), "5 failures of one account are not 5 accounts")

    def test_only_rows_the_base_rule_matches_count(self):
        ok = [(1000 + i * 10, logon("alice", eid=4624)) for i in range(20)]       # successful logons
        self.assertEqual([], self.titles(ok))
        undated = [(None, logon("alice")) for _ in range(20)]
        self.assertEqual([], self.titles(undated), "a row with no time is never in a window")

    def test_unsupported_shapes_are_refused(self):
        refs = {"failed_logon": {"title": "b", "logsource": {"product": "windows"},
                                 "detection": {"s": {"EventID": 1}, "condition": "s"}}}
        for corr, why in (({"type": "event_count", "rules": ["failed_logon"], "timespan": "10m",
                            "condition": {"lt": 3}}, "correlation-condition"),
                          ({"type": "value_count", "rules": ["failed_logon"], "timespan": "10m",
                            "condition": {"gte": 3}}, "correlation-field"),
                          ({"type": "event_count", "rules": ["nope"], "timespan": "10m",
                            "condition": {"gte": 3}}, "correlation-base-missing"),
                          ({"type": "event_count", "rules": ["failed_logon"], "timespan": "ten minutes",
                            "condition": {"gte": 3}}, "timespan")):
            with self.assertRaises(S.Unsupported) as cm:
                S.compile_correlation({"title": "c", "correlation": corr}, refs)
            self.assertTrue(str(cm.exception).startswith(why), (why, str(cm.exception)))


if __name__ == "__main__":
    unittest.main()
