"""AWS Full mode collects every change and only the reads the rules use.

WHY. Full mode paged through EVERY CloudTrail event. On a quiet account (28 writes in
30 days across 3 regions) a security integration's read-only polling filled the 10,000
cap in each region in ~7 minutes (2026-10-26): the 30-day window was never covered
and real changes could be pushed out.
"""
import datetime as dt
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws import cloudtrail_runner as ct  # noqa: E402


class FakeTrail:
    """LookupEvents with one attribute: 3 writes (one by root), 2000 reads of one call."""

    def __init__(self):
        self.calls = []
        t = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)
        ev = lambda i, name, user, ro: {"EventId": f"e{i}", "EventName": name, "Username": user,  # noqa: E731
                                        "EventTime": t, "ReadOnly": ro, "CloudTrailEvent": "{}"}
        self.events = [ev(1, "CreateUser", "Scanner_SVC", "false"), ev(2, "DeleteUser", "root", "false"),
                       ev(3, "ConsoleLogin", "root", "false"), ev(4, "DescribeInstances", "root", "true")]
        self.events += [ev(100 + i, "GetCallerIdentity", "Scanner_SVC", "true") for i in range(2000)]

    def lookup_events(self, **kw):
        attr = (kw.get("LookupAttributes") or [None])[0]
        self.calls.append(attr)
        key = {"ReadOnly": "ReadOnly", "Username": "Username", "EventName": "EventName"}[attr["AttributeKey"]]
        hits = [e for e in self.events if str(e[key]) == attr["AttributeValue"]]
        start = int(kw.get("NextToken") or 0)
        page = hits[start:start + 50]
        return {"Events": page, **({"NextToken": str(start + 50)} if start + 50 < len(hits) else {})}


class FullModeIsWritesFirst(unittest.TestCase):
    def _run(self, cap=10000):
        trail, logs = FakeTrail(), []
        out = ct._collect_for_region(client=trail, region="us-east-1", start_dt=None, end_dt=None,
                                     event_names=None, username_filters=None, max_events=cap,
                                     log=lambda m, l="info": logs.append((l, m)), is_cancelled_func=None)
        return trail, out, logs

    def test_passes_are_writes_then_the_rule_reads(self):
        trail, _, _ = self._run()
        seen = []
        for a in trail.calls:
            if a not in seen:
                seen.append(a)
        self.assertEqual(seen[0], {"AttributeKey": "ReadOnly", "AttributeValue": "false"})
        self.assertEqual([a["AttributeValue"] for a in seen[1:]], list(ct.FULL_READ_EVENT_NAMES))

    def test_every_write_is_kept_once_and_roots_page_loads_are_not(self):
        _, out, _ = self._run()
        names = [e.get("eventName") or e.get("EventName") for e in out]
        for n in ("CreateUser", "DeleteUser", "ConsoleLogin"):
            self.assertEqual(names.count(n), 1, n)
        self.assertNotIn("DescribeInstances", names)

    def test_a_chatty_read_is_capped_and_cannot_crowd_out_writes(self):
        _, out, logs = self._run(cap=10000)
        names = [e.get("eventName") or e.get("EventName") for e in out]
        self.assertEqual(names.count("GetCallerIdentity"), ct.FULL_READ_PASS_CAP)
        self.assertTrue(any("capped at" in m for _l, m in logs))
        _, out, _ = self._run(cap=3)                # tiny region cap: the writes still made it
        self.assertEqual(sorted(e.get("eventName") or e.get("EventName") for e in out),
                         ["ConsoleLogin", "CreateUser", "DeleteUser"])

    def test_light_is_every_change_without_the_reads(self):
        trail, logs = FakeTrail(), []
        out = ct._collect_for_region(client=trail, region="r", start_dt=None, end_dt=None, event_names=None,
                                     username_filters=None, max_events=500, log=lambda m, l="info": None,
                                     is_cancelled_func=None, include_reads=False)
        self.assertEqual({tuple(sorted(a.items())) for a in trail.calls}, {(("AttributeKey", "ReadOnly"), ("AttributeValue", "false"))})
        self.assertEqual(sorted(e.get("eventName") or e.get("EventName") for e in out), ["ConsoleLogin", "CreateUser", "DeleteUser"])

    def test_an_explicit_event_name_slice_is_unchanged(self):
        trail, logs = FakeTrail(), []
        ct._collect_for_region(client=trail, region="r", start_dt=None, end_dt=None,
                               event_names=["CreateUser"], username_filters=None, max_events=500,
                               log=lambda m, l="info": None, is_cancelled_func=None)
        self.assertEqual(trail.calls, [{"AttributeKey": "EventName", "AttributeValue": "CreateUser"}])


class PeopleWhoChangedSomethingHaveTheirReadsFetched(unittest.TestCase):
    """A discovery sweep is many different reads by one person -- no name pass finds it.
    The people who made a change get a Username pass; root and roles do not."""

    def test_it(self):
        import json
        t = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)

        def ev(i, name, user, ro, ui):
            return {"EventId": f"p{i}", "EventName": name, "Username": user, "EventTime": t, "ReadOnly": ro,
                    "CloudTrailEvent": json.dumps({"eventName": name, "userIdentity": ui})}
        alice = {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::1:user/alice"}
        sso = {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/AWSReservedSSO_Admin_x/jane@corp"}
        root = {"type": "Root", "arn": "arn:aws:iam::1:root"}
        role = {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/scanner/s1"}
        trail = FakeTrail()
        trail.events = [ev(1, "CreateUser", "alice", "false", alice), ev(2, "PutRolePolicy", "jane@corp", "false", sso),
                        ev(3, "DeleteUser", "root", "false", root), ev(4, "CreateRole", "s1", "false", role)]
        trail.events += [ev(10 + i, f"List{i}", "alice", "true", alice) for i in range(30)]
        trail.events += [ev(100 + i, "DescribeInstances", "root", "true", root) for i in range(30)]
        trail.events += [ev(200 + i, "ListBuckets", "s1", "true", role) for i in range(30)]
        logs = []
        out = ct._collect_for_region(client=trail, region="r", start_dt=None, end_dt=None, event_names=None,
                                     username_filters=None, max_events=10000,
                                     log=lambda m, l="info": logs.append(m), is_cancelled_func=None)
        users = [a["AttributeValue"] for a in trail.calls if a["AttributeKey"] == "Username"]
        self.assertEqual(sorted(set(users)), ["alice", "jane@corp"])
        names = [e.get("eventName") for e in out]
        self.assertEqual(sum(n.startswith("List") and n != "ListBuckets" for n in names), 30)
        self.assertNotIn("DescribeInstances", names)
        self.assertNotIn("ListBuckets", names)
        self.assertEqual(names.count("CreateUser"), 1)                  # alice's write not doubled
        # light mode: no reads at all
        trail.calls = []
        ct._collect_for_region(client=trail, region="r", start_dt=None, end_dt=None, event_names=None, username_filters=None,
                               max_events=10000, log=lambda m, l="info": None, is_cancelled_func=None, include_reads=False)
        self.assertFalse([a for a in trail.calls if a["AttributeKey"] == "Username"])


class ARolesPollingIsNotCollectedForPersonOnlyReads(unittest.TestCase):
    """A security integration read 1,500 SES identity lists in one scan (2026-10-26);
    the SES rules judge people only -- the role's copies were 1,500 rows of noise."""

    def test_it(self):
        import json
        t = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)
        role = {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/reader/s1"}
        alice = {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::1:user/alice"}

        def ev(i, ui, user):
            return {"EventId": f"q{i}", "EventName": "ListIdentities", "Username": user, "EventTime": t, "ReadOnly": "true",
                    "CloudTrailEvent": json.dumps({"eventName": "ListIdentities", "userIdentity": ui})}
        trail = FakeTrail()
        trail.events = [ev(i, role, "s1") for i in range(600)] + [ev(1000, alice, "alice")]
        out = ct._collect_for_region(client=trail, region="r", start_dt=None, end_dt=None, event_names=None,
                                     username_filters=None, max_events=10000, log=lambda m, l="info": None,
                                     is_cancelled_func=None)
        got = [e for e in out if e.get("eventName") == "ListIdentities"]
        self.assertEqual([e["userIdentity"]["type"] for e in got], ["IAMUser"], "the person's read, past 600 role reads")


class FullModeDoesNotCollectTwice(unittest.TestCase):
    def test_cloudtrail_is_collected_once_in_both_modes(self):
        from services.aws import collectors
        for mode, want_in, want_out in (("full", {"cloudtrail_full"}, {"cloudtrail_console", "cloudtrail_iam"}),
                                        ("light", {"cloudtrail_full"}, {"cloudtrail_console", "cloudtrail_iam"})):
            asked = []
            orig = collectors._stub_collect
            collectors._stub_collect = lambda source, *a, **k: asked.append(source) or []
            try:
                collectors.collect_aws_logs("r1", sources=["cloudtrail_console", "cloudtrail_iam", "cloudtrail_full"],
                                            aws_config={"access_key_id": "x", "secret_access_key": "y"},
                                            cloudtrail_mode=mode, log_func=lambda *a, **k: None)
            finally:
                collectors._stub_collect = orig
            self.assertTrue(want_in <= set(asked), (mode, asked))
            self.assertFalse(want_out & set(asked), (mode, asked))


if __name__ == "__main__":
    unittest.main()
