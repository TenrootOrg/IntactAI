"""OpenCanary honeypot events reach Sigma's 24 OpenCanary rules, the right way round.

The 2026-10-20 severity audit: OpenCanary's JSON was read, but no row had the
opencanary log source (24 HIGH rules, one per logtype), and the shape pass took
src_host for the destination and dst_host for the source -- the intruder landed
on the honeypot's side. Rule bodies: SigmaHQ rules/application/opencanary/.
"""
import json
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402


def rule(title, logtype):
    return S.compile_rule({"title": title, "id": title, "level": "high",
                           "logsource": {"category": "application", "product": "opencanary"},
                           "detection": {"selection": {"logtype": logtype}, "condition": "selection"}})


RULES = [rule("OpenCanary - SSH Login Attempt", 4002), rule("OpenCanary - Host Port Scan (SYN Scan)", 5001)]


def event(logtype, port, **logdata):
    # opencanary.readthedocs.io "Log format": one JSON object per line
    return {"dst_host": "10.0.0.50", "dst_port": port, "local_time": "2026-10-01 10:05:00.123456",
            "local_time_adjusted": "2026-10-01 12:05:00.123456", "logdata": logdata, "logtype": logtype,
            "node_id": "opencanary-1", "src_host": "203.0.113.9", "src_port": 51234,
            "utc_time": "2026-10-01 10:05:00.123456"}


def ingest(text):
    _fmt, rows, _left = X.read(text)
    out = X.normalize(rows, X.detect_columns(rows))
    return [(r["n"], [h["title"] for h in S.evaluate(X.sigma_event(r["raw"]), RULES)]) for r in out]


class OpenCanary(unittest.TestCase):
    def test_honeypot_events_fire_high(self):
        got = ingest("\n".join(json.dumps(e) for e in (
            event(4002, 22, USERNAME="root", PASSWORD="admin123"),
            event(5001, 445),
            event(1001, 0))))                                  # 1001: the canary started -- no rule
        self.assertEqual([["OpenCanary - SSH Login Attempt"], ["OpenCanary - Host Port Scan (SYN Scan)"], []],
                         [t for _n, t in got])

    def test_the_intruder_is_the_source(self):
        n = ingest(json.dumps(event(4002, 22, USERNAME="root")))[0][0]
        self.assertEqual(("203.0.113.9", "10.0.0.50", "22", "root"),
                         (n.get("src_ip"), n.get("dst_ip"), n.get("dst_port"), n.get("user")))

    def test_a_host_named_src_host_is_not_an_ip(self):
        # Other products write a host NAME there: the IP field must not take it.
        rows = [{"src_host": "WS01", "dst_host": "FS02", "event": "logon", "time": "2026-10-01T10:05:00Z"}]
        m = X.detect_columns(rows)
        self.assertNotIn(m.get("src_ip"), ("src_host",))
        self.assertNotIn(m.get("dst_ip"), ("dst_host",))


if __name__ == "__main__":
    unittest.main()
