"""Bitbucket's audit log reaches Sigma's Bitbucket rules (2 critical, 2 high).

The 2026-10-20 severity audit: an attached Bitbucket Data Center audit log was read
(its JSON flattened to auditType.action / auditType.category) but no row had a log
source the rules apply to, and the author was not taken as the user. Rule bodies
are SigmaHQ's rules/application/bitbucket/audit/, as shipped.
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


def rule(title, level, category, action):
    return S.compile_rule({"title": title, "id": title, "level": level,
                           "logsource": {"product": "bitbucket", "service": "audit"},
                           "detection": {"selection": {"auditType.category": category, "auditType.action": action},
                                         "condition": "selection"}})


RULES = [rule("Bitbucket Unauthorized Access To A Resource", "critical", "Security", "Unauthorized access to a resource"),
         rule("Bitbucket Unauthorized Full Data Export Triggered", "critical", "Data pipeline",
              "Unauthorized full data export triggered"),
         rule("Bitbucket Full Data Export Triggered", "high", "Data pipeline", "Full data export triggered")]


def event(action, category, who="jdoe", ip="203.0.113.9"):
    # Atlassian's audit record (Bitbucket log/audit/*.audit.log; REST /rest/auditing/1.0/events)
    return {"affectedObjects": [{"id": "1", "name": "payments", "type": "REPOSITORY"}],
            "auditType": {"action": action, "area": "SECURITY", "category": category, "level": "BASE"},
            "author": {"id": "5", "name": who, "type": "user"}, "changedValues": [], "method": "Browser",
            "source": ip, "system": "https://bitbucket.example.com", "timestamp": "2026-10-01T10:05:00.000Z"}


def ingest(text):
    _fmt, rows, _left = X.read(text)
    out = X.normalize(rows, X.detect_columns(rows))
    return [(r["n"], [h["title"] for h in S.evaluate(X.sigma_event(r["raw"]), RULES)]) for r in out]


class BitbucketAudit(unittest.TestCase):
    def test_the_critical_events_fire_with_who_and_from_where(self):
        lines = "\n".join(json.dumps(e) for e in (
            event("Unauthorized access to a resource", "Security", who="Anonymous"),
            event("Unauthorized full data export triggered", "Data pipeline"),
            event("Full data export triggered", "Data pipeline")))
        got = ingest(lines)
        self.assertEqual([["Bitbucket Unauthorized Access To A Resource"],
                          ["Bitbucket Unauthorized Full Data Export Triggered"],
                          ["Bitbucket Full Data Export Triggered"]], [t for _n, t in got])
        n = got[1][0]
        self.assertEqual(("jdoe", "203.0.113.9", "2026-10-01T10:05:00"), (n.get("user"), n.get("src_ip"), n.get("ts")))

    def test_the_rest_api_envelope_too(self):
        got = ingest(json.dumps({"entities": [event("Unauthorized access to a resource", "Security")]}))
        self.assertEqual([["Bitbucket Unauthorized Access To A Resource"]], [t for _n, t in got])

    def test_ordinary_audit_events_stay_quiet(self):
        got = ingest(json.dumps(event("User logged in", "Authentication")))
        self.assertEqual([[]], [t for _n, t in got])

    def test_an_unrelated_row_is_not_a_bitbucket_row(self):
        self.assertNotIn(("bitbucket", None, "audit"),
                         S.profiles(S.Event({"category": "Security", "action": "allow", "src_ip": "1.2.3.4"})))


if __name__ == "__main__":
    unittest.main()
