"""Chat must be sent what the analyst's question is about.

Live: "was any malicious binary on 2024-05-24 validated as true positive?" The
finding (medium, 2024-05-24) and its True Positive verdict existed, but chat only
sent >=high findings plus name matches, so the model saw the verdict without its
finding and said the evidence started in 2025.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402


def _graph():
    g = schema.FusionGraph(case_id="c")
    g.upsert(schema.Entity(id="asset:a", type="asset", label="ALClient06"))
    g.findings = [
        schema.Finding(id="f_old", title="Shared binary seen on 2 hosts", severity="medium",
                       confidence="high", summary="", asset_ids=["asset:a"], ts="2024-05-24T17:49:46Z"),
        schema.Finding(id="f_mid", title="Suspicious service path", severity="medium",
                       confidence="high", summary="", asset_ids=["asset:a"], ts="2025-03-10T13:34:06Z"),
        schema.Finding(id="f_high", title="Mimikatz", severity="high",
                       confidence="high", summary="", asset_ids=["asset:a"], ts="2026-06-14T09:00:00Z"),
    ]
    return g


def _ids(payload):
    return {f["id"] for f in payload["findings"]}


class ChatContext(unittest.TestCase):
    def test_a_date_in_the_question_brings_that_days_findings(self):
        p = render.chat_subgraph(_graph(), "any malicious binary on 2024-05-24?")
        self.assertIn("f_old", _ids(p))
        self.assertNotIn("f_mid", _ids(p))

    def test_a_month_works_too(self):
        self.assertIn("f_mid", _ids(render.chat_subgraph(_graph(), "what happened in 2025-03")))

    def test_verdicted_findings_are_always_sent(self):
        p = render.chat_subgraph(_graph(), "anything confirmed?", also_finding_ids=["f_old"])
        self.assertIn("f_old", _ids(p))

    def test_the_real_evidence_span_is_sent(self):
        p = render.chat_subgraph(_graph(), "hello")
        self.assertEqual(p["case_evidence_span"][0], "2024-05-24T17:49:46Z")
        self.assertEqual(p["case_findings_total"], 3)


if __name__ == "__main__":
    unittest.main()
