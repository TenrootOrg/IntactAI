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
# Bound at import: test_autofuse installs a fake llm_sim in sys.modules and never
# removes it, so a lookup at test time can get the fake.
from services.fusion import llm_sim as _LLM_SIM  # noqa: E402


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


_ID_BY_TITLE = {"Shared binary seen on 2 hosts": "f_old", "Suspicious service path": "f_mid", "Mimikatz": "f_high"}


def _ids(payload, key="findings"):
    # payloads name findings by title; ids are internal and are not sent
    return {_ID_BY_TITLE[f["title"]] for f in payload[key]}


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


class FullContextChat(unittest.TestCase):
    """The case setting "send the full case to chat" sends the report's budgeted
    summary, which collapses findings and drops what does not fit."""

    def _payload(self, question, validations=None):
        import json
        from unittest import mock
        llm_sim = _LLM_SIM
        seen = {}
        with mock.patch.object(llm_sim, "_real_llm", lambda s, u, **k: seen.setdefault("u", u) or "ok"), \
             mock.patch.object(llm_sim, "_use_real", lambda: True):
            llm_sim.chat(_graph(), question, full_context=True, require_llm=True,
                         validations=validations, excluded_hosts=["DESKTOP-16OJFO6"])
        return json.loads(seen["u"].split("\n\n")[0])

    def test_the_question_findings_and_extent_are_added(self):
        p = self._payload("any malicious binary on 2024-05-24?",
                          validations=[{"finding_id": "f_mid", "status": "true_positive"}])
        ids = _ids(p, "findings_this_question_is_about")
        # a verdicted finding gets micro details only when the question is about verdicts
        self.assertEqual(ids, {"f_old"})
        self.assertEqual(p["case_evidence_span"][0], "2024-05-24T17:49:46Z")
        self.assertEqual(p["hosts_excluded_from_analysis_by_operator"], ["DESKTOP-16OJFO6"])


if __name__ == "__main__":
    unittest.main()


class ReadableForTheAnalyst(unittest.TestCase):
    """Verdicts by title/time/host, not id; the binary's name and path in the finding."""

    def test_verdicts_name_the_finding_and_carry_no_ids(self):
        import json
        g = _graph()
        ctx = _LLM_SIM.analyst_context(validations=[{"finding_id": "f_old", "status": "true_positive",
                                                     "watermark": "1|2024-05-24T17:49:46Z"}], graph=g)
        v = ctx["analyst_verdicts"][0]
        self.assertEqual((v["finding"], v["verdict"]), ("Shared binary seen on 2 hosts", "true_positive"))
        blob = json.dumps(ctx)
        self.assertNotIn("f_old", blob)
        self.assertNotIn("watermark", blob)

    def test_the_binary_name_and_path_come_with_the_finding(self):
        g = _graph()
        h = "9b" * 32
        g.upsert(schema.Entity(id="ioc:hash:" + h, type="ioc", label=h,
                               attrs={"full_hash": h, "source_name": "peview.exe", "_assets": ["asset:a"]}))
        g.upsert(schema.Entity(id="event:1", type="event", label="rename",
                               attrs={"full_hash": h, "name": "peview.exe",
                                      "path": r"C:\Users\kobia\Downloads\amd64\peview.exe", "_assets": ["asset:a"]}))
        f = g.findings[0]
        f.entity_ids = ["ioc:hash:" + h]
        d = render.finding_detail(g, f, "true_positive")
        paths = [x.get("path") for x in d["evidence_details"]]
        self.assertIn(r"C:\Users\kobia\Downloads\amd64\peview.exe", paths)
        self.assertEqual(d["analyst_verdict"], "true_positive")
        self.assertNotIn("id", d)

    def test_old_verdict_codes_are_translated_on_read(self):
        from unittest import mock
        from services.fusion import store
        run = {"automation_type": store.CASE_TYPE,
               "details": {"timeline_validations": [{"finding_id": "x", "status": "real"},
                                                     {"finding_id": "y", "status": "not_real"}],
                           "manual_timeline_events": [{"finding_id": "m", "status": "known_it"}]}}
        ws = mock.Mock(); ws.get_automation_run.return_value = run
        with mock.patch.object(store, "_ws", return_value=ws):
            d = store.get_case("c")
        self.assertEqual([v["status"] for v in d["timeline_validations"]], ["true_positive", "false_positive"])
        self.assertEqual(d["manual_timeline_events"][0]["status"], "known")



class MicroSelection(unittest.TestCase):
    """MACRO for the whole case, MICRO (evidence details) only for what the question is about."""

    def _g(self):
        g = _graph()
        g.upsert(schema.Entity(id="asset:b", type="asset", label="ALClient04", attrs={"hostname": "ALClient04"}))
        g.upsert(schema.Entity(id="ev:1", type="event", label="rename",
                               attrs={"name": "peview.exe", "path": r"C:\Users\srv\peview.exe", "_assets": ["asset:b"]}))
        g.findings.append(schema.Finding(id="f_pe", title="Renamed binary", severity="medium", confidence="high",
                                         summary="", entity_ids=["ev:1"], asset_ids=["asset:b"],
                                         ts="2025-06-01T00:00:00Z"))
        return g

    def _pick(self, q, ctx="", **k):
        g = self._g()
        return {f.id for f in render.question_findings(g.findings, q, graph=g, context_text=ctx, **k)}

    def test_a_host_named_in_the_question(self):
        self.assertEqual(self._pick("what happened on alclient04?"), {"f_pe"})

    def test_a_file_named_in_the_question(self):
        self.assertEqual(self._pick("where did peview.exe run"), {"f_pe"})

    def test_a_follow_up_uses_the_previous_exchange(self):
        self.assertEqual(self._pick("and what was its path?"), set())
        self.assertEqual(self._pick("and what was its path?", ctx="assistant: peview.exe was renamed"), {"f_pe"})

    def test_verdicts_only_when_asked_about(self):
        self.assertEqual(self._pick("summarize", also_finding_ids=["f_mid"]), set())
        self.assertEqual(self._pick("what did I mark true positive?", also_finding_ids=["f_mid"]), {"f_mid"})

    def test_capped_most_severe_first(self):
        g = self._g()
        for n in range(30):
            g.findings.append(schema.Finding(id="x%d" % n, title="t", severity="low" if n else "critical",
                                             confidence="high", summary="", asset_ids=["asset:b"], ts="2025-01-01"))
        out = render.question_findings(g.findings, "alclient04", graph=g, limit=15)
        self.assertEqual(len(out), 15)
        self.assertEqual(out[0].severity, "critical")


class EveryKindOfDataSelects(unittest.TestCase):
    """Measured on a live case: hashes (full, first 8), md5, sha1, IP, domain, event id,
    MITRE id, DOMAIN\\\\user, file, and dates in ISO, 16/06/2026, 16.06.2026 and
    'June 16, 2026' forms, and months, all 100% precise and complete."""

    def _g(self):
        g = schema.FusionGraph(case_id="c")
        g.upsert(schema.Entity(id="asset:a", type="asset", label="HOSTA"))
        h = "ab12cd34" + "0" * 56
        rows = [("f_mail", "Phishing mail", {"sender": "attacker@evil.example"}, "2026-06-16T10:00:00Z"),
                ("f_hash", "Dropped binary", {"full_hash": h, "name": "drop.exe"}, "2026-06-17T10:00:00Z"),
                ("f_srv", "Service created", {"name": "srvhost.exe"}, "2026-07-01T10:00:00Z")]
        for fid, title, attrs, ts in rows:
            g.upsert(schema.Entity(id="e:" + fid, type="event", label=title, attrs=dict(attrs, _assets=["asset:a"])))
            g.findings.append(schema.Finding(id=fid, title=title, severity="high", confidence="high", summary="",
                                             entity_ids=["e:" + fid], asset_ids=["asset:a"], ts=ts, mitre=["T1566"] if fid == "f_mail" else []))
        return g

    def _pick(self, q):
        g = self._g()
        return {f.id for f in render.question_findings(g.findings, q, graph=g)}

    def test_email(self):
        self.assertEqual(self._pick("did attacker@evil.example send anything?"), {"f_mail"})

    def test_hash_prefix(self):
        self.assertEqual(self._pick("what is ab12cd34?"), {"f_hash"})

    def test_whole_words_only(self):
        self.assertEqual(self._pick("what did srv do?"), set())          # not "srvhost.exe"

    def test_mitre_id(self):
        self.assertEqual(self._pick("anything for T1566?"), {"f_mail"})

    def test_date_formats(self):
        for q in ("what happened on 2026-06-16?", "on 16/06/2026", "on 16.06.2026",
                  "what happened June 16, 2026?", "16 June 2026"):
            self.assertEqual(self._pick(q), {"f_mail"}, q)
        self.assertEqual(self._pick("what happened in June 2026?"), {"f_mail", "f_hash"})
