"""Log data attached to a case (SIEM / firewall / EDR / IdP exports) is read
without a parser per vendor, and joins the case only where it meets it.

Executed against the real code: services/fusion/external_logs.py (shapes, column
detection, the model fallback), mappers/external.py and correlate.assemble.
"""
import gzip
import json
import os
import sys
import tempfile
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, external_logs as X, schema  # noqa: E402
from services.fusion.mappers.external import map_external  # noqa: E402

ELASTIC = json.dumps({"hits": {"hits": [{"_source": {
    "@timestamp": "2026-10-01T10:00:00Z", "host": {"name": "WS01"}, "user": {"name": "CORP\\jdoe"},
    "source": {"ip": "10.0.0.5"}, "destination": {"ip": "185.220.101.4", "port": 443},
    "event": {"action": "allowed", "severity": 3}}}]}})
OKTA = "\n".join(json.dumps({"published": f"2026-10-01T10:0{i}:00Z", "actor": {"alternateId": "jdoe@corp.com"},
                             "client": {"ipAddress": "185.220.101.4"}, "eventType": "user.session.start",
                             "outcome": {"result": "FAILURE"}, "severity": "WARN"}) for i in range(5))
DEFENDER = ("Timestamp,DeviceName,AccountName,FileName,SHA256,ProcessCommandLine,AlertTitle,Severity\n"
            "2026-10-01T10:05:00Z,WS01,CORP\\jdoe,mimi.exe," + "a" * 64
            + ",mimi.exe sekurlsa::logonpasswords,Credential dumping,High\n"
            "2026-10-01T10:06:00Z,WS01,CORP\\jdoe,cmd.exe," + "b" * 64 + ",cmd /c whoami,Recon,Low\n")
CEF = ("Oct  1 10:00:00 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|Command and Control Traffic|8|"
       "rt=2026-10-01T10:00:00Z src=10.0.0.5 dst=185.220.101.4 suser=CORP\\jdoe dhost=evil-c2.com act=alert\n") * 3
LEEF = ("LEEF:1.0|Microsoft|MSExchange|2016|15345|src=10.50.1.1\tdst=2.10.20.20\tsev=5"
        "\tdevTime=2026-10-01T10:00:00Z\tusrName=CORP\\jdoe\n") * 3
FORTI = "\n".join(f'date=2026-10-01 time=10:0{i}:00 devname="FG100" srcip=10.0.0.5 dstip=185.220.101.{i} '
                  f'action="deny" user="jdoe" level="warning"' for i in range(4))
FREE = ("2026-10-01 10:00:01 sshd[311]: Failed password for CORP\\jdoe from 185.220.101.4 port 22 ssh2\n"
        "service restarted\n"
        "2026-10-01 10:00:09 sshd[311]: Accepted password for CORP\\jdoe from 185.220.101.4 port 22 ssh2\n")


def _read(text):
    fmt, rows = X.parse(text)
    m = X.detect_columns(rows) if rows else {}
    return fmt, m, (X.normalize(rows, m) if rows else [])


class Shapes(unittest.TestCase):
    """One reader per SHAPE; the columns are found from the schemas' names."""

    def test_each_export_is_recognized_with_its_columns(self):
        for name, text, fmt, want in (
                ("elastic", ELASTIC, "json", {"ts": "@timestamp", "host": "host.name", "user": "user.name",
                                              "src_ip": "source.ip", "dst_ip": "destination.ip"}),
                ("okta", OKTA, "jsonl", {"ts": "published", "user": "actor.alternateId",
                                         "src_ip": "client.ipAddress", "rule": "eventType"}),
                ("okta alert", OKTA + "\n" + json.dumps({"published": "2026-10-01T10:09:00Z",
                                                         "displayMessage": "Password spray", "eventType": "x"}),
                 "jsonl", {"rule": "displayMessage"}),
                ("defender", DEFENDER, "csv", {"ts": "Timestamp", "host": "DeviceName", "hash": "SHA256",
                                               "rule": "AlertTitle", "severity": "Severity"}),
                ("cef", CEF, "cef", {"ts": "rt", "src_ip": "src", "dst_ip": "dst", "user": "suser",
                                     "domain": "dhost", "rule": "cefname"}),
                ("leef", LEEF, "leef", {"src_ip": "src", "dst_ip": "dst", "severity": "sev"}),
                ("fortigate", FORTI, "kv", {"ts": "date", "src_ip": "srcip", "dst_ip": "dstip"})):
            with self.subTest(name):
                got_fmt, m, rows = _read(text)
                self.assertEqual(fmt, got_fmt)
                for f, col in want.items():
                    self.assertEqual(col, m.get(f), (f, m))
                self.assertTrue(rows and rows[0]["n"])

    def test_values_are_normalized(self):
        _, m, rows = _read(DEFENDER)
        self.assertTrue(X.recognized(rows))
        self.assertEqual(["high", "low"], [r["n"]["severity"] for r in rows])
        self.assertEqual("2026-10-01T10:05:00", rows[0]["n"]["ts"][:19])
        _, _, rows = _read(CEF)
        self.assertEqual("high", rows[0]["n"]["severity"], "CEF 0..10: 8 is high")
        _, _, rows = _read(FORTI)
        self.assertEqual("2026-10-01T10:01:00", rows[1]["n"]["ts"][:19], "date + time columns joined")
        self.assertNotIn("severity", rows[0]["n"], "'warning' is an operational level, not an alert")
        _, _, rows = _read(OKTA)
        self.assertNotIn("severity", rows[0]["n"])

    def test_unknown_column_names_are_found_by_their_values(self):
        text = "when,who,peer,what\n" + "\n".join(
            f"2026-10-01T10:0{i}:00Z,CORP\\u{i},185.220.101.{i},x" for i in range(5))
        _, m, _ = _read(text)
        self.assertEqual({"ts": "when", "user": "who", "src_ip": "peer"}, {k: m[k] for k in ("ts", "user", "src_ip")})

    def test_gzip_and_utf16_are_read(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "a.gz")
        with gzip.open(p, "wb") as f:
            f.write(DEFENDER.encode())
        self.assertEqual(DEFENDER, X.read_text(p))
        p2 = os.path.join(d, "b.csv")
        with open(p2, "wb") as f:
            f.write(DEFENDER.encode("utf-16"))
        self.assertEqual(DEFENDER, X.read_text(p2))

    def test_free_text_is_not_a_structure(self):
        self.assertEqual(("", []), X.parse(FREE))


class FreeText(unittest.TestCase):
    """Not recognized -> the case's model reads it, and nothing it says is kept
    unless the line it cites says it too. No model -> indicator lines."""

    def test_without_a_model_lines_with_indicators_are_kept(self):
        rows = X.indicator_rows(FREE.splitlines())
        self.assertEqual([1, 3], [r["raw"]["line"] for r in rows])
        self.assertEqual(["185.220.101.4"], rows[0]["n"]["ips"])
        self.assertEqual(["CORP\\jdoe"], rows[0]["n"]["users"])
        self.assertEqual("2026-10-01T10:00:01", rows[0]["n"]["ts"][:19])

    def _fake(self, answer, seen):
        def call(system, user):
            seen.append(user)
            return json.dumps(answer)
        return call

    def test_the_model_cannot_add_what_the_line_does_not_say(self):
        seen = []
        answer = [{"line": 1, "ts": "2026-10-01T10:00:01", "user": "CORP\\jdoe", "src_ip": "185.220.101.4",
                   "host": "DC01", "rule": "failed login", "severity": "high"},
                  {"line": 99, "user": "CORP\\jdoe"},
                  {"line": 2, "host": "WEB7"}]
        rows, st = X.llm_extract(FREE.splitlines(), call=self._fake(answer, seen))
        self.assertEqual(1, len(rows))
        n = rows[0]["n"]
        self.assertEqual(("CORP\\jdoe", "185.220.101.4"), (n["user"], n["src_ip"]))
        self.assertNotIn("host", n, "DC01 is not in the line")
        self.assertNotIn("severity", n, "the line states no severity")
        self.assertEqual("2026-10-01T10:00:01", n["ts"][:19])
        self.assertEqual((2, 1), (st["dropped"], st["values_dropped"]))
        self.assertTrue(seen[0].startswith("L1: "), "lines are numbered for citing")

    def test_masked_text_goes_out_and_answers_come_back_unmasked(self):
        from services.data_anonymizer import DataAnonymizer
        from services.fusion import investigate
        mask = DataAnonymizer()
        text = "2026-10-01 10:00:01 login failed for CORP\\jdoe from 10.20.30.40 on host DESKTOP-ABC123\n"
        seen = []

        def call(system, user):
            seen.append(user)
            # the model answers in the masked vocabulary it was shown: the words
            # after "for" and "from" in the line it got
            words = user.split()
            return json.dumps([{"line": 1, "user": words[words.index("for") + 1],
                                "src_ip": words[words.index("from") + 1]}])
        rows, _ = X.llm_extract(text.splitlines(), call=call, mask=mask,
                                revert=lambda o: investigate._revert_obj(o, mask))
        for secret in ("jdoe", "10.20.30.40", "DESKTOP-ABC123"):
            self.assertNotIn(secret, seen[0])
        self.assertEqual(("CORP\\jdoe", "10.20.30.40"), (rows[0]["n"]["user"], rows[0]["n"]["src_ip"]))


class IngestAndSearch(unittest.TestCase):
    """The run writes its rows where fusion and evidence drill-down read a run's
    rows; chat's logs() tool searches them, including rows not in the graph."""

    def setUp(self):
        from unittest import mock
        self.tmp = tempfile.mkdtemp()
        self.p = [mock.patch.object(X, "downloads_dir", lambda rid: os.path.join(self.tmp, rid))]
        for p in self.p:
            p.start()
        self.logs = []

    def tearDown(self):
        for p in self.p:
            p.stop()

    def _ingest(self, text, model=None, name="f.log"):
        from unittest import mock
        src = os.path.join(self.tmp, name)
        with open(src, "w") as f:
            f.write(text)
        with mock.patch.object(X, "_model", lambda *a: model):
            s = X.ingest("c", "external_log_1", src, "edr", lambda m, l="info": self.logs.append(m))
        with open(os.path.join(self.tmp, "external_log_1", "raw_results.json")) as f:
            return s, json.load(f)["External.edr"]

    def test_a_recognized_export_is_parsed(self):
        s, rows = self._ingest(DEFENDER)
        self.assertEqual(("parser", 2, 1), (s["via"], s["rows"], s["alerts"]))
        self.assertEqual("WS01", rows[0]["n"]["host"])
        self.assertEqual("mimi.exe", rows[0]["raw"]["FileName"], "the original row is kept for evidence")

    def test_free_text_with_no_model_keeps_indicator_lines(self):
        s, rows = self._ingest(FREE)
        self.assertEqual(("indicators", 2), (s["via"], s["rows"]))

    def test_a_failing_model_still_keeps_the_file(self):
        def boom(system, user):
            raise RuntimeError("provider down")
        s, rows = self._ingest(FREE, model=(boom, None, None))
        self.assertEqual(("indicators", 2), (s["via"], s["rows"]))
        self.assertTrue(any("could not read them" in m for m in self.logs), self.logs)

    def test_the_model_reads_what_no_parser_understood(self):
        call = lambda system, user: json.dumps([{"line": 3, "user": "CORP\\jdoe", "src_ip": "185.220.101.4",
                                                 "rule": "accepted password"}])
        s, rows = self._ingest(FREE, model=(call, None, None))
        self.assertEqual(("llm", 1), (s["via"], s["rows"]))
        self.assertEqual(3, rows[0]["raw"]["line"])

    def test_chat_search_reads_the_rows(self):
        from unittest import mock
        self._ingest(DEFENDER)
        runs = [{"run_id": "external_log_1", "automation_type": "external_log",
                 "details": {"file_name": "alerts.csv", "data_type": "edr", "use_in_analysis": True}}]
        from services.fusion import store
        load = lambda rid, det, log=None: json.load(open(os.path.join(self.tmp, rid, "raw_results.json")))
        with mock.patch("services.workflow_service.get_automation_runs_by_case", lambda cid: runs), \
                mock.patch.object(store, "_agentic_collected_data", load):
            r = X.search("c", "sekurlsa ws01")
            self.assertEqual((1, "alerts.csv", "WS01"), (r["total_matches"], r["files"][0], r["rows"][0]["host"]))
            from services.fusion import keys
            r = X.search("c", "ws01", lo=keys.to_utc_dt("2026-10-01T10:05:30Z"))
            self.assertEqual(1, r["total_matches"], "the time window applies")
            runs[0]["details"]["use_in_analysis"] = False
            self.assertEqual(0, X.search("c", "ws01")["total_matches"], "a switched-off log is not searched")


ENDPOINT = "asset:endpoint:C.1"


def _fuse(external_rows, data_type="edr"):
    ext = map_external({X.artifact_name(data_type): external_rows}, run_id="external_log_1",
                       data_type=data_type, label="export.csv")
    endpoint = ([schema.Entity(id=ENDPOINT, type="asset", label="WS01", attrs={"hostname": "WS01"},
                               sources=["velociraptor"]),
                 schema.Entity(id="ioc:ip:185.220.101.4", type="ioc", label="185.220.101.4",
                               attrs={"_assets": [ENDPOINT], "ioc_kind": "ip"}, sources=["velociraptor"])], [])
    return correlate.assemble("c", [endpoint, ext], ["r1", "external_log_1"])


class Fusion(unittest.TestCase):

    def test_a_vendor_alert_is_a_finding_on_the_case_host(self):
        _, m, rows = _read(DEFENDER)
        g = _fuse(rows)
        f = [f for f in g.findings if "Credential dumping" in f.title]
        self.assertEqual(1, len(f), [x.title for x in g.findings])
        self.assertEqual([ENDPOINT], f[0].asset_ids, "WS01 in the log is the case's WS01")
        self.assertEqual("high", f[0].severity)
        self.assertFalse([x for x in g.findings if "Recon" in x.title], "a Low row is not an alert")
        self.assertIn("ioc:hash:" + "a" * 64, g.entities, "the alert's hash stays (the alert is about it)")

    def test_only_what_meets_the_case_stays(self):
        rows = [{"n": {"ts": "2026-10-01T10:00:00", "src_ip": "10.0.0.5", "dst_ip": f"185.220.{i}.9"}, "raw": {}}
                for i in range(1, 60)]
        rows.append({"n": {"ts": "2026-10-01T10:00:00", "src_ip": "10.0.0.5", "dst_ip": "185.220.101.4"},
                     "raw": {}})
        g = _fuse(rows, "firewall")
        ioc = g.entities.get("ioc:ip:185.220.101.4")
        self.assertIsNotNone(ioc)
        self.assertEqual({"velociraptor", "external"}, set(ioc.sources), "seen by both: one node")
        self.assertEqual([ENDPOINT], ioc.attrs["_assets"], "the firewall is not a second host")
        self.assertNotIn("ioc:ip:185.220.7.9", g.entities, "only in the log: searchable, not a node")
        self.assertFalse([e for e in g.entities if e.startswith("asset:log_source:")],
                         "a log source with nothing left on it is not shown as a host")
        self.assertFalse([f for f in g.findings if f.kind == "cross_host"])

    def test_an_alert_naming_no_host_sits_on_the_log_source(self):
        rows = [{"n": {"ts": "2026-10-01T10:00:00", "user": "jdoe@corp.com", "src_ip": "185.220.101.4",
                       "rule": "Impossible travel", "severity": "high"}, "raw": {}}]
        g = _fuse(rows, "idp")
        f = [f for f in g.findings if "Impossible travel" in f.title]
        self.assertEqual(["asset:log_source:external_log_1"], f[0].asset_ids)
        self.assertIn("account:domain:corp\\jdoe", g.entities)


if __name__ == "__main__":
    unittest.main()
