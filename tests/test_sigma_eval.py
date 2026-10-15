"""The Sigma engine that runs the community rules over attached log data.

Semantics checked with small rules (one per language feature), the row-shape
profiles that decide which rules run, and -- where /opt/sigma-rules is installed
-- every SigmaHQ regression event against the rule it was written for.
"""
import glob
import json
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import yaml  # noqa: E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402


def rule(detection, logsource=None, level="high"):
    return S.compile_rule({"title": "t", "id": "x", "level": level, "logsource": logsource or {"category": "proxy"},
                           "detection": detection})


def hit(r, row):
    ev = S.Event(row)
    res = S._Lazy(r["searches"], ev)
    return any(t(res) for t in r["trees"])


class Language(unittest.TestCase):

    def test_values_and_wildcards(self):
        r = rule({"sel": {"Image": "*\\cmd.exe"}, "condition": "sel"})
        self.assertTrue(hit(r, {"Image": "C:\\Windows\\System32\\CMD.EXE"}), "case-insensitive by default")
        self.assertFalse(hit(r, {"Image": "C:\\cmd.exe.bak"}), "whole value, not a substring")
        r = rule({"sel": {"x": "a?c"}, "condition": "sel"})
        self.assertTrue(hit(r, {"x": "abc"}))
        r = rule({"sel": {"x": "lit\\*"}, "condition": "sel"})
        self.assertTrue(hit(r, {"x": "lit*"}))
        self.assertFalse(hit(r, {"x": "literal"}), "an escaped * is a literal *")

    def test_modifiers(self):
        self.assertTrue(hit(rule({"s": {"c|contains": "\\sysvol\\"}, "condition": "s"}),
                            {"c": "findstr cpassword \\\\DC\\sysvol\\x.xml"}),
                        "a value ending in a backslash: the added wildcard must stay a wildcard")
        self.assertTrue(hit(rule({"s": {"c|contains|all": ["a", "b"]}, "condition": "s"}), {"c": "xbxa"}))
        self.assertFalse(hit(rule({"s": {"c|contains|all": ["a", "b"]}, "condition": "s"}), {"c": "xa"}))
        self.assertTrue(hit(rule({"s": {"c|startswith": "pow"}, "condition": "s"}), {"c": "PowerShell"}))
        self.assertTrue(hit(rule({"s": {"c|re": "^a.c$"}, "condition": "s"}), {"c": "abc"}))
        self.assertFalse(hit(rule({"s": {"c|re": "^A"}, "condition": "s"}), {"c": "abc"}), "re is cased")
        self.assertTrue(hit(rule({"s": {"c|re|i": "^A"}, "condition": "s"}), {"c": "abc"}))
        self.assertTrue(hit(rule({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"}), {"ip": "10.2.3.4"}))
        self.assertFalse(hit(rule({"s": {"ip|cidr": "10.0.0.0/8"}, "condition": "s"}), {"ip": "11.2.3.4"}))
        self.assertTrue(hit(rule({"s": {"c|windash|contains": " -enc "}, "condition": "s"}),
                            {"c": "powershell /enc AAA"}))
        import base64
        blob = base64.b64encode(b"xxIEX (New-Object Net.WebClient)").decode()
        self.assertTrue(hit(rule({"s": {"c|base64offset|contains": "IEX"}, "condition": "s"}), {"c": blob}))
        self.assertTrue(hit(rule({"s": {"n|gt": 5}, "condition": "s"}), {"n": "7"}))
        self.assertTrue(hit(rule({"s": {"a|exists": True}, "condition": "s"}), {"a": "x"}))
        self.assertTrue(hit(rule({"s": {"a|exists": False}, "condition": "s"}), {"b": "x"}))
        self.assertTrue(hit(rule({"s": {"a|fieldref": "b"}, "condition": "s"}), {"a": "1", "b": "1"}))
        self.assertTrue(hit(rule({"s": {"a": None}, "condition": "s"}), {"b": "x"}), "null = the field is missing")

    def test_conditions(self):
        det = {"sel_a": {"x": "1"}, "sel_b": {"y": "2"}, "filter": {"z": "3"},
               "condition": "1 of sel_* and not filter"}
        r = rule(det)
        self.assertTrue(hit(r, {"y": "2"}))
        self.assertFalse(hit(r, {"y": "2", "z": "3"}))
        r = rule({**det, "condition": "all of sel_*"})
        self.assertFalse(hit(r, {"x": "1"}))
        self.assertTrue(hit(r, {"x": "1", "y": "2"}))
        r = rule({**det, "condition": "(sel_a or sel_b) and not (filter)"})
        self.assertTrue(hit(r, {"x": "1"}))
        r = rule({**det, "condition": "1 of them"})
        self.assertTrue(hit(r, {"z": "3"}))

    def test_lists_and_keywords(self):
        r = rule({"s": [{"a": "1"}, {"b": "2"}], "condition": "s"})
        self.assertTrue(hit(r, {"b": "2"}), "a list of maps is OR")
        r = rule({"kw": ["Failed password", "*reverse*shell*"], "condition": "kw"})
        self.assertTrue(hit(r, {"_text": "sshd: Failed password for root"}))
        self.assertTrue(hit(r, {"msg": "a reverse bash shell opened"}))

    def test_what_cannot_be_evaluated_exactly_is_skipped(self):
        for det in ({"s": {"a|expand": "%x%"}, "condition": "s"},
                    {"s": {"a": "1"}, "condition": "s | count() by b > 5"},
                    {"s": {"a|weirdmod": "1"}, "condition": "s"}):
            with self.assertRaises(S.Unsupported):
                rule(det)

    def test_field_lookup(self):
        ev = S.Event({"Event.EventData.Image": "x", "Threat Name": "EICAR", "NewProcessName": "C:\\a.exe"})
        self.assertEqual("x", ev.get("Image"))
        self.assertEqual("EICAR", ev.get("ThreatName"))
        self.assertEqual("C:\\a.exe", S.Event({"NewProcessName": "C:\\a.exe"}).get("Image"), "4688 spelling")
        self.assertEqual("Microsoft-Windows-Eventlog", S.Event({"Provider": "Microsoft-Windows-Eventlog"}).get("Provider_Name"),
                         "event XML's Provider is what 86 SigmaHQ rules call Provider_Name")


class WhichRulesRun(unittest.TestCase):

    def test_profiles(self):
        P = S.profiles
        self.assertIn(("windows", "process_creation", "sysmon"),
                      P({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Image": "a"}))
        self.assertIn(("windows", "process_creation", "security"), P({"EventID": 4688, "Channel": "Security"}))
        self.assertIn(("okta", None, "okta"), P({"eventType": "x", "actor.alternateId": "a@b.c"}))
        self.assertIn((None, "proxy", None), P({"url": "http://x.com/a", "useragent": "curl"}))
        self.assertNotIn((None, "proxy", None), P({"cs-uri-stem": "/a", "sc-status": "200", "cs-method": "GET",
                                                    "cs(User-Agent)": "x"}),
                         "a web server log is no proxy log")
        self.assertIn((None, "webserver", None), P({"cs-uri-stem": "/a", "sc-status": "200"}))
        self.assertIn(("windows", "process_creation", None),
                      P({"ProcessCommandLine": "cmd /c x", "FolderPath": "C:\\Windows\\cmd.exe"}),
                      "EDR process telemetry")
        self.assertEqual(set(), P({"foo": "bar"}))
        lin = P({"EventID": "1", "Channel": "Linux-Sysmon/Operational", "Provider": "Linux-Sysmon",
                 "Image": "/bin/dd", "CommandLine": "dd of=/dev/sda if=/dev/zero"})
        self.assertIn(("linux", "process_creation", "sysmon"), lin, "Sysmon for Linux is Linux")
        ocsf = {"metadata.product.name": "CloudTrail", "api.operation": "StopLogging",
                "api.service.name": "cloudtrail.amazonaws.com", "api.response.error": ""}
        self.assertIn(("aws", None, "cloudtrail"), P(ocsf), "CloudTrail as OCSF (Security Lake)")
        self.assertEqual("StopLogging", S.Event(ocsf).get("eventName"))
        self.assertEqual("cloudtrail.amazonaws.com", S.Event(ocsf).get("eventSource"))
        oq = {"name": "es_process_events", "columns.event_type": "exec", "columns.path": "/sbin/kextload",
              "columns.cmdline": "kextload /tmp/evil.kext"}
        self.assertIn(("macos", "process_creation", None), P(oq), "osquery EndpointSecurity")
        self.assertEqual("/sbin/kextload", S.Event(oq).get("Image"))
        self.assertEqual("kextload /tmp/evil.kext", S.Event(oq).get("CommandLine"))
        self.assertFalse([p for p in lin if p[0] == "windows"], lin)

    def test_a_proxy_rule_never_fires_on_another_products_fields(self):
        r = {**rule({"s": {"c-useragent": "curl*"}, "condition": "s"}), "product": None, "category": "proxy"}
        self.assertEqual([], S.evaluate({"eventType": "x", "actor.alternateId": "a@b.c", "c-useragent": "curl/8"},
                                        [r]))


class NoisyRulesAreContext(unittest.TestCase):
    def test_a_listed_rule_loads_low_and_out_of_bursts(self):
        import tempfile, textwrap
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "r.yml"), "w") as f:
            f.write(textwrap.dedent("""\
                title: Noisy
                id: 11111111-2222-3333-4444-555555555555
                level: medium
                logsource: {category: proxy}
                detection: {sel: {c-uri: '*x*'}, condition: sel}
            """))
        dl = os.path.join(d, "demote.yaml")
        with open(dl, "w") as f:
            f.write('11111111-2222-3333-4444-555555555555: "noisy"\n')
        from unittest import mock
        with mock.patch.object(S, "DEMOTE", dl):
            S._CACHE["key"] = None
            r = S.load(dirs=(d,))["rules"][0]
        S._CACHE["key"] = None
        self.assertEqual(("low", False), (r["level"], r["burst"]))

    def test_a_context_hit_is_not_counted_toward_a_burst(self):
        from unittest import mock
        r = rule({"sel": {"c-uri": "*x*"}, "condition": "sel"}, level="low")
        r["burst"] = False
        out = [{"n": {}, "raw": {"c-uri": "/x", "cs-method": "GET"}}]
        with mock.patch.object(S, "load", return_value={"rules": [r]}):
            X.sigma_pass(out)
        self.assertEqual(["sigma (context): t"], out[0]["n"]["detected_by"])


class SuricataHttp(unittest.TestCase):
    """Suricata writes HTTP as http.url / http.http_method / http.status: the web
    rules named none of them, so no SigmaHQ or Splunk web rule saw Suricata."""
    EVE = {"event_type": "http", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9",
           "http": {"hostname": "wiki", "url": "/template/aui/text-inline.vm", "http_method": "POST",
                    "http_user_agent": "python-requests/2.31", "status": 200}}

    def test_a_web_server_rule_matches_suricata_http(self):
        r = S.compile_rule({"title": "t", "id": "x", "level": "high", "logsource": {"category": "webserver"},
                            "detection": {"sel": {"cs-uri-query|contains": "/template/aui/text-inline.vm",
                                                  "cs-method": "POST", "sc-status": [200, 202]},
                                          "condition": "sel"}})
        self.assertTrue(S.evaluate(X._flat(self.EVE), [r], {}))


class WebUrlParts(unittest.TestCase):
    """nginx (uri_path, uri_query) and IIS (cs-uri-stem, cs-uri-query) split the URL;
    a rule on the whole URL never matched them."""
    def fires(self, row):
        r = S.compile_rule({"title": "t", "id": "x", "level": "high", "logsource": {"category": "web"},
                            "detection": {"sel": {"c-uri": "*.jsp?cmd=*", "cs-method": "GET"},
                                          "condition": "sel"}})
        return bool(S.evaluate(row, [r], {}))

    def test_nginx_path_and_query(self):
        self.assertTrue(self.fires({"uri_path": "/shell.jsp", "uri_query": "cmd=whoami", "http_method": "GET",
                                    "status": "500", "src_ip": "73.245.172.254"}))

    def test_iis_stem_and_query(self):
        self.assertTrue(self.fires({"cs-uri-stem": "/shell.jsp", "cs-uri-query": "cmd=id", "cs-method": "GET",
                                    "sc-status": "200", "c-ip": "10.0.0.1"}))

    def test_a_firewall_url_log_is_web_too(self):
        self.assertTrue(self.fires({"url": "gw.example.com/shell.jsp?cmd=id", "http_method": "get",
                                    "user_agent": "curl/8", "src": "1.2.3.4", "dst": "5.6.7.8",
                                    "dst_port": "443", "action": "allow"}))

    def test_a_url_with_its_category_is_a_proxy_log(self):
        row = {"datetime": "2023-11-06 16:49:47 GMT", "action": "Blocked", "url": "dummy-url.example.com",
               "urlcategory": "Other Information Technology", "urlclass": "Legal Liability", "serverip": "1.2.3.4",
               "ClientIP": "10.0.0.5", "requestmethod": "POST", "useragent": "Mozilla/5.0"}
        r = S.compile_rule({"title": "t", "id": "x", "level": "high", "logsource": {"category": "proxy"},
                            "detection": {"sel": {"urlclass": "Legal Liability"}, "condition": "sel"}})
        self.assertTrue(S.evaluate(row, [r], {}))

    def test_no_query_is_the_path_alone(self):
        self.assertFalse(self.fires({"cs-uri-stem": "/shell.jsp", "cs-uri-query": "-", "cs-method": "GET",
                                     "sc-status": "200", "c-ip": "10.0.0.1"}))


class KubernetesAudit(unittest.TestCase):
    def test_an_api_server_audit_event_runs_the_kubernetes_rules(self):
        ev = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "a9157591", "verb": "create",
              "user": {"username": "kubernetes-admin"}, "sourceIPs": ["176.95.188.101"],
              "objectRef": {"resource": "pods", "namespace": "default", "name": "privileged-the-pod"},
              "requestObject": {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}}
        r = S.compile_rule({"title": "t", "id": "x", "level": "high",
                            "logsource": {"product": "kubernetes", "service": "audit"},
                            "detection": {"sel": {"verb": "create", "objectRef.resource": "pods"},
                                          "condition": "sel"}})
        self.assertTrue(S.evaluate(X._flat(ev), [r], {}))


class CiscoSecureFirewall(unittest.TestCase):
    def test_an_estreamer_record_runs_the_secure_firewall_rules(self):
        ev = {"EventType": "IntrusionEvent", "DeviceUUID": "11bc8e94", "ConnectionID": 1882,
              "InitiatorIP": "23.48.99.12", "ResponderIP": "172.16.3.110", "SignatureID": 65118}
        r = S.compile_rule({"title": "t", "id": "x", "level": "high",
                            "logsource": {"product": "cisco", "service": "secure_firewall"},
                            "detection": {"sel": {"EventType": "IntrusionEvent", "SignatureID": "65118"},
                                          "condition": "sel"}})
        self.assertTrue(S.evaluate(ev, [r], {}))
        self.assertFalse(S.evaluate(dict(ev, SignatureID=1), [r], {}))


class SecurityRegistryAudit(unittest.TestCase):
    """Security 4657 (registry object auditing) names the key as \\REGISTRY\\MACHINE\\...
    plus a value name: the registry rules were written for Sysmon and never ran on it."""
    EV = {"Provider": "Microsoft-Windows-Security-Auditing", "EventID": "4657", "Channel": "Security",
          "ObjectName": "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa",
          "ObjectValueName": "Security Packages", "NewValue": "mimilib",
          "ProcessName": "C:\\Windows\\System32\\reg.exe"}

    def test_a_registry_rule_reads_4657(self):
        r = S.compile_rule({"title": "t", "id": "x", "level": "high",
                            "logsource": {"category": "registry_event", "product": "windows"},
                            "detection": {"sel": {"TargetObject|endswith": "\\Control\\Lsa\\Security Packages",
                                                  "Details": "mimilib"},
                                          "img": {"Image": None}, "condition": "sel and not img"}})
        self.assertTrue(S.evaluate(self.EV, [r], {}))


class JsonInsideAField(unittest.TestCase):
    """Duo's administrator log keeps the policy change as JSON text in "description";
    a rule names its keys (require_lock), as Splunk's spath reads them."""
    ROW = {"ctime": "Wed Jul  9 11:01:58 2025", "action": "policy_update", "actionlabel": "Modified policy",
           "isotimestamp": "2025-07-09T11:01:58+00:00", "object": "test1", "username": "Test Test",
           "description": '{"require_lock": false, "admin_email": "test@test.com"}'}

    def test_a_key_inside_json_text_is_a_field(self):
        r = S.compile_rule({"title": "t", "id": "x", "level": "high",
                            "logsource": {"product": "cisco", "service": "duo"},
                            "detection": {"sel": {"action": "policy_update", "require_lock": "false"},
                                          "condition": "sel"}})
        self.assertTrue(S.evaluate(X.sigma_event(self.ROW), [r], {}))
        self.assertFalse(S.evaluate(X.sigma_event(dict(self.ROW, description='{"require_lock": true}')), [r], {}))


class EsxiSyslog(unittest.TestCase):
    """ESXi lines read as structure (key=value, or columns split on spaces) lost the
    message the ESXi rules match: all 23 Splunk ESXi detections were silent."""
    HOSTD = ("May  7 17:58:34 192.168.8.233 2025-05-07T17:58:32.450Z localhost Hostd[263168]: [Originator@6876 "
             "sub=Vimsvc.ha-eventmgr opID=esxui-6fd9 sid=5290e005 user=root] Event 105 : ESXi Shell for the "
             "host localhost.lan has been enabled")
    VOBD = ("May  7 17:58:30 192.168.8.233 2025-05-07T17:58:28.526Z localhost vobd[262381]:  [UserLevelCorrelator] "
            "621288555us: [vob.user.ssh.enabled] SSH access has been enabled")

    def fires(self, raw, text):
        r = S.compile_rule({"title": "t", "id": "x", "level": "medium", "logsource": {"product": "esxi"},
                            "detection": {"sel": {"text": text}, "condition": "sel"}})
        return bool(S.evaluate(X.sigma_event(X._flat(raw)), [r], {}))

    def test_message_after_key_value_pairs(self):
        self.assertTrue(self.fires(X._kv_row(self.HOSTD), "*ESXi Shell*has been enabled*"))

    def test_line_split_into_unnamed_columns(self):
        fm, rows, _ = X.read("\n".join([self.VOBD] * 3))
        self.assertEqual("space", fm)
        self.assertTrue(self.fires(rows[0], "*SSH access has been enabled"))

    def test_plain_key_value_keeps_no_line(self):
        self.assertNotIn("_line", X._kv_row("date=2025-01-01 srcip=1.2.3.4 dstip=5.6.7.8 action=deny"))


@unittest.skipUnless(os.path.isdir("/opt/sigma-rules/regression_data"), "SigmaHQ rules not installed here")
class SigmaHQRegression(unittest.TestCase):
    def test_every_regression_event_fires_its_rule(self):
        loaded = S.load(dirs=("/opt/sigma-rules/rules", "/opt/sigma-rules/rules-emerging-threats",
                              "/opt/sigma-rules/rules-threat-hunting"), min_level="informational")
        byid = {r["id"]: r for r in loaded["rules"]}
        n, missed = 0, []
        for info in glob.glob("/opt/sigma-rules/regression_data/**/info.yml", recursive=True):
            with open(info) as f:
                meta = yaml.safe_load(f)
            rid = meta["rule_metadata"][0]["id"]
            for js in glob.glob(os.path.join(os.path.dirname(info), "*.json")):
                with open(js) as f:
                    text = f.read()
                evs, pos, dec = [], 0, json.JSONDecoder()
                while pos < len(text):                 # one object, a list, or several in a row
                    while pos < len(text) and text[pos].isspace():
                        pos += 1
                    if pos >= len(text):
                        break
                    obj, pos = dec.raw_decode(text, pos)
                    evs.extend(obj if isinstance(obj, list) else [obj])
                n += 1
                if rid not in byid or not any(S.evaluate(X._flat(e), [byid[rid]]) for e in evs):
                    missed.append(meta["rule_metadata"][0]["title"])
        self.assertGreater(n, 100)
        self.assertEqual([], missed)


if __name__ == "__main__":
    unittest.main()
