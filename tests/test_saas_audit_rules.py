"""SaaS audit logs reach SigmaHQ's medium rules: M365, Google Workspace login, Kubernetes.

2026-10-20 severity audit, medium tier:
- SigmaHQ's M365 rules match eventSource / eventName / status: an O365 Management
  Activity export writes Workload / Operation (or an alert's Name) / ResultStatus, and
  an S&C alert has its own Status ("Active"). On 9,189 real O365 rows 8 hits became 55.
- Google Workspace login rules are written for the Cloud Logging export
  (protoPayload.serviceName login.googleapis.com); the Reports API names them otherwise.
- Half of the Kubernetes rules are filed under category: application.
Rule bodies are SigmaHQ's.
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


def r(title, logsource, selection):
    return S.compile_rule({"title": title, "id": title, "level": "medium", "logsource": logsource,
                           "detection": {"selection": selection, "condition": "selection"}})


M365 = {"product": "m365"}
PST = r("PST Export Alert Using eDiscovery Alert", {**M365, "service": "threat_management"},
        {"eventSource": "SecurityComplianceCenter", "eventName": "eDiscovery search started or exported",
         "status": "success"})
FEDERATED = r("New Federated Domain Added - Exchange", {**M365, "service": "exchange"},
              {"eventSource": "Exchange", "eventName": "Add-FederatedDomain", "status": "success"})
GWS = r("Suspicious Login Activity Classified By Google", {"product": "gcp", "service": "google_workspace.login"},
        {"protoPayload.serviceName": "login.googleapis.com",
         "protoPayload.metadata.event.eventName": ["suspicious_login", "suspicious_programmatic_login"]})
K8S_EXEC = r("Exec Into Container", {"category": "application", "product": "kubernetes", "service": "audit"},
             {"verb": "create", "objectRef.resource": "pods", "objectRef.subresource": "exec"})
RULES = [PST, FEDERATED, GWS, K8S_EXEC]


def titles(doc):
    _fmt, rows, _left = X.read(json.dumps(doc))
    return [h["title"] for h in S.evaluate(X.sigma_event(rows[0]), RULES)]


class O365(unittest.TestCase):
    ALERT = {"CreationTime": "2026-10-20T10:05:00", "Id": "x", "Operation": "AlertEntityGenerated",
             "OrganizationId": "o", "RecordType": 40, "ResultStatus": "Succeeded", "UserKey": "SecurityComplianceAlerts",
             "UserType": 4, "Version": 1, "Workload": "SecurityComplianceCenter", "UserId": "SecurityComplianceAlerts",
             "AlertId": "a1", "Name": "eDiscovery search started or exported", "Status": "Active", "Severity": "Medium"}

    def test_an_sc_alert_is_read_by_its_name_not_its_own_status(self):
        self.assertEqual(["PST Export Alert Using eDiscovery Alert"], titles(self.ALERT))
        self.assertEqual([], titles({**self.ALERT, "ResultStatus": "Failed"}))

    def test_a_failed_result_is_failure(self):
        row = {"Workload": "AzureActiveDirectory", "Operation": "UserLoginFailed", "ResultStatus": "Failed"}
        self.assertEqual("failure", S.Event(row).get("status"))

    def test_an_exchange_cmdlet_is_the_event_name(self):
        rec = {"CreationTime": "2026-10-20T10:05:00", "Operation": "Add-FederatedDomain", "ResultStatus": "True",
               "Workload": "Exchange", "UserId": "admin@corp.example", "RecordType": 1, "OrganizationId": "o"}
        self.assertEqual(["New Federated Domain Added - Exchange"], titles(rec))


class GoogleWorkspaceLogin(unittest.TestCase):
    def test_the_reports_api_row(self):
        rec = {"kind": "admin#reports#activity", "id": {"time": "2026-10-20T10:05:00Z", "applicationName": "login",
                                                        "customerId": "c"},
               "actor": {"email": "jdoe@corp.example"}, "ipAddress": "203.0.113.9",
               "events": [{"type": "login", "name": "suspicious_login"}]}
        self.assertEqual(["Suspicious Login Activity Classified By Google"], titles(rec))
        self.assertEqual([], titles({**rec, "events": [{"type": "login", "name": "login_success"}]}))

    def test_the_cloud_logging_export(self):
        rec = {"protoPayload": {"serviceName": "login.googleapis.com", "methodName": "google.login.LoginService.loginSuccess",
                                "metadata": {"event": {"eventName": "suspicious_programmatic_login"}}}}
        self.assertEqual(["Suspicious Login Activity Classified By Google"], titles(rec))


class Kubernetes(unittest.TestCase):
    def test_exec_into_a_pod(self):
        rec = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "a1", "stage": "ResponseComplete",
               "verb": "create", "user": {"username": "dev"},
               "objectRef": {"resource": "pods", "namespace": "prod", "name": "web-1", "subresource": "exec"}}
        self.assertEqual(["Exec Into Container"], titles(rec))


if __name__ == "__main__":
    unittest.main()
