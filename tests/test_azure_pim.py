"""Entra ID PIM alerts reach Sigma's 7 Azure PIM rules (all high).

The rules match riskEventType values ("staleSignInAlertIncident"...): the kinds of
Microsoft Graph's PIM alert incidents (/identityGovernance/roleManagementAlerts/
alerts/{id}/alertIncidents), which name their kind only in @odata.type. No row had
the azure/pim log source (2026-10-20 severity audit). Shapes from Microsoft's Graph
documentation; no real export was at hand.
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


def rule(title, kind):
    return S.compile_rule({"title": title, "id": title, "level": "high",
                           "logsource": {"product": "azure", "service": "pim"},
                           "detection": {"selection": {"riskEventType": kind}, "condition": "selection"}})


RULES = [rule("Stale Accounts In A Privileged Role", "staleSignInAlertIncident"),
         rule("Roles Activation Doesn't Require MFA", "noMfaOnRoleActivationAlertIncident"),
         rule("Roles Assigned Outside PIM", "rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration")]


def incident(kind, upn="admin@corp.example"):
    return {"@odata.type": f"#microsoft.graph.{kind}", "id": "x1", "assigneeId": "u1",
            "assigneeDisplayName": "Admin", "assigneeUserPrincipalName": upn,
            "roleDefinitionId": "62e90394", "roleDisplayName": "Global Administrator",
            "lastSignInDateTime": "2026-06-01T10:05:00Z"}


def titles(rows):
    return [[h["title"] for h in S.evaluate(X.sigma_event(r), RULES)] for r in rows]


class AzurePim(unittest.TestCase):
    def test_graph_alert_incidents_fire(self):
        _fmt, rows, _left = X.read(json.dumps({"value": [incident("staleSignInAlertIncident"),
                                                         incident("noMfaOnRoleActivationAlertIncident")]}))
        self.assertEqual([["Stale Accounts In A Privileged Role"], ["Roles Activation Doesn't Require MFA"]],
                         titles(rows))

    def test_an_alert_configuration_too(self):
        row = {"@odata.type": "#microsoft.graph.rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration",
               "id": "c1", "isEnabled": True, "alertDefinitionId": "x"}
        self.assertEqual([["Roles Assigned Outside PIM"]], titles([row]))

    def test_other_graph_objects_are_not_pim(self):
        user = {"@odata.type": "#microsoft.graph.user", "id": "u1", "userPrincipalName": "a@b.c"}
        self.assertNotIn(("azure", None, "pim"), S.profiles(S.Event(user)))
        self.assertEqual([[]], titles([user]))

    def test_identity_protection_keeps_its_own_risk_event_type(self):
        det = {"riskEventType": "unfamiliarFeatures", "@odata.type": "#microsoft.graph.riskDetection"}
        self.assertEqual("unfamiliarFeatures", S.Event(det).get("riskEventType"))


if __name__ == "__main__":
    unittest.main()
