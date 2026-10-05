"""Sigma detections reach the account the full event names by SID.

Reported 2026-10-05 (Windows 11 lab, DESKTOP-2175T02): every identity card said
"no findings" while the host had four. Hayabusa's Details name nobody for 4104 /
7045 / Defender and only a SID for 4732's added member, and the linker read
Details alone. The full event (_Event) carries the SIDs; the host's own 4672 /
4720 events pair those SIDs with names. Measured there: RID 1000 was
defaultuser0 (Setup's temporary admin), NOT the operator's account — which is
why a RID guess is never made.
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

M = "S-1-5-21-111-222-333"
HOST = "DESKTOP-2175T02"


def row(eid, title, level="high", user_sid=None, ts="2026-10-05T08:00:00Z", **data):
    ev = {"System": {"EventID": eid, "Computer": HOST, "Channel": "Security",
                     "EventRecordID": hash(title) & 0xFFFF},
          "EventData": data}
    if user_sid:
        ev["System"]["Security"] = {"UserID": user_sid}
    return {"Title": title, "Level": level, "EID": eid, "Computer": HOST,
            "Timestamp": ts, "Details": "SrcSID: x ¦ TgtGrp: Administrators",
            "_Event": ev, "_hostname": HOST, "_client_id": "C.abc"}


ROWS = [
    # names: 4672 pairs RID 1000 with defaultuser0, 4624 pairs 1001 with alice
    row(4672, "Admin Logon", "info", SubjectUserSid=f"{M}-1000",
        SubjectUserName="defaultuser0", SubjectDomainName=HOST),
    row(4624, "Logon", "info", TargetUserSid=f"{M}-1001",
        TargetUserName="alice", TargetDomainName=HOST),
    # 4732: SYSTEM adds RID 1000 to Administrators; the group's own SID is builtin
    row(4732, "User Added To Local Admin Grp", MemberSid=f"{M}-1000",
        TargetSid="S-1-5-32-544", TargetUserName="Administrators",
        SubjectUserSid="S-1-5-18", SubjectUserName=HOST + "$"),
    # 4104 names nobody in EventData; the user is only System.Security.UserID
    row(4104, "Potentially Malicious PwSh", user_sid=f"{M}-1001"),
    # Defender as SYSTEM, and a SID no event names
    row(5001, "Defender Disabled", user_sid="S-1-5-18"),
    row(4104, "Other PwSh", user_sid=f"{M}-1005"),
]


class SidLinking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ents, cls.rels = map_agentic({"Windows.Hayabusa.Rules": ROWS}, run_id="r1")
        cls.by_id = {e.id: e for e in cls.ents}
        cls.acct = {e.label: e.id for e in cls.ents if e.type == "account"}

    def linked(self, label):
        a = self.acct.get(label)
        return {(r.kind, self.by_id[r.dst].attrs.get("title")) for r in self.rels
                if a and r.src == a and r.dst in self.by_id and self.by_id[r.dst].type == "event"}

    def test_the_added_member_is_named_by_its_sid(self):
        self.assertIn(("event_about", "User Added To Local Admin Grp"), self.linked("defaultuser0"))

    def test_the_powershell_user_is_named_by_security_userid(self):
        self.assertIn(("executed", "Potentially Malicious PwSh"), self.linked("alice"))

    def test_system_and_unnamed_sids_link_nobody(self):
        everyone = set().union(*(self.linked(a) for a in self.acct))
        titles = {t for _k, t in everyone}
        self.assertNotIn("Defender Disabled", titles)
        self.assertNotIn("Other PwSh", titles)

    def test_the_group_sid_is_not_an_account(self):
        self.assertNotIn("administrators", {k.lower() for k in self.acct})

    def test_the_card_counts_an_event_about_the_account(self):
        class G:
            relationships = self.rels
            findings = [type("F", (), {"entity_ids": [r.dst]})()
                        for r in self.rels if r.kind == "event_about"
                        and r.src == self.acct["defaultuser0"]]
        self.assertTrue(identities.person_findings(G, [self.acct["defaultuser0"]]))


if __name__ == "__main__":
    unittest.main()
