"""The masking audit log must not repeat itself.

Two real annoyances on a live report: (1) case variants of one value
(Attacked-WIN11 / attacked-win11) were listed twice though they map to the same
pseudonym; (2) the identity list was re-logged for every model call (report,
then checklist) sharing one mask. Both are log-only — masking is unchanged."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim  # noqa: E402


class _Mask:
    def __init__(self, mapping):
        self.mapping = mapping


class CaseVariantsCollapse(unittest.TestCase):
    def test_same_value_different_case_listed_once(self):
        out = llm_sim._mask_audit_lines({
            "Attacked-WIN11": "SAM7", "attacked-win11": "SAM7",
            "DESKTOP-2175T02": "Hostname1", "desktop-2175t02": "Hostname1"})
        self.assertEqual(1, out.count("SAM7"), out)
        self.assertEqual(1, out.count("Hostname1"), out)

    def test_distinct_pseudonyms_both_kept(self):
        # not a case variant — different pseudonyms for one person's forms stay.
        out = llm_sim._mask_audit_lines({"corp\\almogs": "USER1", "almogs": "SAM1"})
        self.assertIn("USER1", out)
        self.assertIn("SAM1", out)


class LoggedOncePerReport(unittest.TestCase):
    def test_second_call_on_same_mask_is_silent(self):
        from services.fusion import store
        logs = []
        orig = store.log_case_event
        store.log_case_event = lambda cid, act, lvl, msg, **kw: logs.append(act)
        try:
            m = _Mask({"host-a": "Hostname1", "almogs": "SAM1"})
            llm_sim._log_mask_audit("run1", m)     # logs
            llm_sim._log_mask_audit("run1", m)     # same mask, nothing new -> silent
        finally:
            store.log_case_event = orig
        self.assertEqual(1, len(logs), logs)


class BuiltinAccountsAreNotIdentities(unittest.TestCase):
    """OpenSSH-for-Windows runs each session as VIRTUAL USERS\\sshd_<pid>. A lab report
    masked those as USER1..USER4 plus an org "Domain1" — fake identities that hid
    that they were SSH sessions. A built-in authority's accounts, and their bare
    forms, are not customer identities; a real user still is."""
    def test_virtual_users_and_bare_form_skipped_real_user_kept(self):
        from services.fusion.schema import Entity, FusionGraph
        from services.data_anonymizer import DataAnonymizer
        g = FusionGraph(case_id="c")
        for i, lbl in enumerate(("VIRTUAL USERS\\sshd_2588", "sshd_2588", "CORP\\alice",
                                   "DefaultAccount", "WDAGUtilityAccount")):
            g.upsert(Entity(id=f"a{i}", type="account", label=lbl))
        m = DataAnonymizer()
        llm_sim._build_mask_mapping(g, m)
        keys = {k.lower() for k in m.mapping}
        self.assertNotIn("virtual users\\sshd_2588", keys, m.mapping)
        self.assertNotIn("sshd_2588", keys, m.mapping)
        self.assertNotIn("virtual users", keys, m.mapping)
        self.assertNotIn("defaultaccount", keys, m.mapping)       # Windows built-ins
        self.assertNotIn("wdagutilityaccount", keys, m.mapping)
        self.assertIn("corp\\alice", keys, m.mapping)


    def test_env_placeholder_and_unc_ip_are_not_identities(self):
        from services.fusion.schema import Entity, FusionGraph
        from services.data_anonymizer import DataAnonymizer
        g = FusionGraph(case_id="c")
        g.upsert(Entity(id="a0", type="account", label="%wmi-userdatauser%"))
        g.upsert(Entity(id="e0", type="event", label="x",
                        attrs={"ev_cmdline": "cmd /c copy x \\\\127.0.0.1\\ADMIN$\\y"}))
        m = DataAnonymizer()
        llm_sim._build_mask_mapping(g, m)
        self.assertNotIn("%wmi-userdatauser%", {k.lower() for k in m.mapping}, m.mapping)
        self.assertFalse(any(str(v).startswith("Hostname") for k, v in m.mapping.items()
                             if k == "127.0.0.1"), m.mapping)

    def test_local_account_is_one_identity_with_its_bare_name(self):
        # HOST\\user arrives from evidence AFTER the bare name: one person, one number.
        from services.fusion.schema import Entity, FusionGraph
        from services.data_anonymizer import DataAnonymizer
        g = FusionGraph(case_id="c")
        g.upsert(Entity(id="h", type="asset", label="DESKTOP-1"))
        g.upsert(Entity(id="a", type="account", label="bob"))
        g.upsert(Entity(id="e", type="event", label="x", attrs={"ev_user": "DESKTOP-1\\bob"}))
        m = DataAnonymizer()
        llm_sim._build_mask_mapping(g, m)
        num = lambda k: "".join(c for c in m.mapping[k] if c.isdigit())
        self.assertEqual(num("bob"), num("DESKTOP-1\\bob"), m.mapping)
        self.assertTrue(m.mapping["DESKTOP-1\\bob"].startswith("USER"), m.mapping)

    def test_a_domain_account_is_not_merged_into_a_bare_name(self):
        # CORP is not a computer here: CORP\\bob and a bare bob stay as before.
        from services.fusion.schema import Entity, FusionGraph
        from services.data_anonymizer import DataAnonymizer
        g = FusionGraph(case_id="c")
        g.upsert(Entity(id="h", type="asset", label="DESKTOP-1"))
        g.upsert(Entity(id="a", type="account", label="carol"))
        g.upsert(Entity(id="e", type="event", label="x", attrs={"ev_user": "CORP\\carol"}))
        m = DataAnonymizer()
        llm_sim._build_mask_mapping(g, m)
        self.assertIn("CORP\\carol", m.mapping)


if __name__ == "__main__":
    unittest.main()
