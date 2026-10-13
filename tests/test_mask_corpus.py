"""Masking must hide every identifier AND leave every other word alone.

Masking a word the model needs ("we will monitor", a rule title, a version)
changes what it concludes, so over-masking is a bug as real as a leak. Each class
pins one finding of `scripts/dev/mask_eval.py corpus` (the full labelled stress
test, run inside the backend); this is its fast, deterministic-layer slice."""
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.data_anonymizer import DataAnonymizer  # noqa: E402
from services.fusion import llm_sim  # noqa: E402
from services.fusion.schema import Entity, FusionGraph  # noqa: E402


def _graph(*ents):
    g = FusionGraph(case_id="t")
    for i, (t, label, attrs, flags) in enumerate(ents):
        g.entities[f"{t}:{i}"] = Entity(id=f"{t}:{i}", type=t, label=label, attrs=attrs or {}, flags=flags or [])
    return g


def _ent(t, label, attrs=None, flags=None):
    return (t, label, attrs, flags)


def _mask(*ents):
    m = DataAnonymizer()
    llm_sim._build_mask_mapping(_graph(*ents), m)
    return m


def _json_masked(m, text):
    """The production shape: the payload is masked as json.dumps text."""
    return json.loads(llm_sim._apply_mask(json.dumps({"v": text}), m, ner=False))["v"]


class EscapeEndsAToken(unittest.TestCase):
    """json.dumps turns a newline into \\n and a Hebrew letter into \\u05dc, so the
    character before the name is a letter/digit and the boundary used to refuse it."""
    def test_glued_to_escapes_still_masked(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"))
        for text in ("x\ndana.levi reset it", "x\tdana.levi", "נשלח לdana.levi", "GALIL%5Cdana.levi"):
            out = _json_masked(m, text)
            self.assertNotIn("dana.levi", out.lower(), (text, out))
        self.assertNotIn("dana.levi", llm_sim._apply_mask("x\ndana.levi", m, ner=False))

    def test_pseudonym_after_escape_reverts(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"))
        masked = llm_sim._apply_mask(json.dumps({"v": "a\ndana.levi"}), m, ner=False)
        self.assertEqual("a\ndana.levi", json.loads(llm_sim._revert_mask(masked, m))["v"])

    def test_hebrew_survives(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"), _ent("asset", "GL-WS-014"))
        text = "הערת אנליסט: המשתמש dana.levi התחבר מ-GL-WS-014 בשעה 08:14"
        out = _json_masked(m, text)
        for part in ("הערת אנליסט: המשתמש", "התחבר", "בשעה 08:14"):
            self.assertIn(part, out)
        self.assertNotIn("dana.levi", out)
        self.assertNotIn("GL-WS-014", out)


class PathSegmentsAreNotIdentities(unittest.TestCase):
    """A lab case masked SysVol/Policies/scripts as accounts and ServiceData/Staging
    as hosts, then rewrote the rule title "Change PowerShell Policies to an Insecure
    Level" as "Change PowerShell SAM24 ..."."""
    def test_sysvol_and_escaped_local_paths(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"),
                  _ent("event", "gpo", {"details": "\\\\galil.local\\SysVol\\galil.local\\Policies\\{31B2F340}\\scripts\\x.ps1"}),
                  _ent("event", "ccm", {"details": "C:\\\\Windows\\\\CCM\\\\ServiceData\\\\Messaging D:\\\\Staging\\\\a.zip"}))
        keys = {k.lower() for k in m.mapping}
        for seg in ("sysvol", "policies", "scripts", "servicedata", "ccm", "staging", "messaging"):
            self.assertNotIn(seg, keys, sorted(m.mapping))
        title = "Change PowerShell Policies to an Insecure Level; WinAPI Calls Via PowerShell Scripts"
        self.assertEqual(title, llm_sim._apply_mask(title, m, ner=False))

    def test_real_unc_host_and_domain_user_still_found(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"),
                  _ent("event", "net use", {"ev_cmdline": "net use \\\\FILESRV01\\c$ /user:GALIL\\amit.cohen x"}),
                  _ent("event", "esc", {"details": "copy \\\\\\\\BKSRV02\\\\share"}))
        self.assertTrue(m.mapping.get("FILESRV01", "").startswith("Hostname"), m.mapping)
        self.assertTrue(m.mapping.get("BKSRV02", "").startswith("Hostname"), m.mapping)
        self.assertTrue(m.mapping.get("GALIL\\amit.cohen", "").startswith("USER"), m.mapping)


class OrdinaryWordNamesOnlyWhereTheyAreNames(unittest.TestCase):
    """Accounts will/mark/scan and hosts BACKUP/WEB were replaced in every sentence:
    "we SAM3 monitor", "Veeam Hostname5", "Mark-of-the-Hostname6"."""
    def setUp(self):
        self.m = _mask(_ent("account", "GALIL\\will"), _ent("account", "GALIL\\mark"),
                       _ent("account", "GALIL\\scan"), _ent("asset", "BACKUP"), _ent("asset", "WEB"),
                       _ent("account", "GALIL\\almogs"),
                       _ent("event", "r", {"title": "Suspicious Backup Deletion via Wbadmin"}, ["sigma"]))

    def test_prose_survives(self):
        for text in ("The attacker will likely return, so we will monitor.",
                     "Mark-of-the-Web was stripped; mark the file as malicious.",
                     "Backup job failed; Veeam Backup stopped.",
                     "A port scan preceded the web shell upload to the IIS web server.",
                     "Rule: Suspicious Backup Deletion via Wbadmin"):
            self.assertEqual(text, _json_masked(self.m, text))
            self.assertEqual(text, llm_sim._apply_mask(text, self.m, ner=False))

    def test_identifier_positions_masked(self):
        for text, gone in (("will", "will"), ("C:\\Users\\will\\Desktop", "will"), ("User: will", "will"),
                           ("logon by will", "will"), ("Account Name:\t\tscan", "scan"),
                           ("\\\\backup\\share", "backup"), ("WEB$ authenticated", "WEB"),
                           ("Suspicious login on BACKUP", "BACKUP"), ("user=mark", "mark"),
                           ("GALIL\\will logged on", "will")):
            out = _json_masked(self.m, text)
            self.assertNotIn(gone, out, (text, out))
            # every form of the name gets the identity's number, never a stray word
            self.assertRegex(out, r"(SAM|USER|Hostname)\d", (text, out))

    def test_names_with_a_digit_or_separator_mask_everywhere(self):
        m = _mask(_ent("asset", "ALClient04"), _ent("account", "GALIL\\dana.levi"))
        out = _json_masked(m, "files copied from alclient04 by Dana.Levi today")
        self.assertNotIn("alclient04", out.lower())
        self.assertNotIn("dana.levi", out.lower())

    def test_a_real_username_in_prose_is_a_known_gap(self):
        # Documented ceiling: a one-word name in running prose, outside any identifier
        # position, is left alone -- the same rule that keeps "will" readable.
        self.assertIn("almogs", _json_masked(self.m, "then almogs ran it"))


class VersionsAreNotAddresses(unittest.TestCase):
    def test_version_shaped_quads_kept_real_ips_masked(self):
        m = _mask(_ent("event", "e", {"details": "ProductVersion 2.0.0.1 FileVersion: 1.0.0.1 "
                                                 "System.Web, Version=4.0.0.0, Culture=neutral v3.1.0.2 "
                                                 "connect 185.220.101.7 and 10.20.30.40"}))
        self.assertEqual({"185.220.101.7", "10.20.30.40"}, {k for k in m.mapping if k[0].isdigit()}, m.mapping)
        text = "Build 2.0.0.1, Version=4.0.0.0, 1.0.0.1"
        self.assertEqual(text, _json_masked(m, text))


class BuiltinsAreNotIdentities(unittest.TestCase):
    def test_krbtgt_is_not_masked(self):
        m = _mask(_ent("account", "krbtgt"), _ent("account", "GALIL\\krbtgt"))
        self.assertFalse([k for k in m.mapping if "krbtgt" in k.lower()], m.mapping)


class OnePersonOneNumber(unittest.TestCase):
    def _nums(self, m, *keys):
        return [m.mapping[k][-1] for k in keys]

    def test_netbios_and_upn_suffix_differ(self):
        for order in ((0, 1), (1, 0)):
            forms = ["GALIL\\dana.levi", "dana.levi@galil-dyn.co.il"]
            m = _mask(*[_ent("account", forms[i]) for i in order], _ent("account", "dana.levi"))
            self.assertEqual({"1"}, set(self._nums(m, *forms, "dana.levi")), m.mapping)

    def test_same_username_in_a_second_domain_is_someone_else(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"), _ent("account", "PARTNER\\dana.levi"))
        self.assertNotEqual(m.mapping["GALIL\\dana.levi"], m.mapping["PARTNER\\dana.levi"])


if __name__ == "__main__":
    unittest.main()
