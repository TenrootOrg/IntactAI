"""Identities: built-in accounts shown, every host listed, local accounts kept apart.

Found in the audit (jev_test):
  * the built-in Administrator — used by hand on two domain controllers — was
    filtered out as "not a person", so it appeared nowhere on the people page;
  * a person's hosts were only hosts whose NAME contained the username, so srv
    and giladt lost ALDC02 and searching "ALDC02" matched nobody;
  * `admin01` from ALClient022's own SAM and `admin01` from ALClient01's own SAM
    — two separate local principals — were one person, and fusion reported
    "Identity 'admin01' active on 2 hosts" as if it were lateral movement.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, schema  # noqa: E402


def _graph():
    g = schema.FusionGraph(case_id="c")
    for h in ("WS1", "WS2", "DC1"):
        g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h, attrs={"bucket": "endpoint"}))

    def acct(eid, label, hosts, artifact="Windows.System.Pslist"):
        g.upsert(schema.Entity(id=eid, type="account", label=label, attrs={"_assets": [f"asset:{h}" for h in hosts]},
                               evidence=[schema.EvidenceRef("velociraptor", "r1", f"{artifact}/row=1")]))
    acct("account:asset:WS1:admin01", "admin01", ["WS1"], "Windows.Forensics.SAM")
    acct("account:asset:WS2:admin01", "admin01", ["WS2"], "Windows.Forensics.SAM")
    acct("account:domain:corp\\srv", "CORP\\srv", ["WS1", "DC1"])
    acct("account:asset:WS2:srv", "srv", ["WS2"])
    acct("account:domain:corp\\administrator", "CORP\\administrator", ["DC1"])
    acct("account:asset:DC1:administrator", "administrator", ["DC1"], "Windows.Forensics.SAM")
    return g


class Cards(unittest.TestCase):
    def setUp(self):
        self.cards = identities.resolve_identities(_graph())

    def _card(self, name):
        return [c for c in self.cards if c["name"] == name]

    def test_builtin_administrator_has_a_card_and_the_domain_one_is_its_own(self):
        # CORP\\administrator and the local (SAM) Administrator were one card
        adm = self._card("administrator")
        self.assertEqual(len(adm), 2)
        self.assertTrue(all(c["builtin"] for c in adm))
        self.assertTrue(all("DC1" in c["seen_on"] for c in adm))
        self.assertEqual(sorted(len(c["accounts"]) for c in adm), [1, 1])

    def test_a_builtins_local_copies_are_one_card_per_host(self):
        # "built-in identities are local and totally different from each other":
        # one card for ten local Administrators meant one verdict for ten accounts.
        g = _graph()
        for h in ("WS1", "WS2"):
            g.upsert(schema.Entity(id=f"account:asset:{h}:guest", type="account", label="guest",
                                   attrs={"_assets": [f"asset:{h}"]},
                                   evidence=[schema.EvidenceRef("velociraptor", "r1", "Windows.Forensics.SAM/row=1")]))
        guest = [c for c in identities.resolve_identities(g) if c["name"] == "guest"]
        self.assertEqual(sorted(c["seen_on"] for c in guest), [["WS1"], ["WS2"]])
        self.assertTrue(all(c["builtin"] and len(c["accounts"]) == 1 for c in guest))
        self.assertFalse(any(c["local_group"] for c in guest))
        self.assertTrue(all(c["local"] for c in guest))              # badge: "local", not "built-in"
        adm = {tuple(c["seen_on"]) + (c["local"],) for c in self._card("administrator")}
        self.assertEqual(adm, {("DC1", True), ("DC1", False)})       # the SAM one is local; CORP\ is not
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("bdg('built-in'", src)
        self.assertIn("${it.local?`<span title=\"A local account", src)

    def test_listed_only_means_seen_in_an_account_list_and_nowhere_else(self):
        ent = lambda *locs: schema.Entity(id="a", type="account", label="x", attrs={},
                                          evidence=[schema.EvidenceRef("v", "r", l) for l in locs])
        self.assertTrue(identities.listed_only(ent("Windows.Forensics.SAM/Parsed/row=1",
                                                   "Windows.Forensics.SAM/CreateTimes/row=2")))
        self.assertTrue(identities.listed_only(ent("Windows.Sys.Users/row=4")))
        self.assertFalse(identities.listed_only(ent("Windows.Forensics.SAM/row=1", "Generic.System.Pstree/row=9")))
        self.assertFalse(identities.listed_only(ent("DetectRaptor.Windows.Detection.Powershell.PSReadline/row=3")))
        self.assertFalse(identities.listed_only(ent()))                    # no record: not "only listed"
        dict_ev = schema.Entity(id="a", type="account", label="x", attrs={})
        dict_ev.evidence = [{"locator": "Windows.Forensics.SAM/row=1"}]
        self.assertTrue(identities.listed_only(dict_ev))                  # the dict form too
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        self.assertIn('it["activity"] = bool(fs) or any(not _idf.listed_only(', src)
        blk = src[src.index('it["activity"] = bool(fs)'):][:700]
        self.assertIn("except Exception as _e:", blk)                     # never fails the tab
        self.assertIn('it["activity"] = True', blk)                        # on error: shown, not hidden

    def test_every_host_is_listed(self):
        srv = self._card("srv")
        self.assertEqual(len(srv), 1)
        self.assertEqual(srv[0]["seen_on"], ["DC1", "WS1", "WS2"])

    def test_local_accounts_on_different_hosts_are_different_people(self):
        self.assertEqual(len(self._card("admin01")), 2)


class Suggestions(unittest.TestCase):
    def test_same_local_name_elsewhere_is_a_suggestion_not_a_merge(self):
        cands = identities.compute_candidates(_graph())
        pair = [c for c in cands if c.get("match") == "same local name"]
        self.assertEqual(len(pair), 1)
        self.assertFalse(pair[0]["auto"])
        self.assertIn("same local account name on different hosts", pair[0]["reason"])

    def test_builtins_are_never_fuzzy_matched(self):
        cands = identities.compute_candidates(_graph())
        self.assertFalse([c for c in cands if c["kind"] == "same_identity" and "administrator" in
                          (identities._norm_user(c["a_label"]), identities._norm_user(c["b_label"]))])

    def test_a_shared_host_in_one_infrastructure_adds_no_score(self):
        # jev_test: a bare prefix match on one workstation scored 0.90 — the same
        # as an exact username — because the shared host added +0.3.
        g = _graph()
        for eid, lbl in (("account:domain:corp\\giladt", "CORP\\giladt"), ("account:domain:corp\\gilad", "CORP\\gilad")):
            g.upsert(schema.Entity(id=eid, type="account", label=lbl, attrs={"_assets": ["asset:WS1"]},
                                   evidence=[schema.EvidenceRef("velociraptor", "r1", "Windows.System.Pslist/row=1")]))
        c = [c for c in identities.compute_candidates(g) if c.get("match") == "username prefix"][0]
        self.assertEqual(c["score"], 0.6)
        self.assertIn("shares host WS1", c["reason"])          # still shown as evidence
        self.assertFalse(c["auto"])

    def test_role_variants_are_suggested_never_merged(self):
        # jev_test: almogs / almognoadmin and kobia / kobitst were never offered.
        for a, b in (("almogs", "almognoadmin"), ("kobia", "kobitst"), ("adm_jdoe", "CORP\\jdoe"), ("jdoe", "jdoe.adm")):
            self.assertEqual(identities._match(a, b), (0.7, "role variant", False), (a, b))
        self.assertIsNone(identities._match("nofl", "giladt"))
        # a shared host across infrastructures would normally auto-merge; not a role variant
        g = _graph()
        g.upsert(schema.Entity(id="account:aws:kobia", type="account", label="kobia",
                               attrs={"_assets": ["cloud_account:aws:1", "asset:WS1"]}))
        g.upsert(schema.Entity(id="account:asset:WS1:kobitst", type="account", label="kobitst",
                               attrs={"_assets": ["asset:WS1"]}))
        c = [c for c in identities.compute_candidates(g) if c.get("match") == "role variant"]
        self.assertEqual(len(c), 1)
        self.assertFalse(c[0]["auto"])


class Page(unittest.TestCase):
    """Cards ranked by risk with their findings; one pair counted once."""

    def test_cards_carry_findings_kinds_and_one_count_per_pair(self):
        from unittest import mock
        from services.fusion import store
        g = _graph()
        for eid, lbl in (("account:domain:corp\\svc_backup", "CORP\\svc_backup"),
                         ("account:domain:corp\\kobia", "CORP\\kobia"), ("account:domain:corp\\kobitst", "CORP\\kobitst")):
            g.upsert(schema.Entity(id=eid, type="account", label=lbl, attrs={"_assets": ["asset:WS1"]},
                                   evidence=[schema.EvidenceRef("velociraptor", "r1", "Windows.System.Pslist/row=1")]))
        g.findings = [schema.Finding(id="f1", title="Mimikatz on WS1", severity="critical", confidence="high",
                                     summary="", entity_ids=["account:domain:corp\\svc_backup"]),
                      schema.Finding(id="f2", title="Odd logon on WS1", severity="medium", confidence="high",
                                     summary="", entity_ids=["account:domain:corp\\kobia"])]
        ws = mock.Mock()
        ws.get_automation_runs_by_case.return_value = []
        with mock.patch.object(store, "get_case", return_value={"x": 1}), \
             mock.patch.object(store, "view_graph", return_value=g), \
             mock.patch("services.fusion.jev.enabled", return_value=False), \
             mock.patch.object(store, "_ws", return_value=ws):
            v = store.identity_view("c1")
        cards = v["identities"]
        by = {c["name"]: c for c in cards}
        self.assertEqual(by["svc_backup"]["account_kind"], "service")
        self.assertEqual(by["kobitst"]["account_kind"], "test")
        self.assertEqual([identities.account_kind(n) for n in ("contest", "tester", "jdoe.test")], [None, None, "test"])
        self.assertEqual((by["svc_backup"]["worst"], by["svc_backup"]["detections"]), ("critical", 1))
        self.assertEqual(by["svc_backup"]["findings"][0]["id"], "f1")
        self.assertEqual(by["srv"]["account_kind"], "service")
        # Jev off: A–Z only (the Jev order is in test_jev_compromise)
        self.assertEqual(v["sort"], "alpha")
        names = [c["name"] for c in cards]
        self.assertEqual(names, sorted(names, key=str.lower))
        # kobia / kobitst is one suggested pair, shown on both cards, counted once
        self.assertEqual(sum(len(c["suggestions"]) for c in cards), 2 * v["counts"]["suggestions"])

    def test_card_markup(self):
        """The real idCard from cases.html, run in node (skips where node is absent)."""
        import shutil, subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        js = r"""
const fs=require("fs"); const src=fs.readFileSync(process.argv[1],"utf8");
eval(src.match(/function idCard\(cid,it,jev\)\{[\s\S]*?\n\}/)[0]);
eval(src.match(/const ID_VERDICTS=\[.*?\];/s)[0].replace("const ","var ")); eval(src.match(/function idVerdictSel\(cid,it\)\{[\s\S]*?\n\}/)[0]); eval(src.match(/function _idJev\(it\)\{[\s\S]*?\n\}/)[0]); eval(src.match(/function _hostRow\(label\)\{[^\n]*\}/)[0]);
const esc=s=>String(s).replace(/[<>&"]/g,""), jsa=s=>String(s); window={_idExpand:{k:true},_riskData:{rows:[{host:"WS1",severity:"high",risk_score:70}]}};
console.log(idCard("c1",{key:"k",jev_compromise:0.9,verdict:"compromised",name:"svc_backup",account_kind:"service",worst:"critical",detections:1,finding_rows:3,
  accounts:[{id:"a",label:"svc_backup"}],seen_on:["WS1"],findings:[{id:"f1",title:"Mimikatz on WS1",severity:"critical"}]},true));"""
        html = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/nginx/html/cases.html")
        out = subprocess.run([node, "-e", js, html], capture_output=True, text=True, check=True).stdout
        for want in (">service</span>", 'class="chip c-critical"', "openFindingDetail('f1')",
                     ">1</b> <span>(3 rows)</span>", "worst 1 of 3", 'class="prow v-compromised"',
                     "90%</b>", '<option value="compromised" selected>',
                     "entOpenHost('WS1')", 'class="chip c-high"'):        # person -> host and its severity
            self.assertIn(want, out)
        self.assertNotIn("ranked #", out)                                      # "the ranked is not necessary"


class RiskSaysIdentities(unittest.TestCase):
    def test_the_risk_tab_says_identities_not_people(self):
        # "people in risk sound not professional, call it Identities"
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            src = fh.read()
        for want in ("<span>Lead finding</span><span>Identities</span>", "Identities on this host",
                     "filter hosts or identities…", 'title="Open this identity"'):
            self.assertIn(want, src)
        for gone in ("<span>People</span>", "People on this host", "filter hosts or people", "and who.</p>"):
            self.assertNotIn(gone, src)


if __name__ == "__main__":
    unittest.main()
