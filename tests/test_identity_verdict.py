"""Identities: the analyst marks a person compromised / not compromised.

Stored against the person's ACCOUNTS (the card key is a union-find root that can
change when accounts are merged), kept across re-fusion, cleared with "".
"""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, schema, store  # noqa: E402


class Store(unittest.TestCase):
    def setUp(self):
        self.d = {}

        def mutate(cid, field, fn):
            self.d[field] = fn(list(self.d.get(field) or []))
        self.p = [mock.patch.object(store, "get_case", return_value={"x": 1}),
                  mock.patch.object(store, "_mutate_list_field", mutate),
                  mock.patch.object(store, "log_case_event")]
        self.log = [p.start() for p in self.p][2]

    def tearDown(self):
        for p in self.p:
            p.stop()

    def test_set_replace_clear(self):
        store.set_identity_verdict("c", ["a1", "a2"], "compromised", name="kobia")
        self.assertIn("kobia marked compromised", self.log.call_args.args[1])
        # a later card holding a2 + a3 (merged) finds it, and a new verdict replaces it
        self.assertEqual(store._identity_verdict_for(self.d["identity_verdicts"], ["a3", "a2"])["verdict"],
                         "compromised")
        store.set_identity_verdict("c", ["a2", "a3"], "not_compromised")
        self.assertEqual([r["verdict"] for r in self.d["identity_verdicts"]], ["not_compromised"])
        store.set_identity_verdict("c", ["a3"], "")
        self.assertEqual(self.d["identity_verdicts"], [])
        self.assertIsNone(store._identity_verdict_for([], ["a1"]))

    def test_bad_input_is_refused(self):
        self.assertIn("error", store.set_identity_verdict("c", [], "compromised"))
        self.assertIn("error", store.set_identity_verdict("c", ["a"], "owned"))
        self.assertNotIn("identity_verdicts", self.d)


class Reach(unittest.TestCase):
    def test_findings_on_what_the_account_executed_count(self):
        g = schema.FusionGraph(case_id="c")
        g.relate(schema.Relationship("acc", "ev1", "executed"))
        g.relate(schema.Relationship("other", "ev2", "executed"))
        self.assertEqual(identities.person_reach(g, ["acc"]), {"acc", "ev1"})


class Card(unittest.TestCase):
    def test_verdict_buttons(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        js = r"""
const fs=require("fs"); const src=fs.readFileSync(process.argv[1],"utf8");
eval(src.match(/const ID_VERDICTS=\[.*?\];/s)[0].replace("const ","var ")); eval(src.match(/function idVerdictSeg\(cid,it\)\{[\s\S]*?\n\}/)[0]);
const esc=s=>String(s), jsa=s=>String(s);
console.log(JSON.stringify([idVerdictSeg("c1",{key:"k",verdict:"compromised"}), idVerdictSeg("c1",{key:"k"})]));"""
        out = subprocess.run([node, "-e", js, os.path.join(_ROOT, "modules/nginx/html/cases.html")],
                             capture_output=True, text=True, check=True).stdout
        import json
        on, off = json.loads(out)
        self.assertIn('class="s-compromised on"', on)
        self.assertIn("idVerdict('c1','k','')", on)                 # clicking the lit one clears
        self.assertIn("idVerdict('c1','k','not_compromised')", on)
        self.assertNotIn(" on\"", off)
        self.assertIn("event.stopPropagation()", on)                # does not fold the card


if __name__ == "__main__":
    unittest.main()
