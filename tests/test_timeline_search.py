"""Timeline search box: every typed word must appear in the row's values, in any
order, case-insensitive -- and field NAMES never match ("host" is a key on every row).
Runs the real _tlText/tlVisible from cases.html in node.
"""
import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()


class TimelineSearch(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_words_match_values_not_keys(self):
        fns = "".join(re.search(r"\nfunction %s\(.*?\n\}" % n, SRC, re.S).group(0) for n in ("_tlText", "tlVisible"))
        js = """const window={}; const TL_SEV_RANK={informational:0,low:1,medium:2,high:3,critical:4};
%s
window._tlData=[
  {host:'VIRUS-PC', title:'Code injection — explorer.exe (1944)', artifacts:['pslist'], severity:'high', jev:{label:'true_positive'}},
  {host:'ALClient022', title:'SIGMA: Suspicious Service Path (logged as ALClient02.AdatumLab.local)', artifacts:['Windows.Hayabusa.Rules'], severity:'high'},
  {host:'ALClient04, ALClient06', title:'Shared binary', severity:'medium',
   parts:[{title:'peview.exe on ALClient04', finding_id:'f9'}]}];
const out={};
for(const q of ['virus-pc','INJECTION virus','adatumlab','peview','host','true_positive','pslist hayabusa','',' ']){
  window._tlf={status:{pending:1,true_positive:1,false_positive:1,known:1},artifact:'',host:'',sev:'informational',order:'time',q};
  out[q]=tlVisible().map(r=>r.host);
}
console.log(JSON.stringify(out));""" % fns
        out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(out["virus-pc"], ["VIRUS-PC"])
        self.assertEqual(out["INJECTION virus"], ["VIRUS-PC"])            # any order, any case
        self.assertEqual(out["adatumlab"], ["ALClient022"])               # the user inside a title
        self.assertEqual(out["peview"], ["ALClient04, ALClient06"])       # a grouped row's part
        self.assertEqual(out["host"], [])                                 # a key, not a value
        self.assertEqual(out["true_positive"], [])                        # Jev's hint is not searched
        self.assertEqual(out["pslist hayabusa"], [])                      # every word, same row
        self.assertEqual(len(out[""]), 3)
        self.assertEqual(len(out[" "]), 3)

    def test_the_box_repaints_rows_only(self):
        # tlSet -> tlPaint keeps the bar (and the caret) in place; tlBuild would not.
        self.assertIn("""oninput="tlSet('q',this.value)\"""", SRC)
        self.assertIn("function tlSet(k,v){window._tlf[k]=v;tlPaint();}", SRC)


if __name__ == "__main__":
    unittest.main()
