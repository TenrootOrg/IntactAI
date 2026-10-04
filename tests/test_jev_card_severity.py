"""Jev's estimate on a phase card reads on the app's severity scale, each band in
its own colour ("give each percentage different color and severity"): the cards
were one blue line, so 66% looked like 86%. Runs the real _ztJev from cases.html.
"""
import json
import os
import re
import shutil
import subprocess
import unittest

SRC = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "modules/nginx/html/cases.html"), encoding="utf-8").read()


@unittest.skipIf(shutil.which("node") is None, "node is not installed")
class JevCardSeverity(unittest.TestCase):
    def test_each_band_has_its_severity_and_colour(self):
        js = (re.search(r"const _JEV_SEV=.*?;", SRC).group(0) + "\n"
              + re.search(r"function _jevSev\(p\)\{.*?\}\n", SRC).group(0)
              + re.search(r"function _ztJev\(t\)\{.*?\n\}", SRC, re.S).group(0)
              + "\nconsole.log(JSON.stringify([0.86,0.85,0.84,0.75,0.6,0.55,0.4,0.35,0.34].map(p=>_ztJev({jev_p:p})).concat([_ztJev({})])));")
        out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)
        sev = [re.search(r'chip c-(\w+)', h).group(1) for h in out[:-1]]
        self.assertEqual(sev, ["critical", "critical", "high", "high", "medium", "medium", "low", "low",
                               "informational"])                    # 60% is medium (QA), not high
        self.assertIn("color:var(--crit);font-weight:600\">86%</span>", out[0])
        self.assertIn("color:var(--high);font-weight:600\">84%</span>", out[2])   # critical starts at 85%
        self.assertEqual(out[-1], "")                       # no estimate: nothing on the card


if __name__ == "__main__":
    unittest.main()
