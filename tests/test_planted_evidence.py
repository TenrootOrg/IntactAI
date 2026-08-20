"""The evidence we plant must be evidence the product actually scores.

A clean CI runner has nothing malicious on it, so a collection from one yields
`findings: 0` and the fusion check falls back to `relationships > 0` — which
process-tree edges satisfy on any Linux box, working or not. Measured on a real
run: 33 entities, 7 relationships, zero findings. Planting evidence is what
turns that check from "did anything correlate" into "did it find the thing we
put there".

Which only holds while the planted items still match the mapper's rules. If
someone tightens _LINUX_SUSP or the SUID path list, the plants would quietly
stop scoring and the fusion assertion would go back to being decorative — with
nothing failing to say so. These tests read the rules out of the PRODUCT and
check the planted values against them, so the two cannot drift apart silently.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAPPER = os.path.join(ROOT, "modules/backend/services/fusion/mappers/agentic.py")
PLANT = os.path.join(ROOT, "qa/lib/plant.py")


def _plant_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("qa_plant", PLANT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _susp_tokens():
    """_LINUX_SUSP, read out of the mapper itself."""
    src = open(MAPPER, encoding="utf-8").read()
    m = re.search(r"_LINUX_SUSP\s*=\s*\((.*?)\)\n", src, re.S)
    return tuple(re.findall(r'"([^"]+)"', m.group(1))) if m else ()


def _standard_suid_prefixes():
    """The paths the mapper considers unremarkable for a SUID binary."""
    src = open(MAPPER, encoding="utf-8").read()
    m = re.search(r'std = any\(path\.startswith\(p\) for p in \((.*?)\)\)',
                  src, re.S)
    return tuple(re.findall(r'"([^"]+)"', m.group(1))) if m else ()


class TestPlantedEvidenceStillScores(unittest.TestCase):

    def setUp(self):
        self.plant = _plant_module()
        self.susp = _susp_tokens()
        self.std = _standard_suid_prefixes()
        # A parser returning nothing would make every assertion below vacuous.
        self.assertTrue(self.susp, "_LINUX_SUSP did not parse from the mapper")
        self.assertTrue(self.std, "the SUID standard-path list did not parse")

    def test_the_planted_cron_command_is_one_the_mapper_calls_suspicious(self):
        src = open(PLANT, encoding="utf-8").read()
        m = re.search(r'\*/17 \* \* \* \* root ([^"\\\n]+)', src)
        self.assertTrue(m, "could not find the planted cron command")
        cmd = m.group(1).lower()
        hits = [tok for tok in self.susp if tok in cmd]
        self.assertTrue(
            hits,
            "the planted cron command matches nothing in _LINUX_SUSP, so it "
            "would score 4 instead of 60 and produce no finding: " + cmd)

    def test_the_planted_suid_path_is_outside_the_standard_locations(self):
        path = self.plant.SUID_PATH
        self.assertFalse(
            any(path.startswith(p) for p in self.std),
            f"{path} is inside a standard SUID location, so the mapper scores "
            f"it 2 rather than 60 and no finding appears")

    def test_the_planted_ssh_key_carries_a_forced_command(self):
        """`command=` is what makes the mapper share the backdoor event id with
        Linux.Detection.SSHKeyFileCmd; without it the key is just a key."""
        src = open(PLANT, encoding="utf-8").read()
        self.assertIn('command="', src,
                      "the planted authorized_keys line has no forced command")
        self.assertIn("has_cmd", open(MAPPER, encoding="utf-8").read(),
                      "the mapper no longer looks for a forced command")

    def test_planting_is_reversible(self):
        """It writes to /etc/passwd and /etc/cron.d. Every item must be removed
        again, or a machine that is not a throwaway runner keeps a uid-0
        account."""
        src = open(PLANT, encoding="utf-8").read()
        unplant = src[src.index("def unplant("):]
        for path_attr in ("CRON_PATH", "SUID_PATH", "AUTHKEYS"):
            self.assertIn(path_attr.replace("CRON_PATH", "{CRON_PATH}")
                          .replace("SUID_PATH", "{SUID_PATH}")
                          .replace("AUTHKEYS", "{AUTHKEYS}"), unplant,
                          f"unplant does not remove {path_attr}")
        self.assertIn("{FAKE_USER}", unplant,
                      "unplant does not remove the uid-0 account")

    def test_planting_is_off_by_default(self):
        cfg = open(os.path.join(ROOT, "qa/lib/config.py"), encoding="utf-8").read()
        self.assertIn('self.get("run", "plant_evidence", default=False)', cfg,
                      "planting must default to OFF — it modifies /etc/passwd")


if __name__ == "__main__":
    unittest.main(verbosity=2)
