"""Fusion must not be tuned to the test datasets.

Fusion is scored against public attack datasets (Szechuan Sauce, APT29 Day 1/2,
AdatumLab; scripts/dev/groundtruth_steps.json). A rule that matched one of their file
names, IPs, hosts or accounts would raise the score and help no real customer -- every
environment has different hosts, sizes and timelines. So no fusion CODE (string
constants, identifiers) and no weighting RULE may name them. Comments and docstrings
may, and do: they record the incident a change came from.
"""
import ast
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUSION = os.path.join(ROOT, "modules/backend/services/fusion")
WEIGHTING = os.path.join(ROOT, "modules/backend/config/fusion_weighting.yaml")

# Facts of the scored datasets: payload/file names, attacker IPs, hosts, domains, accounts.
DATASET_FACTS = re.compile(
    r"3aka3|monkey\.png|javamtsup|hostui|kxwn|coreupdat|outmgo|nehgye|mszhao|pmhrio|"
    r"9seocawv|q9z1bssi|officesupplies|draft\.zip|windowsparentalcontrolmigration|"
    r"194\.61\.24\.102|203\.78\.103\.109|192\.168\.0\.[45]\b|"
    r"dmevals|c137|citadel|sdn1rpt|scranton|nashua|newyork|\butica\b|adatum|"
    r"dschrute|pbeesly|mscott|kmalone|rickSanchez|mortysmith|\btoby\b", re.I)


def _code_strings(path):
    """String constants and identifiers of a module, docstrings excluded."""
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
                docs.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
            yield node.lineno, node.value
        elif isinstance(node, ast.Name):
            yield node.lineno, node.id
        elif isinstance(node, ast.Attribute):
            yield node.lineno, node.attr


class NoDatasetFactsInFusion(unittest.TestCase):
    def test_fusion_code_names_no_test_dataset(self):
        hits = []
        for path in glob.glob(os.path.join(FUSION, "**", "*.py"), recursive=True):
            if "/tests/" in path:
                continue
            for line, s in _code_strings(path):
                if DATASET_FACTS.search(s):
                    hits.append(f"{os.path.relpath(path, ROOT)}:{line}: {s[:80]!r}")
        self.assertEqual([], hits)

    def test_weighting_rules_name_no_test_dataset(self):
        """The `when` side of a rule is matching logic; `examples` and reasons are prose."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with open(WEIGHTING, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        rules = [r for k in ("entity_rules", "pattern_rules") for r in (doc.get(k) or [])]
        self.assertTrue(rules, "no rules read -- the catalogue's keys changed")
        hits = [r.get("id") for r in rules if isinstance(r, dict) and DATASET_FACTS.search(str(r.get("when") or ""))]
        self.assertEqual([], hits)

    def test_the_check_would_catch_one(self):
        self.assertTrue(DATASET_FACTS.search("C:\\Windows\\System32\\coreupdater.exe"))
        self.assertTrue(DATASET_FACTS.search("dmevals.local"))
        self.assertFalse(DATASET_FACTS.search("domain controller"))


if __name__ == "__main__":
    unittest.main()
