"""Online upgrade: the same version, and modules the box never installed.

plan.sh always re-applies intact when the package carries it, so the online
upgrade dialog showed "intact X -> X  UPGRADE" as a locked row: an operator
who only wanted to add a missing module had to re-download and re-apply the
whole platform. Same version must be a normal "no change" row (tick to
reinstall); a newer version stays a forced upgrade.

A module not chosen at install time is `enabled: false` in config.yaml; the
plan skipped it and the dialog dropped it, so a box installed with only
velociraptor was offered nothing to add. It must be offered, and ticking it
must switch it on in config.yaml (the engine skips a disabled module), with
nothing else in the file touched.

_fetch_plan / start_online_upgrade live in upgrade_routes.py, which needs
flask, so they are lifted out with ast and run against stubs (as
test_upgrade_scoped_fetch.py does).
"""
import ast
import json
import os
import re
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/routes/upgrade_routes.py")


def _load():
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)
           and n.name in ("_fetch_plan", "start_online_upgrade", "_enable_modules")]
    for f in fns:
        f.decorator_list = []
    ns = {"json": json, "re": re, "shlex": __import__("shlex"), "WORKDIR": "/x",
          "_plan_bootstrap_sh": lambda: "b.sh",
          "_installed_engine_needs_full_fetch": lambda: False,
          "jsonify": lambda d: d}
    exec(compile(ast.Module(body=fns, type_ignores=[]), SRC, "exec"), ns)
    return ns


NS = _load()


CONFIG = """domain: x
modules:
  # ELK -- a comment that must survive
  elk:
    enabled: false
    id: elastic
    password: '123123'
  iris:
    enabled: false   # off
    password: '123123'
  velociraptor:
    enabled: true
    nested:
      enabled: false
versions:
  backend: intact-20261021
"""
CFG = os.path.join(tempfile.mkdtemp(), "config.yaml")
sys.modules["services.auth_service"] = types.SimpleNamespace(config_path=lambda: CFG)


def plan_of(intact_current, intact_target):
    with open(CFG, "w") as fh:
        fh.write(CONFIG)
    modules = [{"module": "intact", "current": intact_current, "target": intact_target, "action": "upgrade"},
               {"module": "velociraptor", "current": "0.77.3", "target": "0.77.3", "action": "noop"},
               {"module": "aws_sigma", "target": "1.0", "action": "install"},
               {"module": "elk", "target": "9.5.5", "action": "skip", "note": "disabled in config.yaml"},
               {"module": "iris", "target": "v2.4.29", "action": "skip", "note": "disabled in config.yaml"},
               {"module": "plaso", "current": "20260720", "target": "20260720", "action": "skip",
                "note": "disabled in config.yaml"},
               {"module": "o365rc", "action": "skip", "note": "not in this package"}]
    NS["run_command"] = lambda *a, **k: {"success": True, "stdout": json.dumps({"modules": modules})}


def start(body, launch=("started", 202)):
    calls = []
    NS["request"] = types.SimpleNamespace(json=body)
    NS["_start_launcher_run"] = lambda kind, name, meta, args, force=False: calls.append(args) or launch
    out = NS["start_online_upgrade"]()
    return (calls[-1] if calls else None), out


class SameVersion(unittest.TestCase):
    def setUp(self):
        plan_of("intact-20261021", "intact-20261021")

    def test_intact_row_is_no_change(self):
        plan, err = NS["_fetch_plan"]("intact-20261021")
        self.assertIsNone(err)
        self.assertEqual("noop", next(r for r in plan["forced"] if r["module"] == "intact")["action"])

    def test_only_the_missing_module_is_fetched_and_applied(self):
        args, _ = start({"target": "intact-20261021", "opted_in_optional": ["aws_sigma"]})
        self.assertEqual(["intact-20261021", "--only", "aws_sigma"], args)

    def test_ticking_intact_reinstalls_it(self):
        args, _ = start({"target": "intact-20261021", "opted_in_reinstall": ["intact"]})
        self.assertEqual(["intact-20261021", "--only", "intact", "--reinstall", "intact"], args)

    def test_nothing_ticked_starts_nothing(self):
        args, out = start({"target": "intact-20261021"})
        self.assertIsNone(args)
        self.assertEqual(400, out[1])


class ModulesNeverInstalled(unittest.TestCase):
    def setUp(self):
        plan_of("intact-20261021", "intact-20261021")

    def test_disabled_modules_are_offered(self):
        plan, _ = NS["_fetch_plan"]("intact-20261021")
        # plaso too: its "current" is a constant pin, not a sign it is installed
        self.assertEqual(["aws_sigma", "elk", "iris", "plaso"], [r["module"] for r in plan["optional"]])

    def test_ticking_one_switches_only_its_flag_on(self):
        args, _ = start({"target": "intact-20261021", "opted_in_optional": ["elk"]})
        self.assertEqual(["intact-20261021", "--only", "elk"], args)
        self.assertEqual(CONFIG.replace("  elk:\n    enabled: false", "  elk:\n    enabled: true"), open(CFG).read())

    def test_a_refused_start_switches_it_back_off(self):
        start({"target": "intact-20261021", "opted_in_optional": ["elk", "iris"]}, launch=("busy", 409))
        self.assertEqual(CONFIG, open(CFG).read())

    def test_inline_comment_is_kept(self):
        start({"target": "intact-20261021", "opted_in_optional": ["iris"]})
        self.assertIn("    enabled: true   # off\n", open(CFG).read())


class NewerVersion(unittest.TestCase):
    def test_intact_stays_a_forced_upgrade(self):
        plan_of("intact-20261021", "intact-20261108")
        plan, _ = NS["_fetch_plan"]("intact-20261108")
        self.assertEqual("upgrade", next(r for r in plan["forced"] if r["module"] == "intact")["action"])
        args, _ = start({"target": "intact-20261108", "opted_in_optional": ["aws_sigma"]})
        self.assertEqual(["intact-20261108", "--only", "intact,aws_sigma"], args)


if __name__ == "__main__":
    unittest.main()
