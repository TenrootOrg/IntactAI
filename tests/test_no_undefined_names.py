"""No name is used in the QA harness without ever being bound.

This exists because of a single line. `qa/phases/upgrade.py` referenced
`_SELF_ASSERTING`, a constant that was never defined, on the path every upgrade
route takes. It compiles -- Python resolves globals at call time, not at import
-- so nothing local caught it, and the whole test suite passed. In CI it cost
nine of eleven scenarios: each one installed an appliance, ran the upgrade to
completion, and then died with `NameError` while reading the result. Roughly two
hours of runner time to discover a typo.

The check is deliberately an OVER-approximation of what is bound: every name
bound anywhere in the file counts, at any scope. That will not catch a name
defined in one function and used in another, and it is not meant to -- it
catches the case that actually happened, a name bound in NO scope at all, and
it does so with no dependency to install. `run_tests.sh` runs on a dev box, in
CI and on a live appliance, so a check that needs pyflakes is a check that does
not run in two of those three places.
"""

import ast
import builtins
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QA = os.path.join(ROOT, "qa")


def _python_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


class _Bindings(ast.NodeVisitor):
    """Every name this module binds, in any scope, by any means."""

    def __init__(self):
        self.bound = set()
        self.star_import = False

    def _bind(self, target):
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                self.bound.add(node.id)

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bound.add(node.id)
        self.generic_visit(node)

    def visit_arg(self, node):
        self.bound.add(node.arg)
        self.generic_visit(node)

    def _visit_def(self, node):
        self.bound.add(node.name)
        self.generic_visit(node)

    visit_FunctionDef = _visit_def
    visit_AsyncFunctionDef = _visit_def
    visit_ClassDef = _visit_def

    def visit_Import(self, node):
        for alias in node.names:
            self.bound.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == "*":
                # Anything could be in scope; this file cannot be judged.
                self.star_import = True
            else:
                self.bound.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.bound.add(node.name)
        self.generic_visit(node)

    def visit_Global(self, node):
        self.bound.update(node.names)

    def visit_Nonlocal(self, node):
        self.bound.update(node.names)


def _loaded_names(tree):
    """Names read (not written), with the line each was read on."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            out.append((node.id, node.lineno))
    return out


def undefined_names(source):
    """[(name, lineno)] used but bound nowhere. Empty for a star-import file."""
    tree = ast.parse(source)
    b = _Bindings()
    b.visit(tree)
    if b.star_import:
        return []
    known = b.bound | set(dir(builtins)) | {"__file__", "__name__", "__doc__"}
    seen, out = set(), []
    for name, lineno in _loaded_names(tree):
        if name not in known and name not in seen:
            seen.add(name)
            out.append((name, lineno))
    return out


class TestNoUndefinedNames(unittest.TestCase):

    def test_the_checker_actually_catches_one(self):
        """A guard that cannot fail is not a guard.

        This is the exact shape of the bug that prompted the file: a constant
        referenced on a live code path and defined nowhere."""
        found = undefined_names(
            "def f(cfg):\n"
            "    if cfg.scenario in _SELF_ASSERTING:\n"
            "        return 1\n")
        self.assertEqual([n for n, _ in found], ["_SELF_ASSERTING"])

    def test_the_checker_does_not_cry_wolf(self):
        """Ordinary bindings must not be reported: imports, args, loop targets,
        comprehensions, except-as, walrus and attribute access."""
        clean = (
            "import os\n"
            "from json import dumps\n"
            "TABLE = {'a': 1}\n"
            "def f(arg, *rest, **kw):\n"
            "    total = 0\n"
            "    for item in rest:\n"
            "        total += item\n"
            "    squares = [x * x for x in range(int(arg))]\n"
            "    with open(os.devnull) as fh:\n"
            "        fh.read()\n"
            "    try:\n"
            "        pass\n"
            "    except OSError as exc:\n"
            "        print(exc)\n"
            "    if (n := len(squares)) > 1:\n"
            "        total += n\n"
            "    return dumps(TABLE), total, kw\n")
        self.assertEqual(undefined_names(clean), [])

    def test_the_qa_harness_has_none(self):
        files = list(_python_files(QA))
        self.assertTrue(files, "found no QA sources to check — wrong path?")
        problems = []
        for path in files:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            for name, lineno in undefined_names(source):
                rel = os.path.relpath(path, ROOT)
                problems.append(f"{rel}:{lineno}: {name}")
        self.assertFalse(
            problems,
            "used but never bound anywhere in the file:\n  "
            + "\n  ".join(problems))


if __name__ == "__main__":
    unittest.main(verbosity=2)
