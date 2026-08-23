"""Two mistakes that compile fine and only fail when the line finally runs.

Both happened here, in one edit, and shipped:

    def set_disposition(case_id, target, *, verdict="benign", ...):   # no `trigger`
        ...
        fuse_case(case_id, trigger=trigger or TRIGGER_DISPOSITION)    # NameError

    decide_checklist_item -> set_disposition(..., trigger=TRIGGER_CHECKLIST)
                                                   # TypeError: unexpected kwarg

Python resolves both at call time, so the module imported, every static check
passed, and the whole suite stayed green. They surfaced only when a probe drove
the real functions -- and they had already been committed, pushed and deployed.
Every disposition path was broken: marking a timeline row not-real, accepting a
checklist item, dispositioning from the Risk tab.

The existing test_no_undefined_names.py could not have caught it. It covers qa/
only, and by design it is an over-approximation that counts a name bound ANYWHERE
in the file -- `trigger` is a parameter of fuse_case in the same module, so it
looked bound. These two checks are scope-aware instead.

Neither needs anything installed: ast + builtins, like the rest of this suite.
"""

import ast
import builtins
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")

_BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__",
                                  "__spec__", "__package__", "__builtins__"}


def _py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for f in sorted(filenames):
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)


def _params(fn):
    a = fn.args
    out = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        out.append(a.vararg.arg)
    if a.kwarg:
        out.append(a.kwarg.arg)
    return out


def _binds(node, *, descend=False):
    """Names bound directly in `node`'s own scope.

    `descend=False` deliberately does NOT enter nested function/class bodies: a
    parameter of one function is not a binding in another. Collecting them all
    with a flat ast.walk is precisely the over-approximation that let the shipped
    NameError look bound — `trigger` was a parameter of fuse_case, in the same
    module, so a flat walk called it defined. Nested def/class NAMES are still
    recorded, because those really are bound in the enclosing scope.

    Comprehension targets are folded in even though Python scopes them tighter.
    That only makes this permissive, never wrong: it cannot manufacture a
    false positive, and it is not the class of bug being hunted.
    """
    out = set()

    def add(t):
        if isinstance(t, ast.Name):
            out.add(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                add(e)
        elif isinstance(t, ast.Starred):
            add(t.value)

    def visit(n, top=False):
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(c.name)
                if descend:
                    visit(c)
                continue
            if isinstance(c, ast.Lambda):
                continue                      # its params belong to the lambda alone
            if isinstance(c, ast.Assign):
                for t in c.targets:
                    add(t)
            elif isinstance(c, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
                add(c.target)
            elif isinstance(c, (ast.For, ast.AsyncFor)):
                add(c.target)
            elif isinstance(c, (ast.Import, ast.ImportFrom)):
                for a in c.names:
                    out.add((a.asname or a.name).split(".")[0])
            elif isinstance(c, ast.ExceptHandler) and c.name:
                out.add(c.name)
            elif isinstance(c, (ast.With, ast.AsyncWith)):
                for it in c.items:
                    if it.optional_vars is not None:
                        add(it.optional_vars)
            elif isinstance(c, (ast.Global, ast.Nonlocal)):
                out.update(c.names)
            elif isinstance(c, ast.comprehension):
                add(c.target)
            visit(c)

    visit(node, top=True)
    return out


def _own_names(fn):
    """Names LOADED in `fn`'s own scope — not those inside a nested function or
    lambda, which are checked separately against their own scope chain."""
    found = []

    def visit(n):
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(c, ast.Name) and isinstance(c.ctx, ast.Load):
                found.append(c)
            visit(c)

    visit(fn)
    return found


def _has_star_import(tree):
    """`from x import *` puts names in scope that no static pass can see."""
    return any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
               for n in ast.walk(tree))


def _parents(tree):
    p = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            p[c] = n
    return p


class TestNoUnboundNames(unittest.TestCase):
    """A name loaded in a function must be bound somewhere in its scope chain."""

    def test_backend_has_no_unbound_names(self):
        offences = []
        for path in _py_files(BACKEND):
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            if _has_star_import(tree):
                continue          # names arrive invisibly; not statically decidable
            module_scope = _binds(tree) | _BUILTINS
            parents = _parents(tree)
            for fn in [n for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                                         ast.Lambda))]:
                scope = module_scope | set(_params(fn)) | _binds(fn)
                p = parents.get(fn)
                while p is not None:
                    if isinstance(p, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        scope |= set(_params(p)) | _binds(p)
                    elif isinstance(p, ast.ClassDef):
                        scope |= _binds(p) | {"self", "cls"}
                    p = parents.get(p)
                for n in _own_names(fn):
                    if n.id not in scope:
                        offences.append("%s:%d  %s() uses '%s', bound in no scope"
                                        % (os.path.relpath(path, ROOT), n.lineno,
                                           getattr(fn, "name", "<lambda>"), n.id))
        self.assertEqual(offences, [], "\n" + "\n".join(sorted(set(offences))))

    def test_the_check_catches_the_bug_it_was_written_for(self):
        """Non-vacuity, in the exact shape that shipped."""
        src = ("def fuse_case(case_id, *, trigger=None):\n"
               "    return trigger\n"
               "def set_disposition(case_id, target, *, verdict='benign'):\n"
               "    return fuse_case(case_id, trigger=trigger or 'x')\n")
        tree = ast.parse(src)
        module_scope = _binds(tree) | _BUILTINS
        fn = [n for n in tree.body if getattr(n, "name", "") == "set_disposition"][0]
        scope = module_scope | set(_params(fn)) | _binds(fn)
        loaded = {n.id for n in _own_names(fn)}
        self.assertIn("trigger", loaded - scope,
                      "the checker would not have caught the shipped NameError")

    def test_a_correct_function_is_not_flagged(self):
        src = ("def set_disposition(case_id, *, trigger=None):\n"
               "    return trigger or 'x'\n")
        tree = ast.parse(src)
        fn = tree.body[0]
        scope = _binds(tree) | _BUILTINS | set(_params(fn)) | _binds(fn)
        loaded = {n.id for n in _own_names(fn)}
        self.assertEqual(loaded - scope, set())


class TestKeywordsMatchSignatures(unittest.TestCase):
    """A keyword passed to a function defined in the same module must exist.

    This is the other half of the same edit: the call site said
    `set_disposition(..., trigger=...)` while the callee had no such parameter.
    Only intra-module calls are checked -- resolving imported callees would need
    real import machinery, and this suite deliberately has none.
    """

    def test_no_call_passes_an_unknown_keyword(self):
        offences = []
        for path in _py_files(BACKEND):
            with open(path, encoding="utf-8") as f:
                src = f.read()
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            defs = {}
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # A name defined twice (conditionals, decorated overloads)
                    # is ambiguous — skip rather than guess.
                    defs[n.name] = None if n.name in defs else n
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call) or not isinstance(n.func, ast.Name):
                    continue
                fn = defs.get(n.func.id)
                if fn is None:
                    continue
                if fn.args.kwarg:                    # **kwargs accepts anything
                    continue
                accepted = set(_params(fn))
                for kw in n.keywords:
                    if kw.arg is None:               # **spread — unknowable
                        continue
                    if kw.arg not in accepted:
                        offences.append(
                            "%s:%d  %s(%s=...) — %s() has no such parameter"
                            % (os.path.relpath(path, ROOT), n.lineno,
                               n.func.id, kw.arg, n.func.id))
        self.assertEqual(offences, [], "\n" + "\n".join(sorted(set(offences))))

    def test_the_check_catches_the_bug_it_was_written_for(self):
        src = ("def set_disposition(case_id, *, verdict='benign'):\n"
               "    pass\n"
               "def decide(case_id):\n"
               "    set_disposition(case_id, trigger='x')\n")
        tree = ast.parse(src)
        target = [n for n in tree.body if getattr(n, "name", "") == "set_disposition"][0]
        call = [n for n in ast.walk(tree) if isinstance(n, ast.Call)][0]
        accepted = set(_params(target))
        self.assertNotIn(call.keywords[0].arg, accepted)

    def test_kwargs_functions_are_not_flagged(self):
        src = ("def f(a, **kw):\n    pass\ndef g():\n    f(1, anything=2)\n")
        tree = ast.parse(src)
        target = tree.body[0]
        self.assertTrue(target.args.kwarg, "the **kwargs escape hatch must be honoured")


if __name__ == "__main__":
    unittest.main(verbosity=2)
