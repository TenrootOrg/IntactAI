"""Every function the HTML calls must still exist somewhere in the JavaScript.

WHY. modules/nginx/html is 15k lines across 43 files and had no net at all --
exactly two functions in the whole tree have executed tests
(tests/chat_inflight_turn.js and the blueprint filter). The specific hazard when
deleting "dead" frontend code is that Alpine binds handlers by STRING NAME in
HTML attributes:

    <button @click="startCollection()">

`startCollection` appears nowhere in any .js file as a caller, so every
reference-counting tool calls it dead. Deleting it produces no error at build
time, no error at page load, and a button that silently does nothing.

So this checks the direction that actually breaks: HTML -> JS. Every name
called from an Alpine attribute must be defined somewhere in the first-party
JavaScript or an inline <script>.

Deliberately an OVER-APPROXIMATION, the same trade-off tests/test_no_undefined_names.py
already makes for qa/: a name counts as defined if it is bound ANYWHERE -- a
top-level function, a const arrow, a window.* assignment, an object method, a
store action. Alpine resolves component methods against the component's own
scope, which cannot be recovered without evaluating the page, so a stricter
check would be wrong rather than useful. It still catches the thing that
matters: a name that no longer exists ANYWHERE.

Vendored code (alpine.min.js, vendor/) is excluded.
"""

import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML_ROOT = os.path.join(ROOT, "modules/nginx/html")
VENDOR = ("alpine.min.js", "/vendor/")

# Attributes whose value Alpine evaluates as JavaScript.
ATTR = re.compile(
    r'(?:x-on:[a-zA-Z0-9.\-]+|@[a-zA-Z0-9.\-]+|x-show|x-if|x-model|x-init|'
    r'x-data|x-text|x-html|x-effect|x-bind:[a-zA-Z0-9.\-]+|:[a-zA-Z][a-zA-Z0-9.\-]*|'
    # Plain inline handlers. This codebase mixes them with Alpine, and leaving
    # them out left a real hole: index.html's offline-config modal called
    # closeConfigModal() and saveOfflineConfig() through onclick=, so deleting
    # both functions kept the board green.
    r'on[a-z]+)'
    r'\s*=\s*"([^"]*)"')
CALL = re.compile(r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(')

# Anything that binds a name, in any of the styles this codebase uses.
DEFS = [
    re.compile(r'\bfunction\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'),
    re.compile(r'\b(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'),
    re.compile(r'\bwindow\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*='),
    re.compile(r'^\s*(?:async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*\{', re.M),
    re.compile(r'^\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*(?:async\s+)?(?:function|\()', re.M),
    re.compile(r'\bAlpine\.(?:data|store|magic)\(\s*[\'"]([a-zA-Z0-9_$]+)[\'"]'),
    # `get selectedAwsBlueprint() {` -- a computed property, called from the
    # template without parentheses but matched here for completeness.
    re.compile(r'\bget\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\('),
]

# Evaluated in Alpine's scope or the browser's, never defined by us.
BUILTIN = set("""
Alpine $store $el $refs $event $dispatch $nextTick $watch $data $id $root
window document console JSON Math Date Object Array String Number Boolean
Promise Set Map RegExp Error parseInt parseFloat isNaN encodeURIComponent
decodeURIComponent decodeURI encodeURI setTimeout setInterval clearTimeout
clearInterval fetch alert confirm prompt localStorage sessionStorage
String Symbol BigInt structuredClone URLSearchParams URL FormData Blob
Intl Number toFixed if for while switch return typeof instanceof new
async await function class delete void do else try catch finally throw yield
of in isFinite isNaN Infinity NaN undefined null true false this super
flatpickr tus Uint8Array ArrayBuffer TextEncoder TextDecoder AbortController
Element HTMLElement Event CustomEvent MutationObserver IntersectionObserver
navigator location history requestAnimationFrame queueMicrotask crypto
""".split())

# Globals supplied by vendored libraries that are loaded before our scripts.
# Not defined by us, so they would otherwise read as missing.


def _files(*exts):
    out = subprocess.run(["git", "ls-files", "modules/nginx/html"],
                         cwd=ROOT, capture_output=True, text=True).stdout.split()
    return [f for f in out
            if f.endswith(exts) and not any(v in f for v in VENDOR)]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
        return fh.read()


class TestEveryNameTheHtmlCallsExists(unittest.TestCase):
    def test_it(self):
        js = "\n".join(_read(f) for f in _files(".js"))
        html_files = _files(".html")
        html = "\n".join(_read(f) for f in html_files)
        # Definitions live in three places, and all three count:
        #   1. the .js files
        #   2. inline <script> blocks
        #   3. the x-data ATTRIBUTE itself -- this codebase writes whole Alpine
        #      components inline, e.g. partials/aws.html:100 defines
        #      `async startAwsScan() {` inside x-data="{...}". Miss this and the
        #      check reports every handler on the page as undefined.
        inline = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", html, re.S))
        attr_bodies = "\n".join(v for f in html_files for v in ATTR.findall(_read(f)))
        haystack = js + "\n" + inline + "\n" + attr_bodies

        defined = set(BUILTIN)
        for pat in DEFS:
            defined.update(pat.findall(haystack))

        self.assertGreater(len(defined), 200,
                           "the definition scan found almost nothing -- the "
                           "patterns stopped matching this codebase")

        missing = {}
        for rel in html_files:
            for expr in ATTR.findall(_read(rel)):
                # Strip everything in the attribute that is text rather than
                # code. This codebase writes whole Alpine components inline, so
                # an x-data attribute contains comments and template literals,
                # and each of these produced a false "undefined function":
                #   'Download support bundle (' -> bundle
                #   // Time filter - relative (...)  -> relative
                #   `... per region (~${x})`         -> region
                # ${...} interpolations are KEPT, because those really do run.
                expr = re.sub(r"'[^']*'", "''", expr)
                expr = re.sub(r'(?m)//.*$', '', expr)
                expr = re.sub(r'`[^`]*`',
                              lambda m: " ".join(re.findall(r'\$\{(.*?)\}',
                                                            m.group(0), re.S)),
                              expr)
                for m in CALL.finditer(expr):
                    name = m.group(1)
                    if name in defined:
                        continue
                    # `foo.bar()`, `x().then()`, `s.trim()` -- the method belongs
                    # to the receiver, not to us. Decided by the character before
                    # the name, which is exact; a regex over the whole expression
                    # was not, and reported map/split/then/trim as missing.
                    before = expr[:m.start(1)].rstrip()
                    # `.` -> a method on the receiver. `$` -> an Alpine magic
                    # ($nextTick, $watch, $dispatch): the regex starts matching
                    # after the $ because $ is not a word character.
                    if before.endswith(".") or before.endswith("$"):
                        continue
                    missing.setdefault(name, set()).add(rel)

        self.assertEqual(
            {}, {k: sorted(v) for k, v in missing.items()},
            "these names are called from an HTML attribute but defined nowhere")


class TestEveryNameTheJavaScriptCallsExists(unittest.TestCase):
    """The other direction: JS -> JS.

    Added after it caught a real break during the ponytail campaign. The
    HTML->JS check above was green while `populateConfigDropdown` had just been
    deleted, because its two callers are both JavaScript:

        js/stores/app.js:209   loadOfflineBlueprints().then(() => populateConfigDropdown())
        js/velociraptor.js:44  populateConfigDropdown()

    and the <select id="offline-gen-config"> it fills is live in
    partials/velociraptor.html. A green board, and the offline-collector
    dropdown would have shipped empty.

    Same over-approximation as above: a name counts as defined if it is bound
    anywhere. Only bare calls are checked -- `foo()`, never `x.foo()` -- because
    a method belongs to its receiver.
    """

    def test_it(self):
        js_files = _files(".js")
        haystack = "\n".join(_read(f) for f in js_files)
        html = "\n".join(_read(f) for f in _files(".html"))
        haystack += "\n" + "\n".join(
            re.findall(r"<script[^>]*>(.*?)</script>", html, re.S))

        defined = set(BUILTIN)
        for pat in DEFS:
            defined.update(pat.findall(haystack))
        # A parameter is a local binding, not a missing global: `initDropzone(
        # id, input, onFileSelected)` then calls `onFileSelected(...)`. Same for
        # a catch binding and a Promise executor's `resolve`/`reject`.
        for grp in re.findall(r'\(([^)]*)\)\s*(?:=>|\{)', haystack):
            for part in grp.split(","):
                # strip( "()" too: `new Promise((resolve) => {` leaves the
                # capture as "(resolve" because ( is legal inside the group.
                nm = part.strip().split("=")[0].strip("() \t.")
                if re.fullmatch(r'[a-zA-Z_$][\w$]*', nm or ""):
                    defined.add(nm)
        defined.update(re.findall(r'\bcatch\s*\(\s*([a-zA-Z_$][\w$]*)', haystack))

        missing = {}
        for rel in js_files:
            src = _read(rel)
            src = re.sub(r'(?m)//.*$', '', src)
            src = re.sub(r'/\*.*?\*/', '', src, flags=re.S)
            src = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", "''", src)
            # Template literals are text; `${...}` inside them is code. Without
            # this, `${n} plugin(s)` reports `plugin` as an undefined function.
            src = re.sub(r'`[^`]*`',
                         lambda m: " ".join(re.findall(r'\$\{(.*?)\}',
                                                       m.group(0), re.S)),
                         src)
            for m in CALL.finditer(src):
                name = m.group(1)
                if name in defined:
                    continue
                before = src[:m.start(1)].rstrip()
                if before.endswith(".") or before.endswith("$"):
                    continue
                # `function foo(`, `new Foo(`, `catch (e)` are not calls
                if re.search(r'\b(function|new|class)\s*$', before):
                    continue
                missing.setdefault(name, set()).add(rel)

        self.assertEqual(
            {}, {k: sorted(v) for k, v in missing.items()},
            "these names are called from JavaScript but defined nowhere")


class TestEveryFirstPartyScriptParses(unittest.TestCase):
    def test_it(self):
        import shutil
        if not shutil.which("node"):
            self.skipTest("node not installed")
        bad = []
        for rel in _files(".js"):
            r = subprocess.run(["node", "--check", os.path.join(ROOT, rel)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                bad.append(f"{rel}: {r.stderr.strip().splitlines()[:2]}")
        self.assertEqual([], bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
