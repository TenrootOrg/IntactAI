"""The Case Analysis host picker must not let a hostname break out of an attribute.

`cases.html` renders each host row with an inline handler:

    onchange="toggleHost('<host>',this.checked)"

and used to build `<host>` with `esc(h.host).replace(/'/g,"\\'")`. `esc()`
encodes only `&`, `<` and `>` — not `"` — while the attribute it lands in is
double-quoted. So a host name containing a double quote closed `onchange` and
could append sibling attributes (`" onmouseover=... x="`) on the same tag.

That value is not operator-typed. `h.host` comes from `/api/cases/<id>/hosts`,
which reads asset labels out of the fused graph — i.e. hostnames harvested from
endpoint enrollment. In an IR engagement the endpoint is the compromised
machine, so this is stored XSS that fires whenever another analyst opens the
picker, not self-XSS.

The page already had the right helper: `jsa()`, written for exactly this shape
(its own comment says so) and handling backslash, quote, newline, `&<>` AND `"`.
The fix is to use it.

There is no JS runtime in this environment, so rather than reimplement the
helpers (which would test the copy, not the shipped code) this reads the actual
replace-chain out of cases.html and applies it. If someone edits `jsa()`, this
test follows.

Run: docker exec intact_backend python3 /app/workdir/tests/test_cases_host_picker_escaping.py
"""

import os
import re
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

CASES_HTML = os.path.join(
    os.environ.get("INTACT_PATH", "/app/workdir"),
    "modules/nginx/html/cases.html",
)

# A hostname that closes the double-quoted attribute and adds a new handler.
PAYLOAD = 'a" onmouseover=alert(1) x="'


def _src():
    with open(CASES_HTML, encoding="utf-8") as fh:
        return fh.read()


def _apply_js_replace_chain(func_src, value):
    """Run a JS `.replace(/pat/g, 'repl')` chain against a Python string.

    Only the literal-pattern forms the helpers actually use are supported; an
    unrecognised step raises rather than silently passing the value through,
    so this can never report a payload as neutralised because it failed to
    parse the escaping.
    """
    steps = re.findall(r"\.replace\(/(.+?)/g\s*,\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')\)",
                       func_src)
    assert steps, f"no replace chain parsed from: {func_src[:120]}"
    out = value
    for pat, repl in steps:
        # JS string literal -> python (handles the \\' and \\\\ forms used here)
        r = repl[1:-1].replace('\\\\', '\x00').replace("\\'", "'").replace('\\"', '"')
        r = r.replace('\x00', '\\')
        if pat == r"\\":
            out = out.replace("\\", r)
        elif pat == r"\r?\n":
            out = re.sub(r"\r?\n", r, out)
        elif len(pat) == 1 or pat in ("'", '"', "&", "<", ">"):
            out = out.replace(pat, r)
        else:
            raise AssertionError(f"unhandled replace pattern {pat!r} — update this test")
    return out


def test_host_picker_uses_the_attribute_safe_helper():
    """The regression guard. esc() in an on*="…" attribute is the bug."""
    src = _src()
    # Non-greedy to `)"` — the argument itself contains a `)` (jsa(h.host)),
    # so a [^)]* class stops inside the expression and never matches.
    m = re.search(r'onchange="toggleHost\((.+?)\)"', src)
    assert m, "the host picker's onchange handler is gone — did the markup change?"
    expr = m.group(1)
    assert "jsa(" in expr, f"host picker must use jsa(), got: {expr}"
    assert "esc(" not in expr, (
        f"esc() does not encode a double quote, so it cannot make a value safe "
        f"for a double-quoted attribute: {expr}")


def test_jsa_neutralises_an_attribute_breakout():
    src = _src()
    jsa = re.search(r"function jsa\(s\)\{.*?\n\}", src, re.S)
    assert jsa, "jsa() helper not found in cases.html"
    out = _apply_js_replace_chain(jsa.group(0), PAYLOAD)
    assert '"' not in out, f'a raw double quote survived jsa(): {out!r}'
    assert "'" not in out.replace("\\'", ""), f"an unescaped single quote survived: {out!r}"
    assert "onmouseover" in out, "the value should be neutralised, not dropped"


def test_esc_alone_would_not_have_been_enough():
    """Pins WHY the helper was swapped: proves esc() leaves the breakout intact,
    so this test fails loudly if someone 'simplifies' jsa() back to esc()."""
    src = _src()
    esc = re.search(r"function esc\(s\)\{.*?\}\n", src, re.S)
    assert esc, "esc() helper not found"
    out = _apply_js_replace_chain(esc.group(0), PAYLOAD)
    assert '"' in out, (
        "esc() now encodes double quotes — if that is deliberate, this test's "
        "premise changed and the comparison above should be revisited")


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
