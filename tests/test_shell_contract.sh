#!/bin/bash
# Every lib/*.sh must SOURCE cleanly, and every function one file calls must
# still be defined somewhere.
#
# WHY. lib/ is 17k lines across 53 files and four of the largest -- docker.sh
# (1432), package.sh (590), health.sh (530), permissions.sh (231) -- have no
# test at all; they are proved only by a real install on a customer box. There
# was nothing between "someone deletes a helper" and "the installer dies at the
# customer site". `bash -n` does not catch it: an undefined function is a
# runtime error, and shellcheck cannot see across files.
#
# Two checks, both cheap:
#   1. source-smoke  -- each file sourced in its own subshell under `set -u`,
#      which executes every top-level statement (constants, arrays, traps).
#   2. call-graph    -- every `name args` where `name` is a function defined by
#      some lib file must still be defined by some lib file. Catches exactly
#      the deletion this campaign risks.
#
# Deliberately NOT a mock of the whole installer. It never runs docker, apt or
# curl -- only sourcing and name resolution.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

ROOT="$(cd .. && pwd)"

_lib_files() { (cd "$ROOT" && git ls-files 'lib/*.sh' 'lib/**/*.sh' | sort); }

test_every_lib_file_sources_cleanly() {
    local f rc out failed=""
    while read -r f; do
        out="$(cd "$ROOT" && bash -c "set -u; LOG_FILE=/dev/null; SCRIPT_DIR='$ROOT'; source '$f'" 2>&1)"
        rc=$?
        if [[ "$rc" -ne 0 ]]; then
            failed+="    ${f}: rc=${rc} ${out}"$'\n'
        fi
    done < <(_lib_files)
    assert_eq "$failed" "" "every lib/*.sh must source under set -u"
}

test_no_lib_calls_a_function_that_no_longer_exists() {
    # Collect: names defined anywhere in lib/, and names invoked in command
    # position. Report invoked-but-undefined, ignoring anything resolvable as
    # a real binary, a bash builtin or keyword.
    local report
    report="$(cd "$ROOT" && python3 - <<'PY'
import re, subprocess, shutil, os

files = subprocess.run(["git","ls-files","lib/*.sh","lib/**/*.sh"],
                       capture_output=True, text=True).stdout.split()
defined, calls, assigned = set(), {}, set()
DEF = re.compile(r'^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{')
ASSIGN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=')
for f in files:
    for line in open(f, errors="replace"):
        m = DEF.match(line)
        if m:
            defined.add(m.group(1))
        # Anything ever assigned is a variable, not a function. This is what
        # separates a real call from `local a=1 b=2` continuation lines and
        # from the Python that lib/release.sh embeds in a heredoc.
        assigned.update(ASSIGN.findall(line))

# command position: start of line, after && || | ; ( or `if/then/else/do`
CALL = re.compile(r'(?:^|[;&|(]|\b(?:if|then|else|elif|do|while|until)\s+)\s*'
                  r'([a-z_][a-z0-9_]*)\s*(?:$|[\s;&|)])')
for f in files:
    src = open(f, errors="replace").read()
    # Strip, in order: heredoc bodies, comments, then STRING LITERALS. All
    # three are full of English that looks like a call in command position --
    # `log_info "  this will be used"` made an earlier version of this check
    # report `will`, `you` and `with` as missing functions. Command
    # substitutions are preserved, because those really do execute.
    src = re.sub(r'<<-?\s*[\'"]?(\w+)[\'"]?.*?^\1', '', src, flags=re.S | re.M)
    src = re.sub(r'(?m)#.*$', '', src)
    src = re.sub(r"'[^'\n]*'", "''", src)

    def _keep_subst(m):
        return " ".join(re.findall(r'\$\((.*?)\)', m.group(0), flags=re.S))
    src = re.sub(r'"[^"\n]*"', _keep_subst, src)
    # Arithmetic and test brackets: `(( swap_total_kb > 0 ))` puts a bare
    # variable straight after `(`, which is command position everywhere else.
    src = re.sub(r'\$?\(\(.*?\)\)', ' ', src, flags=re.S)
    src = re.sub(r'\[\[.*?\]\]', ' ', src, flags=re.S)
    for m in CALL.finditer(src):
        calls.setdefault(m.group(1), set()).add(f)

BUILTIN = set("""if then else elif fi for while until do done case esac function
return break continue exit local export readonly declare typeset eval exec set
unset shift source trap wait echo printf read cd pwd test true false let time
command builtin type hash umask ulimit alias unalias jobs bg fg kill getopts
mapfile shopt enable caller compgen complete select in esac coproc""".split())

# Only names that LOOK like a project helper: every function defined in lib/
# contains an underscore (log_info, _pull_image_with_retry, upkg_read_manifest,
# ...), while the false positives this check attracts do not -- English inside
# a log string, and `case` arms like `volweb)`. One character of filtering
# removes essentially all the noise, at the cost of missing a deleted
# single-word function. Deletions are also grepped by hand, so this is the
# second line of defence, not the only one.
missing = []
for name, where in sorted(calls.items()):
    if "_" not in name.strip("_"):
        continue
    if name in defined or name in assigned or name in BUILTIN or shutil.which(name):
        continue
    missing.append(f"{name}  (called in {', '.join(sorted(where))})")
print("\n".join(missing))
PY
)"
    assert_eq "$report" "" "every function called in lib/ must still be defined"
}

run_all_tests
