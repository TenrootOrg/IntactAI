#!/usr/bin/env bash
# The timeline row must not name the same machine twice — and must not trim
# anything else.
#
# Rows render as `<host> [phase] <title>`, and finding titles end with
# "on <host>", so nearly every line read:
#
#   ALClient022 [Execution / Injection] SIGMA: ... Detection on ALClient022
#
# _tlTitle drops that suffix for display. The hazard is over-trimming: the
# cross-host findings legitimately end "on 2 hosts" / "across 2 hosts", and a
# careless match would mangle them. Verified against the live case at the time
# of writing: 93 rows, 85 trimmed, 8 left alone, and every single trim was an
# exact suffix removal — never a truncation.
#
# The REAL function is lifted out of cases.html and executed, so this cannot
# drift from what ships. Node is not on an appliance, so this skips there
# rather than failing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/modules/nginx/html/cases.html"

if ! command -v node >/dev/null 2>&1; then
    echo "  SKIP no node on this host — the timeline trim is checked where node exists"
    exit 0
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 - "$SRC" "$tmp/tl.js" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"function _tlTitle\(r\)\{.*?\n\}", s, re.S)
if not m:
    sys.exit("could not find _tlTitle in cases.html — the timeline trim is gone")
open(sys.argv[2], "w", encoding="utf-8").write(m.group(0))
PY
[[ -s "$tmp/tl.js" ]] || { echo "  FAIL _tlTitle not found"; exit 1; }

node - "$tmp/tl.js" <<'JS'
const fs = require('fs');
eval(fs.readFileSync(process.argv[2], 'utf8'));
let bad = 0;
const check = (host, title, want, why) => {
  const got = _tlTitle({ host, title });
  if (got === want) { console.log(`  ok   ${why}`); }
  else { console.log(`  FAIL ${why}\n       want ${JSON.stringify(want)}\n       got  ${JSON.stringify(got)}`); bad++; }
};

// the duplication this exists to remove
check('ALClient022', 'SIGMA: Antivirus Password Dumper Detection on ALClient022',
      'SIGMA: Antivirus Password Dumper Detection', 'trims the row host');
check('ALClient09', 'Renamed binary: pythonw.exe on ALClient09',
      'Renamed binary: pythonw.exe', 'trims after a filename');

// cross-host findings, which really do end in "hosts"
check('ALClient04, ALClient06', 'Shared binary seen on 2 hosts',
      'Shared binary seen on 2 hosts', 'leaves a multi-host row alone');
check('ALClient022, ALClient06', "Account 'adatumlab\\srv' used across 2 hosts",
      "Account 'adatumlab\\srv' used across 2 hosts", 'leaves "across 2 hosts" alone');

// near misses that must NOT match
check('ALClient01', 'Something happened on ALClient012',
      'Something happened on ALClient012', 'does not trim a longer host name');
check('Client01', 'Something happened on ALClient01',
      'Something happened on ALClient01', 'does not trim a host that is only a substring');
check('ALClient01', 'ALClient01 did something',
      'ALClient01 did something', 'does not touch the host mid-title');

// degenerate input
check('ALClient01', 'Some finding with no host suffix',
      'Some finding with no host suffix', 'no suffix, no change');
check('', 'orphan title on ALClient01', 'orphan title on ALClient01', 'no host, no change');
check('ALClient01', '', '', 'empty title survives');

process.exit(bad ? 1 : 0);
JS
