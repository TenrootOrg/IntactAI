#!/usr/bin/env bash
# Drive the REAL memory mapper over REAL `windows.sessions.Sessions` rows.
#
# The python test beside this one reads the source, because the mapper needs
# the backend's dependencies (grpc, pyvelociraptor) and a dev box rarely has
# them. This one runs it where they live — inside the backend container — so
# what is asserted is the mapper's actual output, not its text.
#
# It exists because reading the source would NOT have caught either bug this
# found: "N/A" becoming the domain account `n\a` (38 processes' worth of a
# person who does not exist), and "/SYSTEM" arriving as the user `\system`,
# the same principal under a second name. Both were obvious the moment real
# rows went through.
#
# Skips cleanly without docker or a running backend.
set -uo pipefail

CONTAINER="${INTACT_BACKEND:-intact_backend}"
pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1 (want '$3', got '$2')"; fail=$((fail+1)); fi; }

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker not available"; exit 0; }
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ] \
  || { echo "SKIP: $CONTAINER is not running"; exit 0; }

# One row per shape the real extraction produced on a 5 GB Win10 image.
read -r -d '' DRIVER <<'PY'
import json
from services.fusion.mappers.memory import map_memory

ROWS = [
    {"Process": "System",       "User Name": "N/A",                        "Process ID": 4},
    {"Process": "explorer.exe", "User Name": "DESKTOP-566AT85/vagrant",    "Process ID": 1944,
     "Session Type": "Interactive", "Create Time": "2026-09-23T10:01:02+00:00"},
    {"Process": "svchost.exe",  "User Name": "NT AUTHORITY/LOCAL SERVICE", "Process ID": 1120},
    {"Process": "lsass.exe",    "User Name": "/SYSTEM",                    "Process ID": 700},
    {"Process": "MsMpEng.exe",  "User Name": "WORKGROUP/DESKTOP-566AT85$", "Process ID": 2460},
]
ents, rels = map_memory(
    {"plugins": {"volatility3.plugins.windows.sessions.Sessions": ROWS,
                 "volatility3.plugins.windows.pslist.PsList":
                     [{"PID": r["Process ID"], "ImageFileName": r["Process"]} for r in ROWS]},
     "yara": []},
    run_id="memory_TEST", asset="asset:endpoint:C.abc", hostname="DESKTOP-566AT85")
accounts = sorted({e.id for e in ents if e.type == "account"})
print(json.dumps({
    "accounts": accounts,
    "labels": sorted({e.label for e in ents if e.type == "account"}),
    "executed": len([r for r in rels if r.kind == "executed"]),
}))
PY

tmp=$(mktemp); printf '%s' "$DRIVER" > "$tmp"
docker cp "$tmp" "$CONTAINER":/tmp/_id_driver.py >/dev/null 2>&1
out=$(docker exec -w /app -e PYTHONPATH=/app "$CONTAINER" python3 /tmp/_id_driver.py 2>/dev/null | grep '^{' | tail -1)
docker exec "$CONTAINER" rm -f /tmp/_id_driver.py >/dev/null 2>&1
rm -f "$tmp"

[ -n "$out" ] || { echo "  FAIL the driver produced no output"; exit 1; }
echo "  mapper said: $out"

has() { echo "$out" | grep -q "$1" && echo yes || echo no; }

ck "the logged-on user becomes an account"        "$(has 'vagrant')"            yes
ck "the literal N/A is NOT an account"            "$(has 'n.a\"')"              no
ck "no domain account was invented from N/A"      "$(has 'account:domain:n')"   no
ck "an unqualified principal keeps no separator"  "$(has ':system\"')"        yes
ck "no principal arrives with a stray separator"  "$(has ':.system\"')"       no
ck "the machine account is not a person"          "$(has 'desktop-566at85\$')"  no
ck "each account is linked to what it ran"        "$(echo "$out" | grep -q '"executed": 0' && echo no || echo yes)" yes

echo
echo "$((pass+fail)) checks, $fail failed"
[ "$fail" -eq 0 ]
