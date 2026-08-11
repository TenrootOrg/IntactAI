#!/bin/bash
# Every image a module needs must actually be LOADED from the package.
#
# The bug this guards: each module named its image-tar prefixes by hand, and
# those names only ever covered the module's own images. Transitive
# dependencies were packaged -- deliberately, image_map.py says "Bundling lets
# the apply step load it offline" -- and then never loaded. `iris` loaded
# "iris-" and skipped rabbitmq-3-management-alpine.tar; `timesketch` loaded
# "timesketch-" and skipped postgres, opensearch, redis and nginx.
#
# It fails LATE and only offline: images load, pins stamp, certificates
# generate, and then compose up dies with "No such image:
# rabbitmq:3-management-alpine". Any box that had ever run the module online
# had the image cached, and CI's dry-run stops before compose up -- so nothing
# caught it until a real air-gapped iris install on 2026-08-11.
#
# volweb was the accidental control: its deps are named volweb-postgres-*.tar
# only to avoid colliding with timesketch's postgres-*.tar, and that renaming
# is the sole reason it worked. Luck, not design.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

prefixes_for() {
    python3 -c "
import sys
ns = {}
exec(open('${ROOT}/modules/backend/services/image_map.py', encoding='utf-8').read(), ns)
mod = sys.argv[1]
tars  = [t for _i, t in (ns.get('PRIMARY_IMAGES', {}).get(mod) or [])]
tars += [t for _d, _p, t in (ns.get('TRANSITIVE_IMAGES', {}).get(mod) or [])]
seen = []
for t in tars:
    p = t.split('{')[0]
    if p and p not in seen:
        seen.append(p)
print(' '.join(seen))
" "$1"
}

echo "== every transitive image is covered by its module's prefixes =="
ROOT="$ROOT" python3 - <<'PY' > /tmp/_tt.$$
import os
ns = {}
exec(open(os.path.join(os.environ['ROOT'],
     'modules/backend/services/image_map.py'), encoding='utf-8').read(), ns)
for mod, deps in sorted((ns.get('TRANSITIVE_IMAGES') or {}).items()):
    for _dep, _pat, tar in deps:
        print(f"{mod}\t{tar}")
PY
while IFS=$'\t' read -r mod tar; do
    [[ -n "$mod" ]] || continue
    covered=0
    for p in $(prefixes_for "$mod"); do
        [[ "$tar" == "$p"* ]] && { covered=1; break; }
    done
    if (( covered )); then
        ok "${mod}: ${tar} is covered"
    else
        fail "${mod}: ${tar} is NOT covered" "it would be packaged and never loaded — offline install dies at compose up"
    fi
done < /tmp/_tt.$$
rm -f /tmp/_tt.$$

echo
echo "== primary images are still covered (no regression) =="
ROOT="$ROOT" python3 - <<'PY' > /tmp/_tp.$$
import os
ns = {}
exec(open(os.path.join(os.environ['ROOT'],
     'modules/backend/services/image_map.py'), encoding='utf-8').read(), ns)
for mod, imgs in sorted((ns.get('PRIMARY_IMAGES') or {}).items()):
    for _img, tar in imgs:
        print(f"{mod}\t{tar}")
PY
while IFS=$'\t' read -r mod tar; do
    [[ -n "$mod" ]] || continue
    covered=0
    for p in $(prefixes_for "$mod"); do
        [[ "$tar" == "$p"* ]] && { covered=1; break; }
    done
    (( covered )) && ok "${mod}: ${tar} is covered" \
                  || fail "${mod}: ${tar} is NOT covered"
done < /tmp/_tp.$$
rm -f /tmp/_tp.$$

echo
echo "== a module's prefixes must not swallow another module's tars =="
# timesketch owns "nginx-"; iris ships iris-nginx-<v>.tar. Prefix matching is
# anchored at the start, so these must not collide -- if they ever did, one
# module's load would pull in another's images.
for probe in "timesketch:iris-nginx-v2.4.27.tar" "timesketch:volweb-postgres-16.tar"; do
    mod="${probe%%:*}"; tar="${probe#*:}"
    hit=0
    for p in $(prefixes_for "$mod"); do
        [[ "$tar" == "$p"* ]] && { hit=1; break; }
    done
    (( hit )) && fail "${mod} wrongly claims ${tar}" \
              || ok "${mod} does not claim ${tar}"
done

echo
echo "== the modules call the map-driven loader, not hardcoded prefixes =="
for f in modules/iris.sh timesketch/timesketch.sh modules/volweb.sh \
         modules/portainer.sh modules/elk.sh; do
    p="${ROOT}/lib/upgrade/${f}"
    [[ -f "$p" ]] || { fail "${f} exists"; continue; }
    if grep -q "_u_load_module_images" "$p"; then
        ok "${f} uses _u_load_module_images"
    else
        fail "${f} uses _u_load_module_images" "back to hand-named prefixes — transitive images will be skipped again"
    fi
done
if grep -q "_u_module_tar_prefixes" "${ROOT}/lib/upgrade/modules/shared.sh"; then
    ok "shared.sh derives prefixes from image_map.py"
else
    fail "shared.sh derives prefixes from image_map.py"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
