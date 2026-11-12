#!/bin/bash
# An online install fetches only the modules it will run.
#
# It used to download the whole release (7.5 GB) and then skip loading every
# disabled module's images: on a Velociraptor-only box 19 of 24 images were
# downloaded for nothing (risx migration, 2026-11-12). install_release_modules
# (lib/args.sh) picks the modules; the REAL download_release_assets then runs
# against a fake GitHub served from local files, to prove the filter reaches it.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -c 'import yaml' 2>/dev/null || { echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

source "${REPO}/lib/common.sh" >/dev/null 2>&1
source "${REPO}/lib/args.sh"
source "${REPO}/lib/release.sh"
PLAN="${REPO}/lib/upgrade/plan.sh"

_cfg() {  # _cfg "elk:false iris:false ..." -> a config.yaml; every other module enabled
    local f; f="$(mktemp)"
    python3 - "$f" $1 <<'PYEOF'
import sys, yaml
mods = {m: {"enabled": True} for m in
        ("aws_sigma", "elk", "iris", "plaso", "portainer", "timesketch", "velociraptor", "volweb")}
for kv in sys.argv[2:]:
    m, v = kv.split(":")
    mods[m] = {"enabled": v == "true"}
yaml.safe_dump({"modules": mods}, open(sys.argv[1], "w"))
PYEOF
    echo "$f"
}

test_everything_enabled_keeps_the_old_behaviour() {
    assert_eq "$(install_release_modules "$(_cfg "")" "$PLAN")" "" "nothing disabled: no filter, fetch all"
}

test_a_velociraptor_only_box() {
    local out; out="$(install_release_modules "$(_cfg "elk:false iris:false plaso:false portainer:false timesketch:false volweb:false")" "$PLAN")"
    assert_eq "$out" "aws_sigma intact presidio velociraptor"
}

test_timesketch_brings_plaso_even_when_plaso_is_off() {
    local out; out="$(install_release_modules "$(_cfg "plaso:false iris:false")" "$PLAN")"
    assert_contains " $out " " plaso "
    assert_not_contains " $out " " iris "
}

test_the_always_installed_list_is_read_from_the_upgrade_plan() {
    local always; always="$(sed -n 's/^ALWAYS_INSTALLED=(\(.*\))$/\1/p' "$PLAN")"
    assert_ne "$always" "" "plan.sh still declares ALWAYS_INSTALLED on one line"
    local out; out="$(install_release_modules "$(_cfg "elk:false")" "$PLAN")"
    local m; for m in $always; do assert_contains " $out " " $m "; done
}

test_install_passes_the_filter_to_the_download() {
    assert_true grep -q 'INTACT_RELEASE_ONLY_MODULES="$_only" download_release_assets' "${REPO}/install.sh"
}

# The real download path, against a fake release on disk.
test_the_download_fetches_only_the_enabled_modules() {
    local gh dest tag=intact-29990101 m
    gh="$(mktemp -d)"; dest="$(mktemp -d)"
    mkdir -p "$gh/repos/TenrootOrg/IntactAI/releases/tags" "$gh/TenrootOrg/IntactAI/releases/download/$tag"
    local dl="$gh/TenrootOrg/IntactAI/releases/download/$tag"
    python3 - "$gh" "$tag" "$dl" <<'PYEOF'
import hashlib, json, os, sys
gh, tag, dl = sys.argv[1:]
mods = ["elk", "intact", "iris", "plaso", "portainer", "presidio", "timesketch", "velociraptor", "volweb"]
index, assets = {"release_tag": tag, "assets": {}}, []
for m in mods:
    name = f"{tag}-{m}.tar.gz"; data = f"fake {m}".encode()
    open(os.path.join(dl, name), "wb").write(data)
    sha = hashlib.sha256(data).hexdigest()
    index["assets"][m] = {"asset": name, "sha256": sha, "size": len(data), "parts": []}
    assets.append({"name": name, "size": len(data), "digest": "sha256:" + sha})
for extra in (f"{tag}.index.json", f"{tag}.manifest.json"):
    body = json.dumps(index if extra.endswith("index.json") else {"versions": {}}).encode()
    open(os.path.join(dl, extra), "wb").write(body)
    assets.append({"name": extra, "size": len(body), "digest": "sha256:" + hashlib.sha256(body).hexdigest()})
json.dump({"tag_name": tag, "assets": assets},
          open(os.path.join(gh, "repos/TenrootOrg/IntactAI/releases/tags", tag), "w"))
PYEOF
    local only; only="$(install_release_modules "$(_cfg "elk:false iris:false plaso:false portainer:false timesketch:false volweb:false")" "$PLAN")"
    # the installer's working folder and log, as install.sh provides them
    local SCRIPT_DIR LOG_FILE; SCRIPT_DIR="$(mktemp -d)"; mkdir -p "$SCRIPT_DIR/data/tmp"
    LOG_FILE="$SCRIPT_DIR/install.log"
    ( INTACT_GH_API_BASE="file://$gh" INTACT_GH_DL_BASE="file://$gh" INTACT_RELEASE_ONLY_MODULES="$only" \
        download_release_assets "$tag" "$dest" >/dev/null 2>&1 )
    local got; got="$(ls "$dest" | sort | tr '\n' ' ')"
    for m in intact presidio velociraptor; do assert_contains "$got" "$tag-$m.tar.gz" "$m fetched"; done
    for m in elk iris plaso portainer timesketch volweb; do assert_not_contains "$got" "$tag-$m.tar.gz" "$m skipped"; done
}

run_all_tests
