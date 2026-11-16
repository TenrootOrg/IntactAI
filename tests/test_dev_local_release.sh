#!/bin/bash
# The dev-only local release tools (scripts/dev/). Two traps from a fresh dev
# box install on 2026-11-16: a package carrying the published release's older
# module images, and the operator's intact-backend:<tag> untagged by a build
# that never touched the intact module.
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

test_cached_bundle_pin_drift_is_named() {
    local d; d="$(mktemp -d)"
    cat > "$d/index.json" <<'EOF'
{"assets": {"elk": {"version": "9.5.5"}, "iris": {"version": "v2.4.29"},
            "intact": {"version": "intact-20261021"}}}
EOF
    printf "versions:\n  elk: '9.5.6'\n  iris: v2.4.29\n  presidio: '2.2.366'\n  backend: 'x'\n" > "$d/config.yaml"
    local out rc
    out="$(python3 "$ROOT/scripts/dev/check_cached_pins.py" "$d/index.json" "$d/config.yaml" elk,iris,presidio)"; rc=$?
    assert_eq "$rc" "3" "drift exits 3"
    assert_contains "$out" "elk: cached 9.5.5, config.yaml pins 9.5.6"
    assert_contains "$out" "presidio: not in the cached bundle"
    assert_not_contains "$out" "iris" "matching pin is not reported"
    assert_not_contains "$out" "intact" "intact is rebuilt from source, never checked"

    printf "versions:\n  elk: '9.5.5'\n  iris: v2.4.29\n" > "$d/config.yaml"
    out="$(python3 "$ROOT/scripts/dev/check_cached_pins.py" "$d/index.json" "$d/config.yaml" elk,iris)"; rc=$?
    assert_eq "$rc" "0" "matching pins pass"
    assert_eq "$out" "" "and print nothing"
    rm -rf "$d"
}

# Runs the stale-backend-image block of build_local_release_assets.sh against a
# stub docker that reports a mismatched commit label and logs every call.
_run_stale_image_block() {
    local modules="$1"
    local block
    block="$(sed -n '/^# ── the same question, asked of the backend IMAGE/,/^# ── build one asset per module/p' \
        "$ROOT/scripts/dev/build_local_release_assets.sh")"
    (
        CALLS=""
        docker() {
            CALLS+="$* ;"
            [[ "$1 $2 $3" == "image inspect -f" ]] && echo oldcommit
            return 0
        }
        log() { :; }
        TAG=intact-20261021 COMMIT=newcommit BUILD_IMAGE=intact-backend:intact-20261108 MODULES="$modules"
        eval "$block"
        printf '%s' "$CALLS"
    )
}

test_backend_tag_survives_a_build_without_intact() {
    local calls
    calls="$(_run_stale_image_block "elk portainer plaso presidio")"
    assert_not_contains "$calls" "rmi" "no intact module, no removal of intact-backend:<tag>"

    calls="$(_run_stale_image_block "elk intact")"
    assert_contains "$calls" "rmi -f intact-backend:intact-20261021" "a stale bake is still removed when intact is rebuilt"
}

run_all_tests
