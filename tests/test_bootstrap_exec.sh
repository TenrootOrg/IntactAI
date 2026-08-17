#!/bin/bash
# scripts/bootstrap_upgrade.sh, EXECUTED -- not grepped.
#
# Every other test of the bootstrap asserts on its source text. These run the
# real file end-to-end against fixture engines: a stub upgrade.sh that records
# the argv and environment it was exec'd with, tarballs with good and bad
# checksums, a local HTTP server standing in for the release page. The one
# thing they cannot exercise unprivileged is the root-only reuse path under
# /var/lib/intact/engine (unprivileged runs get a fresh mktemp root by
# design) -- that path is covered on a live box, where it actually runs.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

REPO="$(cd .. && pwd)"
BUP="${REPO}/scripts/bootstrap_upgrade.sh"

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    # As root the script extracts to the real /var/lib/intact/engine; a unit
    # test has no business writing there.
    echo "  SKIP: must run unprivileged (root would use /var/lib/intact/engine)"
    exit 0
fi

# Everything -- the bootstrap's mktemp engine roots included -- lands under one
# scratch dir, so a failed run cannot leak into /tmp.
SCRATCH="$(mktemp -d)"
export TMPDIR="$SCRATCH"
_SERVER_PID=""
cleanup() {
    [[ -n "$_SERVER_PID" ]] && kill "$_SERVER_PID" 2>/dev/null
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

# ── fixtures ──────────────────────────────────────────────────────────────

make_appliance() {
    local d="${SCRATCH}/appliance-$RANDOM"
    mkdir -p "${d}/data/tmp"
    : > "${d}/config.yaml"
    printf '%s' "$d"
}

# A minimal engine source tree whose entry points RECORD how they were
# invoked. BUP_RESULT is threaded through the environment (the bootstrap
# exec's directly, so the environment survives the handover).
make_engine_src() {
    local d="$1" proto="${2:-1}"
    mkdir -p "${d}/scripts" "${d}/lib"
    cat > "${d}/scripts/upgrade.sh" <<'STUB'
#!/bin/bash
{
    printf 'ARGS:'; printf ' %q' "$@"; printf '\n'
    printf 'REEXEC:%s\n' "${INTACT_UPGRADE_REEXEC:-}"
    printf 'CWDSELF:%s\n' "${BASH_SOURCE[0]}"
} > "${BUP_RESULT:?}"
prev=""
for a in "$@"; do
    [[ "$prev" == "--handoff" ]] && cp "$a" "${BUP_RESULT}.handoff" 2>/dev/null
    prev="$a"
done
exit 0
STUB
    cat > "${d}/scripts/prepare_package.sh" <<'STUB'
#!/bin/bash
{ printf 'PREPARE_ARGS:'; printf ' %q' "$@"; printf '\n'; } > "${BUP_RESULT:?}"
exit 0
STUB
    : > "${d}/lib/common.sh"
    : > "${d}/install.sh"
    printf '%s\n' "$proto" > "${d}/BOOTSTRAP_PROTOCOL"
    printf 'intact-20260899\n' > "${d}/VERSION"
}

# Flat tarball (the frozen layout) + its sha256 beside it.
pack_engine() {
    local src="$1" tarball="$2"
    tar -C "$src" -czf "$tarball" .
    ( cd "$(dirname "$tarball")" && sha256sum "$(basename "$tarball")" > "$(basename "$tarball").sha256" )
}

new_engine_tar() {   # -> path, in a fresh dir so digests never collide
    local proto="${1:-1}" d
    d="$(mktemp -d)"
    make_engine_src "${d}/src" "$proto"
    # Uniquify so each test's tarball has its own digest -> its own engine dir.
    printf '%s %s\n' "$RANDOM" "$RANDOM" > "${d}/src/lib/salt"
    pack_engine "${d}/src" "${d}/eng.tar.gz"
    printf '%s' "${d}/eng.tar.gz"
}

run_bup() {   # result file must be $1; rest is argv
    local result="$1"; shift
    BUP_RESULT="$result" bash "$BUP" "$@"
}

# ── the handover, from an --engine file ───────────────────────────────────

test_happy_path_execs_the_engine_with_root_and_handoff() {
    local app tarball result rc
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    result="${SCRATCH}/r1"
    run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" \
        --only elk --yes >/dev/null 2>&1
    rc=$?
    assert_eq "$rc" "0" "bootstrap should exit with the stub engine's rc"
    [[ -f "$result" ]] || { _fail "the stub engine never ran"; return; }
    local args; args="$(grep '^ARGS:' "$result")"
    assert_contains "$args" "--root $app"      "authoritative --root passed"
    assert_contains "$args" "--handoff"        "handoff file passed as a flag"
    assert_contains "$args" "intact-20260899"  "the tag is forwarded"
    assert_contains "$args" "--only elk"       "unknown-to-bootstrap flags forwarded"
    assert_contains "$args" "--yes"            "passthrough kept verbatim"
    assert_not_contains "$args" "--engine"     "--engine is the bootstrap's alone"
    assert_contains "$(grep '^REEXEC:' "$result")" "REEXEC:1" \
        "INTACT_UPGRADE_REEXEC must survive the exec"
}

test_the_handoff_file_is_schema_1_and_verified() {
    local app tarball result
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    result="${SCRATCH}/r2"
    run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" >/dev/null 2>&1
    [[ -f "${result}.handoff" ]] || { _fail "no handoff file reached the engine"; return; }
    local hj; hj="$(cat "${result}.handoff")"
    assert_contains "$hj" '"schema": 1'          "versioned handoff"
    assert_contains "$hj" '"verified": true'     "the engine may trust the verification"
    assert_contains "$hj" "\"appliance_root\": \"$app\""
    assert_contains "$hj" '"target_tag": "intact-20260899"'
}

test_the_engine_runs_from_the_extraction_not_the_appliance() {
    local app tarball result
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    result="${SCRATCH}/r3"
    run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" >/dev/null 2>&1
    local self; self="$(grep '^CWDSELF:' "$result")"
    assert_not_contains "$self" "$app" \
        "the executing upgrade.sh must not live inside the appliance tree"
    assert_contains "$self" "/engine-" "content-addressed extraction dir"
}

# ── verification refusals ─────────────────────────────────────────────────

test_a_tampered_tarball_is_refused_before_anything_runs() {
    local app tarball result out rc
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    printf 'x' >> "$tarball"   # one byte past the published checksum
    result="${SCRATCH}/r4"
    out="$(run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" 2>&1)"
    rc=$?
    assert_ne "$rc" "0" "tampered engine must not exit 0"
    assert_contains "$out" "checksum mismatch"
    [[ -f "$result" ]] && _fail "the tampered engine RAN"
}

test_a_missing_sha256_is_fatal_not_a_warning() {
    local app tarball result out rc
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    rm -f "${tarball}.sha256"
    result="${SCRATCH}/r5"
    out="$(run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" 2>&1)"
    rc=$?
    assert_ne "$rc" "0" "no .sha256 must refuse, not warn-and-run"
    assert_contains "$out" ".sha256"
    [[ -f "$result" ]] && _fail "an unverifiable engine RAN"
}

test_no_verify_is_refused_with_the_reason() {
    local app out rc
    app="$(make_appliance)"
    out="$(bash "$BUP" intact-20260899 --no-verify --root "$app" 2>&1)"
    rc=$?
    assert_ne "$rc" "0"
    assert_contains "$out" "--no-verify has been removed"
}

test_a_newer_bootstrap_protocol_is_refused_with_the_way_out() {
    local app tarball result out rc
    app="$(make_appliance)"; tarball="$(new_engine_tar 2)"
    result="${SCRATCH}/r6"
    out="$(run_bup "$result" intact-20260899 --engine "$tarball" --root "$app" 2>&1)"
    rc=$?
    assert_eq "$rc" "2" "protocol refusal exits 2"
    assert_contains "$out" "protocol 2"
    assert_contains "$out" "intermediate release" "must name the way out"
    [[ -f "$result" ]] && _fail "an engine requiring a newer protocol RAN"
}

# ── the network fetch, against a local release server ─────────────────────

_start_server() {   # $1 = docroot; sets _SERVER_PID and _SERVER_PORT
    local portf="${SCRATCH}/port"
    : > "$portf"
    python3 - "$1" > "$portf" 2>/dev/null <<'PY' &
import functools, http.server, socketserver, sys
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 0), handler) as srv:
    print(srv.server_address[1], flush=True)
    srv.serve_forever()
PY
    _SERVER_PID=$!
    local i=0
    while [[ ! -s "$portf" ]] && (( i++ < 50 )); do sleep 0.1; done
    _SERVER_PORT="$(cat "$portf")"
    [[ -n "$_SERVER_PORT" ]]
}

test_an_explicit_http_base_is_allowed_and_fetches_the_engine() {
    local app tarball result rc droot rel
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    droot="${SCRATCH}/www"
    rel="${droot}/TenrootOrg/IntactAI/releases/download/intact-20260899"
    mkdir -p "$rel"
    cp "$tarball" "${rel}/intact-20260899-engine.tar.gz"
    # Re-hash under the served name: the sidecar carries the filename.
    ( cd "$rel" && sha256sum intact-20260899-engine.tar.gz \
        > intact-20260899-engine.tar.gz.sha256 )
    _start_server "$droot" || { _fail "could not start the fixture server"; return; }
    result="${SCRATCH}/r7"
    BUP_RESULT="$result" INTACT_GH_DL_BASE="http://127.0.0.1:${_SERVER_PORT}" \
        bash "$BUP" intact-20260899 --root "$app" >/dev/null 2>&1
    rc=$?
    kill "$_SERVER_PID" 2>/dev/null; _SERVER_PID=""
    assert_eq "$rc" "0" "an explicit http:// mirror must work"
    [[ -f "$result" ]] || _fail "the fetched engine never ran"
}

test_a_non_http_scheme_never_relaxes_the_https_rule() {
    local app out rc
    app="$(make_appliance)"
    out="$(INTACT_GH_DL_BASE="ftp://127.0.0.1:1" \
        bash "$BUP" intact-20260899 --root "$app" 2>&1)"
    rc=$?
    assert_ne "$rc" "0"
    assert_contains "$out" "could not obtain" "refusal, not a silent fallback"
}

test_a_fetch_failure_surfaces_curls_reason() {
    local app out rc
    # A closed port: connection refused, no retries worth waiting for a server.
    app="$(make_appliance)"
    out="$(INTACT_GH_DL_BASE="http://127.0.0.1:1" \
        bash "$BUP" intact-20260899 --root "$app" 2>&1)"
    rc=$?
    assert_ne "$rc" "0"
    assert_contains "$out" "engine fetch failed" \
        "curl's failure must be surfaced, not swallowed"
}

# ── the package path (import / air-gap) ───────────────────────────────────

test_the_engine_is_pulled_from_the_wrapper_top_level() {
    local app tarball wrapdir wrapper result rc
    app="$(make_appliance)"; tarball="$(new_engine_tar)"
    wrapdir="$(mktemp -d)"
    cp "$tarball" "${wrapdir}/intact-20260899-engine.tar.gz"
    ( cd "$wrapdir" && sha256sum intact-20260899-engine.tar.gz \
        > intact-20260899-engine.tar.gz.sha256 )
    printf '{}' > "${wrapdir}/intact-20260899.index.json"
    wrapper="${wrapdir}/intact-upgrade-intact-20260899.tar"
    ( cd "$wrapdir" && tar -cf "$wrapper" intact-20260899.index.json \
        intact-20260899-engine.tar.gz intact-20260899-engine.tar.gz.sha256 )
    result="${SCRATCH}/r8"
    run_bup "$result" --package "$wrapper" --root "$app" >/dev/null 2>&1
    rc=$?
    assert_eq "$rc" "0" "a wrapper carrying its own engine must apply"
    [[ -f "$result" ]] || { _fail "the wrapper's engine never ran"; return; }
    assert_contains "$(grep '^ARGS:' "$result")" "--package $wrapper" \
        "--package is forwarded to the engine"
}

# ── --prepare hands to the target's packager ──────────────────────────────

test_prepare_execs_the_targets_packager_positionally() {
    local tarball outdir result rc
    tarball="$(new_engine_tar)"
    outdir="${SCRATCH}/pkg-out"
    result="${SCRATCH}/r9"
    run_bup "$result" intact-20260899 --prepare "$outdir" --engine "$tarball" \
        >/dev/null 2>&1
    rc=$?
    assert_eq "$rc" "0"
    [[ -f "$result" ]] || { _fail "the target's prepare_package.sh never ran"; return; }
    local args; args="$(grep '^PREPARE_ARGS:' "$result")"
    assert_contains "$args" "intact-20260899" "tag is the first positional"
    assert_contains "$args" "$outdir"         "output dir is the second positional"
    assert_not_contains "$args" "--root"      "the packager knows no flags"
}

run_all_tests
