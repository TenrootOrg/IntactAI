#!/bin/bash
# Host dependency drift: report it, never apply it.
#
# THE GAP. scripts/upgrade.sh sources common/config/docker/health/package/
# release/permissions -- deliberately NOT deps -- and every system-bundle
# reference under lib/upgrade/ is a skip. Nothing in an upgrade has ever
# touched Docker or the host's apt packages, so a box installed with Docker 24
# stays on Docker 24 through any number of upgrades, silently, while every
# module around it moves.
#
# WHY THIS ONLY REPORTS. Two hard reasons, not caution:
#
#   1. The engine runs inside the helper container (upgrade_launcher.py's
#      `docker run -d`, no restart policy). Installing docker-ce restarts the
#      daemon, which kills that container mid-run -- and an interrupted apt
#      leaves broken dpkg state on the host.
#   2. A container cannot apt-get its host anyway. The packages have to be
#      installed by something running on the machine, which is what
#      scripts/update_host_deps.sh is for.
#
# TODO (not done, recorded so it is not re-derived): BOTH reasons above are
# properties of the CONTAINER-launched path only. Invoked from a shell,
# scripts/upgrade.sh runs ON THE HOST -- there is no helper container to kill,
# and apt-get is perfectly reachable. The two cases are already distinguishable
# (upgrade_launcher.py sets the environment the re-exec path keys off; see
# INTACT_UPGRADE_REEXEC in scripts/upgrade.sh), so a CLI run could apply host
# deps itself and only the dashboard-launched run would stay report-only.
#
# That would fold update_host_deps.sh into the upgrade for the case that needs
# it most: the air-gapped operator, who is already at a shell with the
# system-bundle in hand and today has to know a second script exists. Two
# things to settle first -- the Docker restart takes every container down
# mid-upgrade, so it has to happen BEFORE the module loop rather than during
# it; and an upgrade that reboots the daemon needs its own confirmation, since
# "upgrade the platform" and "restart the machine's Docker" are different
# consents. Deliberately NOT documented in the README yet, so the docs do not
# describe a split that is expected to go away.
#
# WHAT IT CAN HONESTLY SEE. The Docker daemon's version, over docker.sock --
# that is genuinely the HOST's daemon, not the container's. The other packages
# in the bundle (python3, jq, curl...) are host state a container cannot
# inspect: `dpkg-query` here would answer for the container's own filesystem
# and be confidently wrong. So this compares what it can actually observe and
# says so, rather than implying a full audit it did not perform.

# Set by upkg_expand_args when a *-system-bundle.tar is found beside the module
# assets. Empty when the package carries none (a prepare_package.sh wrapper
# never does -- the index it reads lists only module assets).
: "${UPKG_SYSTEM_BUNDLE:=}"

# The upstream version out of a Debian version string:
#   5:29.7.2-1~ubuntu.24.04~noble  ->  29.7.2
#   2.3.3-1~ubuntu.24.04~noble     ->  2.3.3
_hostdeps_upstream_version() {
    local v="$1"
    v="${v#*:}"      # drop the epoch
    v="${v%%-*}"     # drop the debian revision
    printf '%s' "$v"
}

# "Package<TAB>Version" for every package in the bundle's apt index. The index
# is the release's own declaration of what it expects the host to run, so there
# is no second pin file to keep in sync.
_hostdeps_bundle_versions() {
    local bundle="$1"
    # -O to stdout: the bundle is ~240 MB and only this one small file is
    # wanted. Both entry spellings, because `tar -C dir -cf out .` writes
    # "./Packages" while a hand-rolled bundle may write "Packages".
    tar -xOf "$bundle" ./Packages 2>/dev/null || tar -xOf "$bundle" Packages 2>/dev/null
}

# The report. Never fails the run: this is information, and an upgrade that
# refused because it could not read an apt index would be worse than the drift.
hostdeps_report() {
    [[ -n "${UPKG_SYSTEM_BUNDLE}" && -f "${UPKG_SYSTEM_BUNDLE}" ]] || return 0

    local pkgs; pkgs="$(_hostdeps_bundle_versions "${UPKG_SYSTEM_BUNDLE}")"
    if [[ -z "$pkgs" ]]; then
        log_warn "  host deps: this release ships a system bundle but its apt index"
        log_warn "  could not be read; skipping the host dependency check."
        return 0
    fi

    local want_docker want_containerd
    want_docker="$(awk '
        /^Package: docker-ce$/    { want = 1; next }
        /^Package: /              { want = 0 }
        want && /^Version: /      { print $2; exit }' <<< "$pkgs")"
    want_containerd="$(awk '
        /^Package: containerd\.io$/ { want = 1; next }
        /^Package: /                { want = 0 }
        want && /^Version: /        { print $2; exit }' <<< "$pkgs")"

    local have_docker have_containerd
    have_docker="$("${DOCKER_BIN:-docker}" version --format '{{.Server.Version}}' 2>/dev/null)"
    have_containerd="$("${DOCKER_BIN:-docker}" version --format \
        '{{range .Server.Components}}{{if eq .Name "containerd"}}{{.Version}}{{end}}{{end}}' 2>/dev/null)"
    have_containerd="${have_containerd#v}"

    local behind=0 line
    log_info ""
    log_info "Host dependencies (from this release's system bundle)"
    for line in "docker|${have_docker}|$(_hostdeps_upstream_version "${want_docker}")" \
                "containerd|${have_containerd}|$(_hostdeps_upstream_version "${want_containerd}")"; do
        local name="${line%%|*}" rest="${line#*|}"
        local have="${rest%%|*}" want="${rest##*|}"
        if [[ -z "$want" ]]; then
            log_info "  ${name}: the bundle does not pin it"
        elif [[ -z "$have" ]]; then
            log_info "  ${name}: installed version unknown; expected ${want}"
        elif [[ "$have" == "$want" ]]; then
            log_info "  ${name}: ${have} — matches this release"
        elif [[ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -1)" == "$have" ]]; then
            log_warn "  ${name}: ${have} installed, this release expects ${want} — BEHIND"
            behind=1
        else
            log_info "  ${name}: ${have} installed, newer than the release's ${want}"
        fi
    done

    if (( behind )); then
        log_warn "  Not applied here, on purpose: upgrading Docker restarts the daemon,"
        log_warn "  which would kill this upgrade mid-run. Apply it separately, from a"
        log_warn "  shell on the host:"
        log_warn "    sudo bash ${SCRIPT_DIR}/scripts/update_host_deps.sh --package <the package you just applied>"
    fi
    # Said every time, not only when behind: an operator reading a clean report
    # should not conclude that the whole host was audited.
    log_info "  (only the Docker daemon and containerd are checked — the bundle's"
    log_info "  other packages are host state this container cannot see)"
    return 0
}
