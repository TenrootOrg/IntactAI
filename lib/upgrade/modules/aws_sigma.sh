#!/bin/bash
# Intact.AI upgrade — AWS SIGMA rule pack.
#
# The versioned artifact is a SIGMA rule pack, not an image. /opt/sigma-rules
# is mounted read-only into the backend, so it is written by a one-shot
# container instead. Non-fatal throughout: stale detection rules degrade
# coverage, they do not break the platform.

upgrade_module_aws_sigma() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin aws_sigma
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 600 "install the AWS SIGMA rule pack" -- _u_install_sigma_pack "$target"
    # Keep the env var name: renaming it would break every consumer, and the
    # config migration deliberately does not rename it either.
    u_do "stamp CLOUDTRAIL_VERSION" -- _u_stamp "$envf" "CLOUDTRAIL_VERSION=${target}"
    u_do "enable aws_sigma in config.yaml" -- _pin_module_version aws_sigma "$target"

    u_end aws_sigma none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

_u_install_sigma_pack() {
    local target="$1" tar=""
    # Accept the pre-rename filename too: a package cut before the
    # cloudtrail -> aws_sigma rename carries the old one.
    local c
    for c in "aws_sigma-${target}.tar" "cloudtrail-${target}.tar"; do
        [[ -f "${UPKG_DIR}/images/${c}" ]] && { tar="${UPKG_DIR}/images/${c}"; break; }
    done
    if [[ -z "$tar" ]]; then
        log_warn "  no AWS SIGMA rule pack in this package; leaving the existing rules"
        return 0
    fi
    local dest="/opt/sigma-rules/rules/cloud/aws"
    # Streamed over stdin so no host path has to be translated into the
    # container. aws.py:110-115.
    if ! "${DOCKER_BIN:-docker}" run --rm -i -v /opt/sigma-rules:/opt/sigma-rules \
            ubuntu:22.04 sh -c "mkdir -p '${dest}' && tar xf - -C '${dest}'" \
            < "$tar" >>"${LOG_FILE:-/dev/null}" 2>&1; then
        log_warn "  could not unpack the AWS SIGMA rule pack"
        return 0
    fi
    log_info "  AWS SIGMA rule pack ${target} installed"
    return 0
}
