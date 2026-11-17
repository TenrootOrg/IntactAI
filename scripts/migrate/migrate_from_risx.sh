#!/bin/bash
# migrate_from_risx.sh — the old name of risx_to_intact.sh, kept so the
# command people already know still works.
#
# Retired 2026-11-17 after QA: it copied the whole datastore, found an
# existing ~/intact only after it had removed risx, and could not resume. risx_to_intact.sh does the
# same migration with every check before the removal. Its options differ
# (--backup, --backup-dir, --package): see --help.
echo "migrate_from_risx.sh is now risx_to_intact.sh — running it."
exec bash "$(dirname "${BASH_SOURCE[0]}")/risx_to_intact.sh" "$@"
