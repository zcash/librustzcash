#!/usr/bin/env bash
#
# Lint each of a crate's features on its own.
#
# `Clippy (MSRV)` lints `--all-features` and `Clippy (no default features)` lints the empty
# set: the two ENDPOINTS. Neither sees the configurations a downstream crate creates by
# taking one feature without another, which is how an import used only under `orchard` or
# `transparent-inputs` can sit in an ungated `use` block indefinitely.
#
# Lint each of the crate's features on its own, which is what catches that class. The full
# powerset is not an option (2^19 for zcash_client_backend) and pairwise interactions are
# deliberately out of scope. Deriving both the crate list and the feature list from `cargo
# metadata` means a new crate or feature is covered the day it lands.
#
# In CI this runs one job per crate, looping that crate's features in-process, so the
# dependency build is paid once and reused across every configuration rather than once per
# runner.
#
# Usage:
#   scripts/clippy-each-feature.sh                       # every workspace crate
#   scripts/clippy-each-feature.sh zcash_client_backend  # one crate
#
# Exits non-zero if any configuration fails to lint.

set -uo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)

# GitHub's log-annotation commands are noise outside Actions, so emit them only there.
if [ -n "${GITHUB_ACTIONS:-}" ]; then
    group_start() { echo "::group::$1"; }
    group_end() { echo "::endgroup::"; }
    error() { echo "::error::$1"; }
else
    group_start() { echo "=== $1"; }
    group_end() { :; }
    error() { echo "error: $1" >&2; }
fi

crates_json=$(cd "$repo_root" && cargo metadata --no-deps --format-version 1)

if [ "$#" -gt 0 ]; then
    crates="$*"
else
    crates=$(echo "$crates_json" | jq -r '.packages[].name' | sort)
fi

failed=0
for crate in $crates; do
    features=$(echo "$crates_json" \
        | jq -r --arg c "$crate" \
            '.packages[] | select(.name == $c) | .features | keys[] | select(. != "default")')

    # "<none>" is the no-default-features baseline; the rest are the crate's own features.
    for f in "<none>" $features; do
        if [ "$f" = "<none>" ]; then
            set -- -p "$crate" --no-default-features --all-targets
        else
            set -- -p "$crate" --no-default-features --features "$f" --all-targets
        fi

        group_start "$crate $f"
        if ! (cd "$repo_root" && cargo clippy "$@" -- -D warnings); then
            error "clippy failed for $crate $f"
            failed=1
        fi
        group_end
    done
done

exit "$failed"
