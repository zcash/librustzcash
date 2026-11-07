# librustzcash overlay

Repository-specific facts for `zcash/librustzcash`. Read with `SKILL.md`; this file
only adds to it. The governing discipline is in the repo's `AGENTS.md`
("Changelog & Commit Discipline") and `CONTRIBUTING.md` ("Changelog
Entries").

## Base branches (Phase 0)

Maintenance branches are named `maint/<crate>-<x.y>.x`. When no tag exists
for a baseline version, find its release commit by subject:

```sh
git log --oneline --grep='Release <crate> version <baseline>'
```

## Crate order (Phase 0)

Release bottom-up, lowest first:

`zcash_encoding` / `equihash` / `f4jumble` → `zcash_protocol` →
`zcash_address` / `zip321` → `zcash_transparent` → `zcash_primitives` →
`zcash_proofs` → `zcash_keys` → `pczt` → `zcash_client_backend` →
`zcash_pool_migration` → `zcash_client_sqlite`

## Toolchain (Phase 2b)

`rust-toolchain.toml` pins the workspace to the MSRV, so `cargo-semver-checks`
must run as `cargo +stable semver-checks …`; on the pinned toolchain it fails
instead of reporting.

## Workspace dependencies (Phase 3)

`zcash_client_sqlite` has no `[workspace.dependencies]` entry, since nothing in
the workspace depends on it; its release commit is one file smaller.

## Supply chain (Phase 4)

```sh
cargo vet       > <scratch>/vet-<crate>.log 2>&1; echo "VET EXIT: $?"
cargo vet prune >> <scratch>/vet-<crate>.log 2>&1; echo "PRUNE EXIT: $?"
cargo fmt --all
```

`cargo vet` adds an `[[unpublished.<crate>]] version = … audited_as = …`
record to `supply-chain/imports.lock`; `cargo vet prune` drops records made
obsolete by crates published since. **Always run prune**, or the file
accumulates stale entries a later release has to clean up. Stage
`supply-chain/imports.lock` in the release commit.

## PR (Phase 5)

The PR API target is `repos/zcash/librustzcash/pulls`.

## Tags (Phase 6)

Tag name: `<crate>-<version>`, crate name as written (`zcash_protocol-0.10.2`,
`zcash_client_backend-0.24.0-rc.5`). Find each release commit on the base
with:

```sh
git log upstream/<base> --format='%H %s' --grep='^Release <crate> version <version>$'
```

Tagging before merge is **enforced**: the `release-tags` job in
`.github/workflows/ci.yml` compares each `Cargo.toml`'s `[package] version`
between the PR's base and head and, for every crate whose version changed,
requires the tag `<name>-<new version>` to exist upstream naming a commit the
PR introduces. It is a dependency of `required-checks`, the context the
"Merge Requirements" ruleset requires. The order is: push branch → open draft
PR → tag → push tags → CI goes green → mark ready for review → merge.
