---
name: librustzcash-release
description: Release or tag the crates in this repository — audit each CHANGELOG against the last published version, bump versions, commit per crate, open the release PR, and create signed tags whose message carries the version's CHANGELOG section. Also use to tag an already-published release or backfill missing release tags.
---

# librustzcash Crate Release

Releasing one or more crates from this repository, and tagging releases —
including backfilling tags for versions already on crates.io. `AGENTS.md`,
`CONTRIBUTING.md`, and the release-related CI govern where they differ from
this file; re-read them if a judgement call is close.

**Repository facts.** [`librustzcash.md`](librustzcash.md) holds the facts
specific to this repository (crate order, toolchain quirks, supply-chain
tooling, CI gates) that the phases below refer to as "the overlay". Read it
before starting.

`cargo publish` is **not** part of this workflow. Publishing is a separate,
human-gated step, often held until a downstream verification confirms the
exact revision. Never run it.

**Entry points.** A full release round runs Phases 0–6. A request to tag a
release that has already been published starts at Phase 1 (to identify the
published commit) and then goes straight to Phase 6, but the CHANGELOG
section still gets checked against the release range (Phase 2) before it is
put into a tag.

## Phase 0 — Scope and order

1. **Confirm the base branch with the user before doing anything else.**
   Releases do not always come off `main`. A semver-compatible release of an
   older series is cut from that series' maintenance branch, and a release
   round already in progress may be stacked on an earlier release branch. The
   base determines the baseline in Phase 1 and the PR target in Phase 5, so
   guessing it wrong invalidates the changelog audit as well as the merge.

   List the candidates rather than assuming:
   ```sh
   git branch -r --list 'upstream/maint/*' 'upstream/release/*'
   ```

2. **Bring the base up to date, then branch from it.** A stale base silently
   releases without the changes being released.
   ```sh
   git fetch upstream
   git merge --ff-only upstream/<base>   # or branch fresh from upstream/<base>
   ```
   If the fast-forward is refused, stop and ask — do not reset or rebase a
   branch someone may have based work on.

3. **Branch name**: `release/<top-crate>-<version>`, named for the highest
   crate in the stack (the one whose release motivates the round).

4. **In a multi-crate workspace, release bottom-up in dependency order.**
   Each crate's release commit must see its dependencies already bumped. Read
   the order from the overlay, or derive it from the workspace's internal
   dependency graph (`cargo metadata --format-version 1 --no-deps`).

5. **One commit per crate**, committed before starting the next.

## Phase 1 — Establish the baseline

The baseline is **the last version actually published from the base branch
confirmed in Phase 0**, not the newest git tag and not necessarily the newest
version on crates.io. A maintenance series releases against its own most
recent release, which is older than what `main` has shipped. Tags are also
often missing for a published release.

```sh
curl -s -H 'User-Agent: release-check (<user email>)' \
  'https://crates.io/api/v1/crates/<crate>/versions' \
  | python3 -c 'import json,sys; print([(v["num"], v["yanked"]) for v in json.load(sys.stdin)["versions"]][:8])'
```

**Resolve a published version to its exact commit from the crate itself.**
`cargo package` records the source commit in `.cargo_vcs_info.json`; this is
authoritative where tags and commit subjects are not:

```sh
curl -sL -H 'User-Agent: release-check (<user email>)' \
  https://crates.io/api/v1/crates/<crate>/<version>/download -o <scratch>/c.crate
tar xzOf <scratch>/c.crate --wildcards '*/.cargo_vcs_info.json'
```

A `"dirty": true` field means the crate was packaged from uncommitted
changes; no commit matches it exactly, so raise it with the user. Also check
that the commit is reachable from an upstream branch
(`git branch -r --contains <sha>`); if it is not, pushing a tag for it will
publish that commit for the first time — say so.

Then decide the bump level, Rust-flavored semver:

| Change | `0.x.y` | `x.y.z` (≥ 1.0) |
| --- | --- | --- |
| Additions, bug fixes, new trait impls | `0.x.(y+1)` | `x.(y+1).0` (fixes only: `x.y.(z+1)`) |
| Anything breaking — removals, signature changes, new required trait methods, **MSRV bump** | `0.(x+1).0` | `(x+1).0.0` |
| Iterating a release candidate | `-rc.N` → `-rc.(N+1)` | same |

## Phase 2 — CHANGELOG audit (do not skip)

This is the step that gets dropped under time pressure, and the one that
degrades the changelogs over time. The `## [Unreleased]` section accumulated
across many PRs describes *deltas between commits*; a release entry must
describe the **net difference between the baseline and the release commit**.
Those are not the same document, and converting one into the other is real
work.

### 2a. Gather the evidence

```sh
git log --oneline <baseline-ref>..<release-ref> -- <crate-path>/
git diff <baseline-ref>..<release-ref> --stat -- <crate-path>/
git diff <baseline-ref>..<release-ref> -- <crate-path>/
```

The commit list reveals interstitial churn — an API introduced under one name
and renamed three commits later, or added and then removed again.

### 2b. Machine-check the public surface

```sh
cargo semver-checks check-release -p <crate> \
  --baseline-rev <baseline-ref> --all-features \
  > <scratch>/semver-<crate>.log 2>&1; echo "EXIT: $?"
```

(`--baseline-version <v>` compares against crates.io instead.) If
`rust-toolchain.toml` pins an old toolchain, add `+stable`:
`cargo-semver-checks` needs a current toolchain for the rustdoc JSON it diffs.

It reports **violations** relative to the version already in `Cargo.toml`. If
the crate is already bumped to a new breaking version, a clean result says
only that the bump suffices — it does not list the breaking changes. It never
enumerates additions. The diff sweep below is required either way.

### 2c. Sweep the diff for what the tool won't summarize

```sh
git diff <baseline-ref>..<release-ref> -- <crate-path>/src \
  | grep -E '^[-+].*(\bpub |impl |#\[non_exhaustive\]|#\[derive)' \
  | grep -v 'pub(crate)\|pub(super)' | sort | uniq -c
# hunks inside public fns/types whose signature line itself did not change:
git diff -U0 <baseline-ref>..<release-ref> -- <crate-path>/src \
  | grep -E '^@@.*(pub (async )?fn|pub struct|pub enum|pub trait)' \
  | sed 's/^@@[^@]*@@//' | sort | uniq -c
git diff <baseline-ref>..<release-ref> -- <crate-path>/Cargo.toml   # features, deps
grep -n 'rust-version' <crate-path>/Cargo.toml rust-toolchain.toml
```

A changed parameter on a multi-line signature does not show up as a `pub`
line; the second command finds the hunks to read. Check a changed item's
visibility in the source before calling it public.

Also look for changes with no type-signature footprint, which are the ones
most often missed: stricter validation, changed equality/ordering semantics, a
previously fixed value becoming configurable, changed meaning of a reported
value, and privacy/security/cost properties documented only in code comments.
All of those are user-facing.

### 2d. Reconcile every entry against the net state

For each `## [Unreleased]` entry (or each entry of an already-dated section,
when only tagging):

- **Still true vs the baseline?** An API renamed before release yields one
  entry naming the *final* name; the intermediate name was never public.
  An API added and removed again in the same cycle yields **no entry**.
- **Visible through the public API?** Internal refactors, test-fixture
  reworks, and contracts not observable to a consumer get deleted outright.
- **Right section?** `Added` / `Changed` / `Deprecated` / `Removed` / `Fixed`,
  in that order.
- **Overlapping with a sibling entry?** Consolidate into one.
- **Rationale creep?** State the change, not why the old behaviour was wrong.
  Past roughly four lines you are explaining rather than reporting.

Then, for each public change found in 2b/2c with no entry, add one. When only
tagging an already-published release, report gaps to the user instead of
editing a published section.

### 2e. Style pass

- `- Migrated to \`<dep> <version>\`.` leads the `### Changed` section.
- `Added` entries are pointers: name the item, let its rustdoc explain it.
- `Changed` entries say what a caller must **do differently**.
- No issue or PR numbers.
- No separate "Breaking changes" section — `### Changed` already is breaking.

### 2f. Confirm published history was not rewritten

```sh
git diff <baseline-ref>..<release-ref> -- <crate-path>/CHANGELOG.md
```

Nothing under an already-published `## [x.y.z] - DATE` heading may change,
except to correct an entry that was inaccurate as written. Anything that
happened after that release belongs under `## [Unreleased]`.

## Phase 3 — Release edits

1. **CHANGELOG**: insert `## [<version>] - <YYYY-MM-DD>` immediately below
   `## [Unreleased]`, so the audited content falls under it. **Leave the
   `## [Unreleased]` heading in place, empty.** It is permanent.

2. **`<crate-path>/Cargo.toml`**: bump `version`.

3. **Workspace dependency requirement**, if the root `Cargo.toml` has a
   `[workspace.dependencies]` entry for the crate (`grep -n '<crate> = '
   Cargo.toml`). Raise it whenever a dependent needs the new version.

   A **pre-release** version (`-pre.N`, `-rc.N`) gets an equality requirement:
   `version = "=0.14.0-pre.0"`. Cargo treats a caret requirement on a
   pre-release as compatible with the later stable release, which may be
   breaking with respect to it. A stable release keeps the plain caret.

4. **Dependent CHANGELOGs**: for each in-workspace dependent, add or extend
   `- Migrated to \`<crate> <version>\`.` at the top of that dependent's
   `## [Unreleased]` → `### Changed`.
   - Extend an existing `Migrated to` line **in place** (comma-separated).
   - Pre-release bumps get an entry.
   - Semver-compatible patch bumps of a stable dependency do **not** — the
     types still unify and a consumer has nothing to adapt to.

## Phase 4 — Verify and commit

Never verify through a pipe; a pipeline reports the *last* stage's status.
Redirect and echo `$?`.

```sh
cargo check --workspace --tests --all-features > <scratch>/check-<crate>.log 2>&1; echo "EXIT: $?"
```

`cargo check` refreshes `Cargo.lock`. Run any supply-chain tooling the overlay
names (e.g. `cargo vet`), and format only the files you touched where the
repository is not fmt-clean.

Commit, one crate per commit:

```
Release <crate> version <version>

Co-Authored-By: <model attribution>
```

Stage `Cargo.lock`, the crate's `CHANGELOG.md` and `Cargo.toml`, the root
`Cargo.toml` if its workspace entry changed, any dependent `CHANGELOG.md`
touched in 3.4, and any supply-chain files the overlay names.

## Phase 5 — Push and PR

Only when the user explicitly asks to push. An earlier authorization is
per-commit, not standing.

```sh
git push -u upstream release/<top-crate>-<version>:release/<top-crate>-<version>
```

Push to the canonical `upstream` remote, never a personal fork. Use the
explicit `<branch>:<branch>` refspec: a branch created with
`git switch -c <topic> upstream/<base>` tracks `<base>`, so a bare push can
land on the protected branch you just branched from.

Release PRs usually have no tracking issue, and the `gh pr create` hook
requires a `Closes #N` keyword, so create the PR through the API:

```sh
python3 - <<'EOF'
import json, subprocess
body = open('<body-file>').read()
payload = {'title': 'Release <top-crate> version <version>',
           'head': 'release/<top-crate>-<version>',
           'base': '<base branch confirmed in Phase 0>',
           'draft': True,
           'body': body}
r = subprocess.run(['gh','api','repos/<owner>/<repo>/pulls','--method','POST','--input','-'],
                   input=json.dumps(payload), capture_output=True, text=True)
print('EXIT', r.returncode)
print(json.loads(r.stdout)['html_url'] if r.returncode == 0 else r.stderr[:2000])
EOF
```

Open it as a **draft**: it should not be merged before its tags exist
(Phase 6). `draft` cannot be changed by a REST `PATCH`; use GraphQL
(`convertPullRequestToDraft` / `markPullRequestReadyForReview`).

PR body: a crate → version table, what motivates the round (linking the merged
PRs it ships), any publish-ordering constraint, and a closing
`Prepared with Claude Code assistance.` line.

## Phase 6 — Tag the releases

**Tag before the release PR is merged.** With a merge-based workflow (no
squash, no rebase) every release commit keeps its SHA, so a tag made on the
branch still names a commit that survives the merge. Once tagged, the branch
must not be rewritten. If the repository squash- or rebase-merges, tag after
the merge instead, on the landed commit.

For a release that is **already published**, the commit is the one in its
`.cargo_vcs_info.json` (Phase 1) — not the merge commit, branch tip, or a
commit found by subject, though those usually agree.

### What gets tagged

One tag per crate, on **that crate's own release commit**: the commit that
incremented that crate's version. The exception is a round whose commits are
not in dependency order, where later commits change what earlier crates ship;
there, tag **the branch tip** for every crate involved. Confirm with the user
when the release commits are not in bottom-up order.

**Tag name**: follow the repository's existing tags (`git tag -l`). Without a
precedent, use `<crate>-<version>`. Repositories differ — `zcash_protocol-0.10.2`
uses the crate name as written, while some repositories replace `-` with `_`
in the crate part (`zodl_slipstream-0.3.0` for crate `zodl-slipstream`). Use
one form for all crates in a repository.

### Message format

The message is the same in every repository, and **always carries the
CHANGELOG section** — even where earlier tags in the repository have a bare
subject only. Do not copy a body-less precedent.

Subject `<crate> release version <version>` (crate name as published), a
blank line, then that version's CHANGELOG section with Markdown ATX headings
rewritten as setext underlines: `## [0.10.2] - 2026-07-28` becomes the bare
title over a row of `=`, and each `### Added` becomes `Added` over a row of
`-`, both underlines matching the text length. Each tag carries only its own
crate's section. A yanked release keeps its `[YANKED]` heading suffix.

`changelog-to-tag-message.py`, alongside this file, does the conversion. Take
the section from the CHANGELOG on the current base branch — it is the
corrected record, and an old release commit can carry a since-fixed heading:

```sh
python3 <skill-dir>/changelog-to-tag-message.py \
  <crate> <version> <crate-path>/CHANGELOG.md > <scratch>/tagmsg-<crate>.txt
```

### Signing

Tags are **signed** (`git tag -s`), never plain annotated `-a`. If signing
fails, hand off — do not fall back to an unsigned tag.

```sh
git tag -s -F <scratch>/tagmsg-<crate>.txt <tag-name> <release-commit>
```

Whether a tool call can sign at all depends on two things:

- **`~/.gnupg/gpg.conf` must not set `pinentry-mode loopback`.** Loopback
  makes `gpg` collect the passphrase itself, so it demands a controlling
  terminal and a tool call dies with `gpg: cannot open '/dev/tty'` before any
  pinentry appears. If that error shows up, check for it first.
- **The passphrase must be reachable.** With loopback off, the first
  signature raises the graphical pinentry and `gpg-agent` caches it, so the
  remaining tags in a round sign with no prompt.

If a signature still cannot be produced non-interactively, ask the user to run
the command with the `!` prefix so the output lands in the conversation.

A local tag that has not been pushed can be replaced with `git tag -f -s`. A
tag that is already pushed is published: ask before replacing it.

### Verify, then push

Verify each tag's signature and target:

```sh
git tag -v <tag-name> 2>&1 | grep -E 'Good signature|BAD signature'
git rev-parse <tag-name>^{commit}
```

Push only when asked, naming each tag explicitly. Never `git push --tags`,
which would publish every local tag including throwaways.

```sh
git push upstream <tag-name>
```
