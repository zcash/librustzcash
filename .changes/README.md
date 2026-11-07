# Changelog sources

The `CHANGELOG.md` of each crate listed in [`projects.toml`](projects.toml) is
generated from the files in this directory by
[`scripts/changelog.py`](../scripts/changelog.py). Don't edit those
`CHANGELOG.md` files by hand. Crates not listed in `projects.toml` keep a
hand-edited `CHANGELOG.md`.

The tool needs Python 3.11 or later, and no other packages.

## Recording a change

A commit that needs a changelog entry (see "Changelog Entries" in
`CONTRIBUTING.md`) adds a change fragment for each affected crate:

```sh
scripts/changelog.py new zcash_primitives Changed
scripts/changelog.py new zcash_primitives Added -m '`zcash_primitives::foo::Bar`'
```

`new` writes `.changes/log/<crate>/<Kind>/<id>.md` and opens it in `$EDITOR`,
unless `-m` gives the text. The kinds are `Added`, `Changed`, `Deprecated`,
`Removed`, `Fixed`, and `Security`.

A fragment holds the text of one entry, in Markdown, without the leading
`- `. Continuation lines and nested lists are written unindented; the release
draft indents them under the entry's bullet:

```markdown
`zcash_primitives::transaction::builder`:
- `Builder::expiry_height`
- `default_tx_expiry_delta`
```

**A fragment is permanent once it merges.** Don't edit, move, or delete it
later, even when a later change renames or removes what it describes: the
fragments are a record of what each change did, and the release section is
where entries are consolidated. CI rejects a pull request that changes or
deletes a fragment that is already on the target branch. A fragment that is
wrong before its pull request merges can be fixed in that pull request.

To backport a change to a maintenance branch, cherry-pick the commit. The
fragment keeps its file name, which is how the tool recognizes that the change
was already released on another branch.

## Releasing

1. Draft the release section from the fragments that the release adds:

   ```sh
   scripts/changelog.py draft zcash_primitives 0.32.0 --write
   ```

   The draft lists each fragment that is in the release commit but not in the
   tree of the release's predecessor: the highest release tag reachable from
   the release commit whose version is below the new version. For a release
   that is not a pre-release, only earlier releases that are not pre-releases
   count, so the draft spans any pre-releases of the same version. `--since
   <tag>` drafts from a different tag. Without `--write`, the draft is printed.

2. Edit `.changes/releases/<crate>/<version>.md` by hand. Consolidate entries
   that describe the same item, and remove entries for changes that a later
   change in the same release superseded or reverted, so that the section
   states the difference from the previous release. For a release that
   follows pre-releases, fold the pre-release sections into it and delete
   their files; `draft` lists them.

3. Regenerate `CHANGELOG.md`, and commit it with the release section:

   ```sh
   scripts/changelog.py assemble
   ```

4. Tag the release `<crate>-<version>` as usual. The tags are how later drafts
   find their predecessor, so every published release needs one.

A release section is an ordinary file, so a release on a maintenance branch
adds its section there, and merging the maintenance branch forward brings the
section to `main` without conflicts. `assemble` orders the sections by the
highest version that each heading names, such as `[0.4.1, 0.5.1]`.

To correct an entry in a published release, edit that release's section file
and run `assemble`.

## Files

| Path | Contents |
| --- | --- |
| `projects.toml` | The crates whose changelogs the tool maintains, their `CHANGELOG.md` paths, and their release tag prefixes |
| `log/<crate>/<Kind>/<id>.md` | Change fragments |
| `releases/<crate>/header.md` | The text above the `## [Unreleased]` heading |
| `releases/<crate>/<version>.md` | One release section, starting with its `## [...]` heading |

`scripts/changelog.py check` checks the fragments and release sections, and
that each `CHANGELOG.md` matches them. `check --base <revision>` also rejects
changes to fragments that exist at `<revision>`. To move another crate to this
layout, add it to `projects.toml` and run `scripts/changelog.py migrate
<crate>`, which converts its `## [Unreleased]` entries into fragments.
