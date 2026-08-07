#!/usr/bin/env python3
"""Require that every crate version bumped in a pull request is already tagged.

A crate's `[package] version` changes only when it is released, so that bump is
what a release IS — not the commit subject that happens to accompany it. For each
`Cargo.toml` whose package version differs between the base and the head of the
pull request, the tag `<name>-<new version>` must exist upstream and must name a
commit the pull request introduces.

Tagging therefore happens on the release branch before the merge. The merge
neither squashes nor rebases, so a tag made then still names a commit that lands,
and a released version can never reach the default branch without a tag
identifying what it shipped.

Requiring the tagged commit to lie in the pull request's range, rather than to be
one specific commit, accommodates both tagging conventions: one tag per crate on
that crate's own release commit, and — for a round whose commits are not in
dependency order — every tag on the branch tip.

Reads the range from BASE_SHA and HEAD_SHA; with either unset there is nothing to
judge and the check passes. REMOTE selects the remote to consult (default
`origin`).

A manifest added by the pull request is skipped: introducing a crate is not a
version bump, and a crate is routinely added and iterated before its first
release.
"""

import os
import subprocess
import sys
import tomllib


def git(*args, check=True):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check)


def manifest_at(ref, path):
    """The parsed manifest at `ref`, or None if it does not exist there."""
    r = git("show", f"{ref}:{path}", check=False)
    if r.returncode != 0:
        return None
    try:
        return tomllib.loads(r.stdout)
    except tomllib.TOMLDecodeError:
        return None


def package_version(manifest, ref):
    """A manifest's own version, resolving `version.workspace = true`.

    Returns None for a manifest with no `[package]` (the workspace root), so a
    `[workspace.dependencies]` requirement bump is never mistaken for a release.
    """
    package = (manifest or {}).get("package")
    if not package:
        return None
    version = package.get("version")
    if isinstance(version, dict) and version.get("workspace"):
        root = manifest_at(ref, "Cargo.toml") or {}
        version = root.get("workspace", {}).get("package", {}).get("version")
    return version if isinstance(version, str) else None


def released_crates(base, head):
    """The (name, version) of each crate whose version this range bumps."""
    changed = git("diff", "--name-only", f"{base}..{head}", "--", "*Cargo.toml").stdout
    for path in changed.splitlines():
        head_manifest = manifest_at(head, path)
        if head_manifest is None:
            continue
        package = head_manifest.get("package", {})
        if package.get("publish") is False:
            continue
        new = package_version(head_manifest, head)
        if new is None:
            continue
        base_manifest = manifest_at(base, path)
        if base_manifest is None:
            continue
        if package_version(base_manifest, base) == new:
            continue
        name = package.get("name")
        if name:
            yield path, name, new


def tagged_commit(remote, tag):
    """The commit `tag` names on `remote`, or None if there is no such tag.

    Annotated tags are peeled, so the result is a commit rather than a tag
    object.
    """
    refs = git(
        "ls-remote", "--tags", remote, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"
    ).stdout
    peeled = plain = None
    for line in refs.splitlines():
        sha, _, ref = line.partition("\t")
        if ref.endswith("^{}"):
            peeled = sha
        else:
            plain = sha
    return peeled or plain


def introduced_by_range(sha, base, head):
    """Whether `sha` is a commit this range adds: reachable from head, not base."""
    if git("cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode != 0:
        return False
    reachable = git("merge-base", "--is-ancestor", sha, head, check=False).returncode == 0
    in_base = git("merge-base", "--is-ancestor", sha, base, check=False).returncode == 0
    return reachable and not in_base


def main():
    base, head = os.environ.get("BASE_SHA"), os.environ.get("HEAD_SHA")
    remote = os.environ.get("REMOTE", "origin")
    if not base or not head:
        print("No commit range supplied; nothing to check.")
        return 0

    releases = list(released_crates(base, head))
    if not releases:
        print("No crate versions are bumped in this range.")
        return 0

    problems = []
    for path, name, version in releases:
        tag = f"{name}-{version}"
        at = tagged_commit(remote, tag)
        if at is None:
            problems.append(f"{tag}: no such tag on {remote} ({path} bumps to {version})")
        elif not introduced_by_range(at, base, head):
            problems.append(
                f"{tag}: names {at[:12]}, which this pull request does not introduce"
            )
        else:
            print(f"{tag}: OK ({at[:12]})")

    if problems:
        print("\nCrate versions bumped without a matching tag:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            "\nTag each release commit and push the tags before merging; see"
            "\nCONTRIBUTING.md. A release must not reach the default branch"
            "\nuntagged, because the version it published would then name no"
            "\nidentifiable commit.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
