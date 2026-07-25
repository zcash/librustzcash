#!/usr/bin/env python3
"""
Automated crate release script for the librustzcash workspace.

This script releases crates in dependency order, performing version updates,
updating CHANGELOGs, and creating release commits.
"""

import json
import subprocess
import sys
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from datetime import datetime

@dataclass
class CrateInfo:
    name: str
    version: str
    manifest_path: str
    dependencies: Set[str]


# A ``## [X.Y.Z] - PLANNED`` heading captures an author-declared upcoming
# release version (the PLANNED marker is a project convention described at the
# top of each CHANGELOG.md).
_H2_PLANNED_RE = re.compile(r'^## \[([^\]]+)\]\s*-\s*PLANNED\s*$')
_H2_UNRELEASED_RE = re.compile(r'^## \[Unreleased\]\s*$')
# Any level-2 section heading whose label is bracketed (i.e. a version section,
# not narrative prose like "## Notes").
_H2_VERSION_RE = re.compile(r'^## \[[^\]]+\]')
_H2_ANY_RE = re.compile(r'^## ')
_H3_CHANGED_RE = re.compile(r'^### Changed\s*$')
_H3_ANY_RE = re.compile(r'^### ')
_LIST_ITEM_RE = re.compile(r'^(\s*)([-*+])\s+(.*)$')


def _short_version(version: str) -> str:
    """Return major.minor for plain 3-component SemVer; full version otherwise.

    Migration changelog entries conventionally use the SemVer-compatibility
    range (e.g. `orchard 0.12`), matching what appears in Cargo.toml. Versions
    carrying pre-release or build metadata are returned verbatim so that an
    equality pin such as ``=0.6.0-pre.1`` reads correctly.
    """
    m = re.fullmatch(r'(\d+)\.(\d+)\.\d+', version)
    return f"{m.group(1)}.{m.group(2)}" if m else version


class ChangelogParser:
    """Line-based editor for a CHANGELOG.md file.

    We parse the file into lines and operate on line ranges rather than a
    full markdown AST. This preserves the original formatting of every line
    we do not explicitly touch — important because CHANGELOG.md files here
    contain human-authored formatting (indented continuation lines, nested
    lists, etc.) that a round-trip through any general markdown renderer
    would silently normalize.

    Understands the project's two conventions for representing an upcoming
    release: either a ``## [Unreleased]`` section or a ``## [X.Y.Z] - PLANNED``
    section. Migration notes from dependency bumps land under a ``### Changed``
    subsection of whichever upcoming section exists (creating one when none
    does).
    """

    def __init__(self, content: str):
        self._trailing_newline = content.endswith('\n')
        self.lines: List[str] = content.splitlines()

    # -- Section discovery --------------------------------------------------

    def _section_end(self, start: int) -> int:
        """Exclusive line index where the ``##`` section starting at ``start`` ends."""
        for i in range(start + 1, len(self.lines)):
            if _H2_ANY_RE.match(self.lines[i]):
                return i
        return len(self.lines)

    def _subsection_end(self, start: int, outer_end: int) -> int:
        """Exclusive line index where a ``###`` subsection ends within its parent."""
        for i in range(start + 1, outer_end):
            if _H3_ANY_RE.match(self.lines[i]) or _H2_ANY_RE.match(self.lines[i]):
                return i
        return outer_end

    def _upcoming_section_line(self) -> Optional[int]:
        """Line index of the upcoming-release heading, or None."""
        for i, line in enumerate(self.lines):
            if _H2_UNRELEASED_RE.match(line) or _H2_PLANNED_RE.match(line):
                return i
        return None

    def _first_version_heading_line(self) -> Optional[int]:
        """Line index of the first ``## [...]`` heading (upcoming or released)."""
        for i, line in enumerate(self.lines):
            if _H2_VERSION_RE.match(line):
                return i
        return None

    def planned_version(self) -> Optional[str]:
        """Return the author-declared upcoming version from ``[X.Y.Z] - PLANNED``.

        Returns None if the upcoming section is ``[Unreleased]`` or missing.
        Callers use this to honor an author's chosen next-release version in
        preference to a mechanical --bump computation.
        """
        line_idx = self._upcoming_section_line()
        if line_idx is None:
            return None
        m = _H2_PLANNED_RE.match(self.lines[line_idx])
        return m.group(1) if m else None

    # -- Section creation / finalization ------------------------------------

    def _create_upcoming_section(self) -> int:
        """Insert a new ``## [Unreleased]`` section at the top of the version
        list and return its line index."""
        insert_at = self._first_version_heading_line()
        if insert_at is None:
            if self.lines and self.lines[-1].strip():
                self.lines.append("")
            insert_at = len(self.lines)
            self.lines.extend(["## [Unreleased]", ""])
            return insert_at
        # Insert heading + blank line separator before the first existing
        # version heading.
        self.lines[insert_at:insert_at] = ["## [Unreleased]", ""]
        return insert_at

    def finalize_upcoming_section(self, version: str, date: str) -> bool:
        """Rewrite the upcoming heading line to ``## [version] - date``.

        Returns False when no upcoming section exists.
        """
        line_idx = self._upcoming_section_line()
        if line_idx is None:
            return False
        self.lines[line_idx] = f"## [{version}] - {date}"
        return True

    def ensure_finalized_section(self, version: str, date: str):
        """Ensure a dated section for ``version`` exists at the top of the
        version list, either by finalizing an upcoming section or by
        synthesizing a new dated heading."""
        if self.finalize_upcoming_section(version, date):
            return
        insert_at = self._first_version_heading_line()
        if insert_at is None:
            if self.lines and self.lines[-1].strip():
                self.lines.append("")
            self.lines.extend([f"## [{version}] - {date}", ""])
        else:
            self.lines[insert_at:insert_at] = [f"## [{version}] - {date}", ""]

    # -- Migration-line management ------------------------------------------

    def _find_or_create_changed_subsection(self, section_start: int) -> tuple:
        """Locate or create the ``### Changed`` subsection of the ``##`` section
        starting at ``section_start``.

        Returns (heading_line, end_line) where end_line is exclusive.
        """
        section_end = self._section_end(section_start)

        for i in range(section_start + 1, section_end):
            if _H3_CHANGED_RE.match(self.lines[i]):
                return i, self._subsection_end(i, section_end)

        # No ### Changed yet. Insert one immediately after the section heading
        # and the blank line that conventionally follows it. Positioned above
        # any other ### subsections so Changed appears first — matching the
        # Added/Changed/Deprecated/Removed/Fixed ordering used throughout
        # this workspace's CHANGELOGs.
        insert_at = section_start + 1
        if insert_at < section_end and self.lines[insert_at] == "":
            insert_at += 1
        new_block = ["### Changed", ""]
        if insert_at < section_end and self.lines[insert_at] != "":
            new_block.append("")
        self.lines[insert_at:insert_at] = new_block
        heading_line = insert_at
        return heading_line, self._subsection_end(
            heading_line, section_end + len(new_block))

    def record_migration(self, dep_name: str, dep_version: str):
        """Add or update a ``- Migrated to `dep_name maj.min`.`` line under
        ``### Changed`` of the upcoming section.

        Creates the upcoming section and/or ``### Changed`` subsection as
        needed. If a migration line for the same dep is already present, its
        version ref is replaced in place.
        """
        section_idx = self._upcoming_section_line()
        if section_idx is None:
            section_idx = self._create_upcoming_section()

        heading_line, end_line = self._find_or_create_changed_subsection(section_idx)

        short = _short_version(dep_version)
        bullet_text = f"- Migrated to `{dep_name} {short}`."

        # Scan for an existing "- Migrated to `dep_name ..." line we can update.
        # Only match top-level list items (no leading indentation) to avoid
        # rewriting something nested under a different bullet.
        dep_prefix = f"- Migrated to `{dep_name} "
        dep_prefix_alt = f"- Migrated to `{dep_name}`"  # legacy form without version
        last_top_level_item = None
        for i in range(heading_line + 1, end_line):
            line = self.lines[i]
            if line.startswith(dep_prefix) or line.startswith(dep_prefix_alt):
                self.lines[i] = bullet_text
                return
            if _LIST_ITEM_RE.match(line) and not line.startswith(' '):
                last_top_level_item = i

        # No existing entry for this dep: append a new list item.
        if last_top_level_item is not None:
            # Insert after the last top-level item's indented continuation
            # lines, if any.
            insert_at = last_top_level_item + 1
            while (insert_at < end_line
                   and self.lines[insert_at].startswith(' ')
                   and self.lines[insert_at].strip() != ''):
                insert_at += 1
            self.lines.insert(insert_at, bullet_text)
        else:
            # Empty Changed subsection: place the item after the heading +
            # its trailing blank line.
            insert_at = heading_line + 1
            if insert_at < len(self.lines) and self.lines[insert_at] == "":
                insert_at += 1
            block = [bullet_text]
            if insert_at < len(self.lines) and self.lines[insert_at] != "":
                block.append("")
            self.lines[insert_at:insert_at] = block

    def render(self) -> str:
        result = "\n".join(self.lines)
        if self._trailing_newline:
            result += "\n"
        return result


class WorkspaceReleaser:
    def __init__(self, workspace_root: str = "."):
        self.workspace_root = Path(workspace_root).resolve()
        self.crates: Dict[str, CrateInfo] = {}
        self.load_workspace_metadata()
    
    def load_workspace_metadata(self):
        """Load workspace metadata using cargo metadata."""
        cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.workspace_root)
        
        if result.returncode != 0:
            print(f"Error running cargo metadata: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        
        metadata = json.loads(result.stdout)
        workspace_members = set(metadata["workspace_members"])

        # First pass: identify workspace packages by matching cargo's package id.
        workspace_packages = [p for p in metadata["packages"] if p["id"] in workspace_members]
        workspace_names = {p["name"] for p in workspace_packages}

        for package in workspace_packages:
            # A cargo-metadata dependency's ``kind`` is null for normal,
            # "build" for build-dependencies, or "dev" for dev-dependencies.
            # Dev-dependencies must not influence release order: a crate only
            # needs a re-release when one of its public or build-time deps
            # changes, not when a test-only dep does.
            deps = {dep["name"] for dep in package.get("dependencies", [])
                    if dep["name"] in workspace_names
                    and dep.get("kind") != "dev"}

            self.crates[package["name"]] = CrateInfo(
                name=package["name"],
                version=package["version"],
                manifest_path=package["manifest_path"],
                dependencies=deps
            )
    
    def topological_sort(self) -> List[str]:
        """Sort crates in dependency order using topological sort."""
        # Build reverse dependency graph (dependents)
        dependents: Dict[str, Set[str]] = {name: set() for name in self.crates}
        
        for crate_name, crate_info in self.crates.items():
            for dep in crate_info.dependencies:
                if dep in dependents:
                    dependents[dep].add(crate_name)
        
        # Topological sort using Kahn's algorithm
        in_degree = {name: len(info.dependencies) for name, info in self.crates.items()}
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(current)
            
            for dependent in dependents[current]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)
        
        if len(result) != len(self.crates):
            remaining = [name for name, degree in in_degree.items() if degree > 0]
            print(f"Circular dependency detected among: {remaining}", file=sys.stderr)
            sys.exit(1)
        
        return result
    
    def bump_version(self, version: str, bump_type: str = "patch") -> str:
        """Bump a three-component SemVer version string.

        Pre-release and build-metadata suffixes are stripped; the resulting
        release version is always ``MAJOR.MINOR.PATCH``. Raises ``ValueError``
        if the input isn't a valid SemVer release or pre-release version.
        """
        m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:[-+].*)?', version)
        if not m:
            raise ValueError(f"Cannot bump non-SemVer version: {version!r}")
        major, minor, patch = (int(x) for x in m.groups())

        if bump_type == "major":
            return f"{major + 1}.0.0"
        if bump_type == "minor":
            return f"{major}.{minor + 1}.0"
        return f"{major}.{minor}.{patch + 1}"

    def _target_version(self, crate_name: str, bump_type: str) -> str:
        """Compute the release target for ``crate_name``.

        If the crate's CHANGELOG has an explicit ``## [X.Y.Z] - PLANNED``
        heading, that declared version wins (it represents a decision the
        author has already made about the magnitude of the next release).
        Otherwise the version is derived mechanically from the current
        version and ``bump_type``.
        """
        planned = self.planned_version(crate_name)
        if planned is not None:
            return planned
        return self.bump_version(self.crates[crate_name].version, bump_type)
    
    def update_crate_toml(self, crate_name: str, new_version: str) -> Set[Path]:
        """Update the version in a crate's Cargo.toml. Returns modified paths."""
        manifest_path = Path(self.crates[crate_name].manifest_path)

        with open(manifest_path, 'r') as f:
            content = f.read()

        # Update version field
        content = re.sub(
            r'version\s*=\s*"[^"]*"',
            f'version = "{new_version}"',
            content,
            count=1
        )

        with open(manifest_path, 'w') as f:
            f.write(content)

        return {manifest_path}

    def update_workspace_toml(self, crate_name: str, new_version: str) -> Set[Path]:
        """Update the version in workspace Cargo.toml dependencies. Returns modified paths."""
        workspace_toml = self.workspace_root / "Cargo.toml"

        with open(workspace_toml, 'r') as f:
            content = f.read()

        # Find and update the workspace dependency entry
        pattern = rf'{re.escape(crate_name)}\s*=\s*{{\s*version\s*=\s*"[^"]*"'
        replacement = f'{crate_name} = {{ version = "{new_version}"'
        content = re.sub(pattern, replacement, content)

        with open(workspace_toml, 'w') as f:
            f.write(content)

        return {workspace_toml}

    def _changelog_path(self, crate_name: str) -> Path:
        return Path(self.crates[crate_name].manifest_path).parent / "CHANGELOG.md"

    def planned_version(self, crate_name: str) -> Optional[str]:
        """Return the author-declared PLANNED target version from the crate's
        CHANGELOG, if any, so the release target can honor author intent
        instead of always recomputing from --bump."""
        path = self._changelog_path(crate_name)
        if not path.exists():
            return None
        return ChangelogParser(path.read_text()).planned_version()

    def update_changelog(self, crate_name: str, new_version: str) -> Set[Path]:
        """Finalize the upcoming section in the crate's CHANGELOG.md."""
        changelog_path = self._changelog_path(crate_name)

        if not changelog_path.exists():
            print(f"Warning: No CHANGELOG.md found for {crate_name}")
            return set()

        today = datetime.now().strftime("%Y-%m-%d")
        parser = ChangelogParser(changelog_path.read_text())
        parser.ensure_finalized_section(new_version, today)
        changelog_path.write_text(parser.render())

        return {changelog_path}

    def update_dependent_changelogs(self, crate_name: str, new_version: str) -> Set[Path]:
        """Record migration notes in the upcoming section of each dependent's
        CHANGELOG.md. Dependents that have no upcoming section will have one
        created for them (as ``## [Unreleased]``)."""
        modified: Set[Path] = set()
        dependents = [name for name, info in self.crates.items()
                      if crate_name in info.dependencies]

        for dependent in dependents:
            changelog_path = self._changelog_path(dependent)
            if not changelog_path.exists():
                continue

            parser = ChangelogParser(changelog_path.read_text())
            parser.record_migration(crate_name, new_version)
            changelog_path.write_text(parser.render())
            modified.add(changelog_path)

        return modified

    def update_supply_chain(self, crate_name: str, new_version: str) -> Set[Path]:
        """Update supply chain metadata using cargo vet. Returns modified paths."""
        cmd = ["cargo", "vet"]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)

        if result.returncode != 0:
            # Print prominently (stdout, not just stderr) so it's visible in a
            # scrolling release log. The release continues because cargo vet
            # can flag human-reviewable attestation gaps that don't block a
            # release, but the operator needs to notice.
            print(f"  ⚠ cargo vet reported an issue for {crate_name}:")
            for line in (result.stderr or "").splitlines():
                print(f"      {line}")
            print("  Continuing — please resolve supply-chain attestations before publishing.")

        # cargo vet updates files under supply-chain/; stage the whole directory
        # so we pick up any additions, deletions, or modifications.
        supply_chain = self.workspace_root / "supply-chain"
        return {supply_chain} if supply_chain.exists() else set()
    
    def run_cargo_update(self):
        """Run cargo check to perform minimal required updates to Cargo.lock."""
        cmd = ["cargo", "check", "--tests", "--all-features"]
        result = subprocess.run(cmd, cwd=self.workspace_root)
        if result.returncode != 0:
            print("Error running cargo check", file=sys.stderr)
            sys.exit(1)
    
    def validate_release(self, crate_name: str, new_version: str) -> bool:
        """Validate the release using cargo publish --dry-run and cargo semver-checks."""
        print(f"  Validating release for {crate_name}...")
        
        # Run cargo publish --dry-run
        print(f"  Running cargo publish --dry-run for {crate_name}...")
        cmd = ["cargo", "publish", "-p", crate_name, "--dry-run", "--allow-dirty"]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error: cargo publish --dry-run failed for {crate_name}:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return False
        
        # Run cargo semver-checks
        print(f"  Running cargo semver-checks for {crate_name}...")
        cmd = ["cargo", "semver-checks", "check-release", "-p", crate_name]
        result = subprocess.run(cmd, cwd=self.workspace_root, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error: cargo semver-checks failed for {crate_name}:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            print(f"Consider using a different version bump type (--bump major/minor/patch)", file=sys.stderr)
            return False
        
        print(f"  ✓ Validation passed for {crate_name}")
        return True
    
    def ensure_clean_working_tree(self):
        """Abort if the working tree has any uncommitted or untracked changes.

        The release flow commits a precise set of files per crate; starting from
        a dirty state risks rolling unrelated edits into release commits.
        """
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=self.workspace_root,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Error checking git status: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        if result.stdout.strip():
            print(
                "Error: working tree is not clean. Commit, stash, or remove the "
                "following before running a release:",
                file=sys.stderr,
            )
            print(result.stdout, file=sys.stderr)
            sys.exit(1)

    def create_commit(self, crate_name: str, new_version: str, paths: Set[Path]):
        """Create a git commit for the release, staging only the given paths."""
        # Backticks around the crate name match the project's recent release
        # commit convention, e.g. ``Release `zcash_transparent` version 0.6.4``.
        commit_message = f"Release `{crate_name}` version {new_version}"

        if not paths:
            print(f"Error: no paths to stage for {crate_name}", file=sys.stderr)
            sys.exit(1)

        # Stage only the explicitly-tracked paths so we never sweep in
        # unrelated untracked files sitting in the working tree.
        rel_paths = [str(p.resolve().relative_to(self.workspace_root)) for p in paths]
        cmd = ["git", "add", "--"] + rel_paths
        result = subprocess.run(cmd, cwd=self.workspace_root)
        if result.returncode != 0:
            print(f"Error staging paths for {crate_name}: {rel_paths}", file=sys.stderr)
            sys.exit(1)

        cmd = ["git", "commit", "-m", commit_message]
        result = subprocess.run(cmd, cwd=self.workspace_root)

        if result.returncode != 0:
            print(f"Error creating commit for {crate_name}", file=sys.stderr)
            sys.exit(1)

        print(f"✓ Created commit: {commit_message}")

    def _recent_commit_subjects(self, limit: int = 200) -> List[str]:
        """Return commit subjects from recent history for resume detection."""
        result = subprocess.run(
            ["git", "log", "--format=%s", f"-n{limit}"],
            cwd=self.workspace_root, capture_output=True, text=True,
        )
        if result.returncode != 0:
            return []
        return result.stdout.splitlines()

    def already_released(self, crate_name: str, version: str) -> bool:
        """Check whether a release commit for (crate, version) already exists.

        Used to make re-running the script after a partial release idempotent:
        if a ``Release `crate` version X.Y.Z`` commit exists and the crate's
        current on-disk version matches X.Y.Z, there is nothing to do for this
        crate on a re-run.
        """
        target = f"Release `{crate_name}` version {version}"
        return target in self._recent_commit_subjects()

    def _release_tag(self, crate_name: str, version: str) -> str:
        """Tag name convention for a released crate version: ``<crate>-<ver>``."""
        return f"{crate_name}-{version}"

    def _workspace_dep_versions_at(self, ref: str) -> Optional[Dict[str, str]]:
        """Extract ``[workspace.dependencies]`` name → version at the given
        git ref. Returns ``None`` if the file cannot be read at that ref.

        Only entries of the form ``name = { version = "X.Y.Z" ... }`` are
        captured — which is how this workspace declares versioned deps.
        Git-sourced ``[patch.crates-io]`` entries are naturally skipped by
        the regex because they lack a ``version`` key.
        """
        result = subprocess.run(
            ["git", "show", f"{ref}:Cargo.toml"],
            cwd=self.workspace_root, capture_output=True, text=True,
        )
        if result.returncode != 0:
            return None
        pattern = re.compile(
            r'^(?P<name>[A-Za-z0-9_-]+)\s*=\s*\{\s*version\s*=\s*"(?P<ver>[^"]+)"',
            re.MULTILINE,
        )
        return {m.group("name"): m.group("ver") for m in pattern.finditer(result.stdout)}

    @staticmethod
    def _compat_shelf(version: str) -> Optional[tuple]:
        """Cargo compatibility shelf for a version or partial version string.

        Two versions are SemVer-compatible under cargo iff they share a shelf
        and neither carries a pre-release/build suffix. The shelf is:

        - ``(major,)`` when ``major > 0``
        - ``(major, minor)`` when ``major == 0`` and ``minor > 0``
        - ``(major, minor, patch)`` when ``major == 0`` and ``minor == 0``

        Partial forms like ``"0.6"`` (common in this workspace's
        ``[workspace.dependencies]`` entries) are accepted — missing trailing
        components default to 0. Returns ``None`` if the version has a
        pre-release or build suffix, signalling "not comparable as a plain
        shelf" to the caller.
        """
        m = re.fullmatch(
            r'(\d+)(?:\.(\d+))?(?:\.(\d+))?(?P<suffix>[-+].*)?',
            version,
        )
        if m is None or m.group("suffix"):
            return None
        major = int(m.group(1))
        minor = int(m.group(2)) if m.group(2) is not None else 0
        patch = int(m.group(3)) if m.group(3) is not None else 0
        if major > 0:
            return (major,)
        if minor > 0:
            return (major, minor)
        return (major, minor, patch)

    @classmethod
    def _is_breaking_bump(cls, old: str, new: str) -> bool:
        """Whether ``old`` → ``new`` is a SemVer-breaking bump under cargo's
        compatibility rules. Any pre-release/build-metadata involvement is
        treated as breaking; otherwise the compatibility shelf must match.
        """
        if old == new:
            return False
        so, sn = cls._compat_shelf(old), cls._compat_shelf(new)
        if so is None or sn is None:
            return True
        return so != sn

    def has_changes_since_release(self, crate_name: str) -> Optional[bool]:
        """Return whether the crate should be re-released relative to its tag.

        Returns ``True`` if either the crate's source tree differs from its
        release tag *or* any of its workspace dependencies has undergone a
        SemVer-breaking bump since that tag. Returns ``False`` if both are
        clean, and ``None`` if the tag does not exist (so no comparison is
        possible). The tag convention is ``<crate>-<version>``.
        """
        info = self.crates[crate_name]
        tag = self._release_tag(crate_name, info.version)

        # Verify the tag exists; treat missing as "unknown" so the caller can
        # conservatively keep the crate in the release set.
        verify = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
            cwd=self.workspace_root, capture_output=True, text=True,
        )
        if verify.returncode != 0:
            return None

        crate_dir = Path(info.manifest_path).parent
        rel_dir = str(crate_dir.resolve().relative_to(self.workspace_root))

        diff = subprocess.run(
            ["git", "diff", "--quiet", tag, "--", rel_dir],
            cwd=self.workspace_root,
        )
        if diff.returncode == 1:
            return True
        if diff.returncode != 0:
            print(f"Error diffing {crate_name} against {tag}", file=sys.stderr)
            sys.exit(1)

        # Crate's own tree is clean; check whether any workspace dependency
        # it consumes has had a breaking bump since the tag. Workspace deps
        # use ``workspace = true`` in the crate manifest, so the effective
        # version lives in the root Cargo.toml — diffing the crate directory
        # alone cannot see it.
        versions_at_tag = self._workspace_dep_versions_at(tag)
        if versions_at_tag is None:
            return False
        for dep in info.dependencies:
            if dep not in self.crates:
                continue
            old = versions_at_tag.get(dep)
            new = self.crates[dep].version
            if old is None:
                continue
            if self._is_breaking_bump(old, new):
                return True
        return False

    def unchanged_crates(self) -> tuple:
        """Partition crates by whether their source tree has changed since
        their release tag. Returns ``(unchanged, untagged)`` — the first is
        safe to auto-exclude, the second could not be checked.
        """
        unchanged: Set[str] = set()
        untagged: Set[str] = set()
        for name in self.crates:
            status = self.has_changes_since_release(name)
            if status is None:
                untagged.add(name)
            elif status is False:
                unchanged.add(name)
        return unchanged, untagged
    
    def release_crate(self, crate_name: str, bump_type: str = "patch"):
        """Release a single crate."""
        if crate_name not in self.crates:
            print(f"Error: Crate '{crate_name}' not found in workspace", file=sys.stderr)
            return False

        current_version = self.crates[crate_name].version
        new_version = self._target_version(crate_name, bump_type)

        # Resume support: if a release commit for (crate, current_version)
        # already exists on this branch, treat the crate as already released
        # and skip. This makes re-running after a partial failure safe.
        if self.already_released(crate_name, current_version):
            print(f"Skipping {crate_name}: already at {current_version} via a prior release commit")
            return True

        print(f"Releasing {crate_name}: {current_version} -> {new_version}")

        # Update versions and files, accumulating the exact set of paths touched
        # so the release commit stages only those paths (never unrelated
        # untracked files in the working tree).
        modified: Set[Path] = set()
        modified |= self.update_crate_toml(crate_name, new_version)
        modified |= self.update_workspace_toml(crate_name, new_version)
        modified |= self.update_changelog(crate_name, new_version)
        modified |= self.update_dependent_changelogs(crate_name, new_version)
        modified |= self.update_supply_chain(crate_name, new_version)

        # Update Cargo.lock
        self.run_cargo_update()
        modified.add(self.workspace_root / "Cargo.lock")

        # Validate the release before committing
        if not self.validate_release(crate_name, new_version):
            print(f"Release validation failed for {crate_name}", file=sys.stderr)
            return False

        # Create commit
        self.create_commit(crate_name, new_version, modified)

        # Update our internal version tracking
        self.crates[crate_name].version = new_version

        return True

    def _dependents_closure(self, seeds: List[str]) -> Set[str]:
        """Return ``seeds`` plus every crate that transitively depends on any
        seed. Used to propagate ``--exclude`` down the dependency DAG so that
        excluding a crate also excludes everything that would need to be
        re-released because of it."""
        dependents: Dict[str, Set[str]] = {n: set() for n in self.crates}
        for name, info in self.crates.items():
            for d in info.dependencies:
                if d in dependents:
                    dependents[d].add(name)

        visited: Set[str] = set()
        stack = [s for s in seeds if s in self.crates]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            stack.extend(dependents.get(current, ()))
        return visited

    def release_all(self, bump_type: str = "patch", exclude: Optional[List[str]] = None,
                    skip_unchanged: bool = True):
        """Release all crates in dependency order."""
        seeds = list(exclude or [])
        effective_exclude = self._dependents_closure(seeds)

        # Auto-exclude crates whose source tree is identical to their release
        # tag. These are skipped without propagating through the dependents
        # closure: a dependent that *has* changed is still safe to release,
        # because the unchanged crate's version has not moved.
        auto_excluded: Set[str] = set()
        if skip_unchanged:
            unchanged, _ = self.unchanged_crates()
            auto_excluded = unchanged - effective_exclude
            effective_exclude = effective_exclude | auto_excluded

        release_order = self.topological_sort()

        transitively_excluded = sorted(self._dependents_closure(seeds) - set(seeds))
        if transitively_excluded:
            print("Transitively excluded (dependents of explicit excludes): "
                  + ", ".join(transitively_excluded))
        if auto_excluded:
            print("Auto-excluded (unchanged since release tag): "
                  + ", ".join(sorted(auto_excluded)))

        included = [c for c in release_order if c not in effective_exclude]
        print("Release order:", " -> ".join(included))
        print()

        for crate_name in release_order:
            if crate_name in effective_exclude:
                print(f"Skipping {crate_name} (excluded)")
                continue

            if not self.release_crate(crate_name, bump_type):
                return False

        return True


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Release crates in dependency order")
    parser.add_argument("--crate", help="Release specific crate only")
    parser.add_argument("--bump", choices=["major", "minor", "patch"], default="patch",
                        help="Version bump type (default: patch)")
    parser.add_argument("--exclude", nargs="*", default=[],
                        help="Crates to exclude from release")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show release order without making changes")
    parser.add_argument("--no-skip-unchanged", action="store_true",
                        help="Include crates whose source tree is identical "
                             "to their release tag (default: auto-skip them)")

    args = parser.parse_args()

    releaser = WorkspaceReleaser()
    skip_unchanged = not args.no_skip_unchanged

    if args.dry_run:
        release_order = releaser.topological_sort()
        seeds = list(args.exclude or [])
        effective_exclude = releaser._dependents_closure(seeds)

        auto_excluded: Set[str] = set()
        untagged: Set[str] = set()
        if skip_unchanged:
            unchanged, untagged = releaser.unchanged_crates()
            auto_excluded = unchanged - effective_exclude
            effective_exclude = effective_exclude | auto_excluded

        transitively_excluded = sorted(releaser._dependents_closure(seeds) - set(seeds))
        if transitively_excluded:
            print("Transitively excluded (dependents of explicit excludes): "
                  + ", ".join(transitively_excluded))
        if auto_excluded:
            print("Auto-excluded (unchanged since release tag): "
                  + ", ".join(sorted(auto_excluded)))
        if untagged:
            print("No release tag found (will be released): "
                  + ", ".join(sorted(untagged)))

        included = [c for c in release_order if c not in effective_exclude]
        print("Release order:", " -> ".join(included))
        return

    # Refuse to run against a dirty working tree: any pre-existing edits would
    # otherwise be swept into release commits or leave the repo in a confusing
    # half-released state.
    releaser.ensure_clean_working_tree()

    if args.crate:
        success = releaser.release_crate(args.crate, args.bump)
    else:
        success = releaser.release_all(args.bump, args.exclude, skip_unchanged)
    
    if success:
        print("\n✓ All releases completed successfully!")
    else:
        print("\n✗ Release failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
