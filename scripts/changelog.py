#!/usr/bin/env python3
"""Maintains crate changelogs from change fragments and hand-edited release sections.

See `.changes/README.md` for the workflow. In brief, for each project listed in
`.changes/projects.toml`:

- `.changes/log/<project>/<Kind>/<id>.md` is a change fragment: one changelog
  entry, written by the change that it describes. A fragment is never edited,
  moved between kinds, or deleted after it merges.
- `.changes/releases/<project>/header.md` is the text above the
  `## [Unreleased]` heading of the project's `CHANGELOG.md`.
- `.changes/releases/<project>/<version>.md` is a release section, which starts
  with its `## [...]` heading. A release section is drafted from the fragments
  that the release adds, and then edited by hand.
- `CHANGELOG.md` is the header, an empty `## [Unreleased]` section, and the
  release sections in descending order of the highest version that each names.
  It is never edited by hand.

Requires Python 3.11 or later, and no packages outside the standard library.
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import secrets
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

CHANGES_DIR = PurePosixPath(".changes")
PROJECTS_FILE = CHANGES_DIR / "projects.toml"
LOG_DIR = CHANGES_DIR / "log"
RELEASES_DIR = CHANGES_DIR / "releases"
HEADER_FILE = "header.md"
UNRELEASED_HEADING = "## [Unreleased]\n"
# The changelog sections, in the order that a release section lists them.
KINDS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
SECTION_HEADING = re.compile(r"^## \[([^\]]+)\]", re.MULTILINE)
KIND_HEADING = re.compile(r"^### (\S+)\s*$")
FRAGMENT_NAME = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-z][0-9a-z-]*\.md$")
VERSION = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


class ChangelogError(Exception):
    """A changelog source file, project setting, or argument is not valid."""


@dataclass(frozen=True, order=True)
class Version:
    """A semantic version, ordered by semver precedence."""

    major: int
    minor: int
    patch: int
    # Semver orders a version without pre-release identifiers above any version with them.
    is_release: bool
    pre: tuple[tuple[int, int | str], ...]
    text: str = field(compare=False)

    @staticmethod
    def parse(text: str) -> Version | None:
        """Returns the version that `text` names, or `None` if it is not a semantic version."""
        match = VERSION.match(text.strip())
        if match is None:
            return None
        major, minor, patch, pre = match.groups()
        # Numeric identifiers sort below alphanumeric identifiers, and numerically among themselves.
        pre_key = tuple(
            (0, int(part)) if part.isdigit() else (1, part) for part in pre.split(".")
        ) if pre else ()
        return Version(int(major), int(minor), int(patch), pre is None, pre_key, text.strip())

    def __str__(self) -> str:
        return self.text


def parse_version(text: str) -> Version:
    version = Version.parse(text)
    if version is None:
        raise ChangelogError(f"{text} is not a semantic version")
    return version


@dataclass(frozen=True)
class Section:
    """One release section of a changelog."""

    label: str
    text: str

    @property
    def versions(self) -> list[Version]:
        """Returns the versions that the section heading names, such as `[0.4.1, 0.5.1]`."""
        versions = [Version.parse(part) for part in self.label.split(",")]
        if any(version is None for version in versions):
            raise ChangelogError(f"section heading [{self.label}] does not name semantic versions")
        return versions  # type: ignore[return-value]

    @property
    def sort_key(self) -> Version:
        return max(self.versions)

    @property
    def file_name(self) -> str:
        return "_".join(part.strip() for part in self.label.split(",")) + ".md"


@dataclass(frozen=True)
class Fragment:
    """One changelog entry, written by the change that it describes."""

    project: str
    kind: str
    # The file name. It identifies the fragment on every branch that the fragment reaches.
    name: str
    body: str

    def rendered(self) -> str:
        """Returns the entry as a Markdown list item."""
        first, *rest = self.body.strip("\n").split("\n")
        lines = [f"- {first}"] + [f"  {line}" if line else "" for line in rest]
        return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Project:
    """A changelog that this tool maintains."""

    name: str
    changelog: Path
    tag_prefix: str

    @property
    def releases_dir(self) -> Path:
        return Path(RELEASES_DIR / self.name)

    @property
    def log_dir(self) -> PurePosixPath:
        return LOG_DIR / self.name


def git(*args: str) -> str:
    """Runs git and returns its standard output."""
    result = subprocess.run(["git", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise ChangelogError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def load_projects() -> dict[str, Project]:
    """Reads the project list from `.changes/projects.toml`."""
    with open(PROJECTS_FILE, "rb") as file:
        config = tomllib.load(file)
    return {
        name: Project(name, Path(settings["changelog"]), settings["tag_prefix"])
        for name, settings in config.items()
    }


def project_named(projects: dict[str, Project], name: str) -> Project:
    if name not in projects:
        raise ChangelogError(f"{name} is not listed in {PROJECTS_FILE}")
    return projects[name]


# Release sections and CHANGELOG.md


def split_changelog(text: str) -> tuple[str, str | None, list[Section]]:
    """Splits a hand-maintained changelog into its header, the body of its
    `## [Unreleased]` section (`None` if it has none), and its release sections."""
    starts = [match.start() for match in SECTION_HEADING.finditer(text)]
    if not starts:
        return text, None, []
    header = text[: starts[0]]
    unreleased = None
    sections = []
    for start, end in zip(starts, starts[1:] + [len(text)]):
        chunk = text[start:end]
        label = SECTION_HEADING.match(chunk).group(1)  # type: ignore[union-attr]
        if label == "Unreleased":
            unreleased = chunk[len(UNRELEASED_HEADING) :]
        else:
            sections.append(Section(label, chunk))
    return header, unreleased, sections


def read_sections(project: Project) -> tuple[str, list[Section]]:
    """Reads a project's header and release section files."""
    directory = project.releases_dir
    header_path = directory / HEADER_FILE
    if not header_path.is_file():
        raise ChangelogError(f"{header_path} does not exist")
    sections = []
    for path in sorted(directory.glob("*.md")):
        if path.name == HEADER_FILE:
            continue
        text = path.read_text()
        match = SECTION_HEADING.match(text)
        if match is None:
            raise ChangelogError(f"{path} does not start with a `## [...]` section heading")
        section = Section(match.group(1), text)
        if path.name != section.file_name:
            raise ChangelogError(f"{path} holds section [{section.label}]; name it {section.file_name}")
        sections.append(section)
    return header_path.read_text(), sections


def assemble(header: str, sections: list[Section]) -> str:
    """Returns the changelog text for a header and release sections."""
    ordered = sorted(sections, key=lambda section: section.sort_key, reverse=True)
    keys = [section.sort_key for section in ordered]
    for higher, lower in zip(keys, keys[1:]):
        if higher == lower:
            raise ChangelogError(f"two release sections name {higher} as their highest version")
    body = "".join(section.text for section in ordered)
    return header + UNRELEASED_HEADING + ("\n" if body else "") + body


# Fragments


def fragment_from_path(path: PurePosixPath, body: str) -> Fragment:
    """Returns the fragment that `path`, relative to the repository root, holds.

    Fails if the path is not `.changes/log/<project>/<Kind>/<id>.md`, or the body is not one entry.
    """
    parts = path.relative_to(LOG_DIR).parts if path.is_relative_to(LOG_DIR) else ()
    if len(parts) != 3:
        raise ChangelogError(f"{path}: a fragment must be at {LOG_DIR}/<project>/<Kind>/<id>.md")
    project, kind, name = parts
    if kind not in KINDS:
        raise ChangelogError(f"{path}: {kind} is not a changelog section; use one of {', '.join(KINDS)}")
    if not FRAGMENT_NAME.match(name):
        raise ChangelogError(f"{path}: name a fragment YYYYMMDD-HHMMSS-<suffix>.md, as `new` does")
    if not body.strip():
        raise ChangelogError(f"{path}: the fragment is empty")
    if body.lstrip().startswith(("- ", "* ", "#")):
        raise ChangelogError(
            f"{path}: write the entry text without a leading bullet or heading; "
            "the draft adds the bullet"
        )
    return Fragment(project, kind, name, body)


def fragments_at(revision: str, project: Project) -> dict[str, Fragment]:
    """Returns the project's fragments in the tree of `revision`, by name."""
    paths = git("ls-tree", "-r", "--name-only", revision, "--", str(project.log_dir)).split("\n")
    fragments = {}
    for path in filter(None, paths):
        fragment = fragment_from_path(PurePosixPath(path), git("show", f"{revision}:{path}"))
        fragments[fragment.name] = fragment
    return fragments


def fragment_names_at(revision: str, project: Project) -> set[str]:
    """Returns the names of the project's fragments in the tree of `revision`."""
    paths = git("ls-tree", "-r", "--name-only", revision, "--", str(project.log_dir)).split("\n")
    return {PurePosixPath(path).name for path in paths if path}


def render_draft(version: Version, date: str, fragments: list[Fragment]) -> str:
    """Returns a release section that lists `fragments`, grouped by kind."""
    lines = [f"## [{version}] - {date}\n"]
    for kind in KINDS:
        entries = sorted((f for f in fragments if f.kind == kind), key=lambda f: f.name)
        if entries:
            lines.append(f"\n### {kind}\n")
            lines.extend(entry.rendered() for entry in entries)
    return "".join(lines) + "\n"


def fragments_from_unreleased(project: Project, body: str, timestamp: str) -> dict[PurePosixPath, str]:
    """Converts the body of an `## [Unreleased]` section into fragment files, by path."""
    files = {}
    kind = None
    entry: list[str] = []

    def finish_entry() -> None:
        if entry:
            name = f"{timestamp}-m{len(files) + 1:03d}.md"
            text = "\n".join(line[2:] if line.startswith("  ") else line for line in entry)
            files[project.log_dir / str(kind) / name] = text.rstrip("\n") + "\n"
            entry.clear()

    for line in body.split("\n"):
        heading = KIND_HEADING.match(line)
        if heading:
            finish_entry()
            kind = heading.group(1)
            if kind not in KINDS:
                raise ChangelogError(f"the Unreleased section has an unknown heading: {line}")
        elif line.startswith("- "):
            finish_entry()
            if kind is None:
                raise ChangelogError(f"an Unreleased entry is not under a section heading: {line}")
            entry.append(line[2:])
        elif line.startswith("  ") or (not line.strip() and entry):
            if not entry:
                raise ChangelogError(f"an indented Unreleased line follows no entry: {line}")
            entry.append(line)
        elif line.strip():
            raise ChangelogError(f"an Unreleased line is not part of an entry: {line}")
    finish_entry()
    return files


# Release tags


def release_tags(project: Project, revision: str) -> dict[Version, str]:
    """Returns the project's release tags that are reachable from `revision`, by version."""
    output = git("tag", "--merged", revision, "--list", f"{project.tag_prefix}*")
    tags = {}
    for tag in output.split():
        version = Version.parse(tag[len(project.tag_prefix) :])
        if version is not None:
            tags[version] = tag
    return tags


def predecessor(project: Project, target: Version, revision: str) -> str | None:
    """Returns the tag of the release that a release of `target` from `revision` follows.

    This is the highest reachable release tag whose version is below `target`. For a
    release that is not a pre-release, only other such releases count: its changelog
    section replaces the sections of the pre-releases before it.
    """
    tags = release_tags(project, revision)
    earlier = [
        version
        for version in tags
        if version < target and (version.is_release or not target.is_release)
    ]
    return tags[max(earlier)] if earlier else None


def pending_fragments(project: Project, target: Version, revision: str, since: str | None) -> tuple[str | None, list[Fragment]]:
    """Returns the predecessor release tag, and the fragments that a release of `target`
    from `revision` adds: those at `revision` that are not in the predecessor's tree."""
    base = since if since is not None else predecessor(project, target, revision)
    released = fragment_names_at(base, project) if base is not None else set()
    current = fragments_at(revision, project)
    return base, [fragment for name, fragment in current.items() if name not in released]


# Commands


def command_new(project: Project, kind: str, message: str | None) -> int:
    """Creates a fragment, and opens it in `$EDITOR` unless `message` gives its text."""
    if kind not in KINDS:
        raise ChangelogError(f"{kind} is not a changelog section; use one of {', '.join(KINDS)}")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = Path(project.log_dir / kind / f"{now}-{secrets.token_hex(2)}.md")
    path.parent.mkdir(parents=True, exist_ok=True)
    if message is not None:
        path.write_text(message.rstrip("\n") + "\n")
    else:
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if not editor:
            raise ChangelogError("set $EDITOR, or pass the entry text with -m")
        path.write_text("")
        subprocess.run([*editor.split(), str(path)], check=True)
    fragment_from_path(PurePosixPath(path.as_posix()), path.read_text())
    print(path)
    return 0


def command_draft(project: Project, version_text: str, revision: str, since: str | None, date: str, write: bool) -> int:
    """Prints, or with `write` saves, a draft release section from the pending fragments."""
    version = parse_version(version_text)
    base, fragments = pending_fragments(project, version, revision, since)
    draft = render_draft(version, date, fragments)
    print(f"{len(fragments)} fragments added since {base or 'the start of the log'}", file=sys.stderr)
    superseded = [
        section.file_name
        for section in read_sections(project)[1]
        if version.is_release
        and all(not v.is_release and (v.major, v.minor, v.patch) == (version.major, version.minor, version.patch) for v in section.versions)
    ]
    if superseded:
        print(
            f"fold these pre-release sections into the draft, then delete them: {', '.join(superseded)}",
            file=sys.stderr,
        )
    if not write:
        sys.stdout.write(draft)
        return 0
    section = Section(str(version), draft)
    path = project.releases_dir / section.file_name
    if path.exists():
        raise ChangelogError(f"{path} already exists")
    path.write_text(draft)
    print(f"wrote {path}; edit it, then run `scripts/changelog.py assemble`", file=sys.stderr)
    return 0


def command_assemble(projects: dict[str, Project]) -> int:
    """Writes each project's `CHANGELOG.md` from its sources."""
    for project in projects.values():
        project.changelog.write_text(assemble(*read_sections(project)))
    return 0


def command_check(projects: dict[str, Project], base: str | None) -> int:
    """Checks fragments and release sections, and that each `CHANGELOG.md` is up to date.

    With `base`, also checks that no fragment present at `base` was changed or removed.
    """
    problems = []
    for path in sorted(Path(LOG_DIR).rglob("*")):
        if path.is_file():
            try:
                fragment = fragment_from_path(PurePosixPath(path.as_posix()), path.read_text())
                project_named(projects, fragment.project)
            except ChangelogError as error:
                problems.append(str(error))
    for project in projects.values():
        try:
            if project.changelog.read_text() != assemble(*read_sections(project)):
                problems.append(f"{project.changelog} differs from its sources; run `scripts/changelog.py assemble`")
        except (ChangelogError, OSError) as error:
            problems.append(str(error))
    if base is not None:
        changed = git("diff", "--name-status", "--no-renames", "--diff-filter=MD", base, "--", str(LOG_DIR))
        for line in filter(None, changed.split("\n")):
            status, path = line.split("\t", 1)
            action = "changes" if status == "M" else "deletes"
            problems.append(f"{path}: this change {action} a fragment that already merged; fragments are permanent")
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


def command_migrate(project: Project) -> int:
    """Splits a hand-maintained `CHANGELOG.md` into release section files, converts its
    `## [Unreleased]` entries into fragments, and writes the assembled `CHANGELOG.md`."""
    directory = project.releases_dir
    if directory.exists():
        raise ChangelogError(f"{directory} already exists")
    header, unreleased, sections = split_changelog(project.changelog.read_text())
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    fragments = fragments_from_unreleased(project, unreleased or "", timestamp)
    # Rejects headings that are not versions, and duplicate versions, before writing anything.
    text = assemble(header, sections)
    directory.mkdir(parents=True)
    (directory / HEADER_FILE).write_text(header)
    for section in sections:
        (directory / section.file_name).write_text(section.text)
    for path, body in fragments.items():
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(body)
    project.changelog.write_text(text)
    print(f"wrote {len(sections)} release sections and {len(fragments)} fragments", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Maintains crate changelogs from change fragments and hand-edited release sections."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    new = commands.add_parser("new", help="write a change fragment")
    new.add_argument("project")
    new.add_argument("kind", choices=KINDS)
    new.add_argument("-m", "--message", help="the entry text; without it, $EDITOR opens the new file")

    draft = commands.add_parser("draft", help="draft a release section from the fragments a release adds")
    draft.add_argument("project")
    draft.add_argument("version")
    draft.add_argument("--rev", default="HEAD", help="the revision to release from (default: HEAD)")
    draft.add_argument("--since", help="the release tag to draft from, in place of the predecessor")
    draft.add_argument("--date", default=datetime.date.today().isoformat(), help="the release date")
    draft.add_argument("--write", action="store_true", help="save the draft as the release section file")

    commands.add_parser("assemble", help="write each CHANGELOG.md from its sources")

    check = commands.add_parser("check", help="check fragments, release sections, and each CHANGELOG.md")
    check.add_argument("--base", help="also fail if a fragment present at this revision changed or was removed")

    predecessor_parser = commands.add_parser("predecessor", help="print the tag that a release is drafted from")
    predecessor_parser.add_argument("project")
    predecessor_parser.add_argument("version")
    predecessor_parser.add_argument("--rev", default="HEAD", help="the revision to release from (default: HEAD)")

    migrate = commands.add_parser("migrate", help="convert a hand-maintained CHANGELOG.md to this layout")
    migrate.add_argument("project")

    args = parser.parse_args(argv)
    try:
        projects = load_projects()
        if args.command == "assemble":
            return command_assemble(projects)
        if args.command == "check":
            return command_check(projects, args.base)
        project = project_named(projects, args.project)
        if args.command == "new":
            return command_new(project, args.kind, args.message)
        if args.command == "draft":
            return command_draft(project, args.version, args.rev, args.since, args.date, args.write)
        if args.command == "predecessor":
            tag = predecessor(project, parse_version(args.version), args.rev)
            print(tag if tag is not None else "(none: this is the first release)")
            return 0
        return command_migrate(project)
    except ChangelogError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
