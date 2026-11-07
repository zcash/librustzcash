"""Tests for `scripts/changelog.py`. Run with `python3 -m unittest discover -s scripts`."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "changelog.py"
sys.path.insert(0, str(SCRIPT.parent))

import changelog  # noqa: E402

# Isolates the test repositories from the user's git configuration, such as commit signing.
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}

HEADER = "# Changelog\nAll notable changes to this library will be documented in this file.\n\n"


class Repository:
    """A temporary git repository with one project, `demo`, that the tool maintains."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "-q", "-b", "main")
        self.write(".changes/projects.toml", '[demo]\nchangelog = "demo/CHANGELOG.md"\ntag_prefix = "demo-"\n')
        self.write(".changes/releases/demo/header.md", HEADER)
        self.write("demo/CHANGELOG.md", HEADER + "## [Unreleased]\n")
        self.commit("Start the demo project")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, env=GIT_ENV, check=True, capture_output=True, text=True
        ).stdout

    def tool(self, *args: str, expect: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=self.root, env=GIT_ENV, capture_output=True, text=True
        )
        if result.returncode != expect:
            raise AssertionError(f"exit {result.returncode}, expected {expect}:\n{result.stdout}{result.stderr}")
        return result

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def change(self, name: str, kind: str = "Fixed") -> str:
        """Commits a change whose fragment is `name`, and returns the commit."""
        self.write(f".changes/log/demo/{kind}/20260101-000000-{name}.md", f"`{name}`\n")
        return self.commit(f"Change {name}")

    def draft_entries(self, version: str, *args: str) -> list[str]:
        """Returns the names of the fragments that a draft of `version` lists."""
        draft = self.tool("draft", "demo", version, "--date", "D", *args).stdout
        return sorted(line[3:-1] for line in draft.splitlines() if line.startswith("- `"))


class MaintenanceBranchTest(unittest.TestCase):
    """A release lists exactly the fragments that are not in the tree of its predecessor."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Repository(Path(self.directory.name))
        self.repo.change("initial")
        self.repo.git("tag", "demo-0.1.0")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_first_release_lists_every_fragment(self) -> None:
        self.assertEqual(self.repo.draft_entries("0.1.0", "--rev", "demo-0.1.0~0"), ["initial"])

    def test_backport_release_lists_only_cherry_picked_fixes(self) -> None:
        repo = self.repo
        repo.change("feature", kind="Added")
        fix = repo.change("fix")
        repo.git("switch", "-q", "-c", "maint", "demo-0.1.0")
        repo.git("cherry-pick", fix)
        self.assertEqual(repo.draft_entries("0.1.1"), ["fix"])

    def test_release_after_forward_merge_omits_fixes_the_backport_released(self) -> None:
        repo = self.repo
        repo.change("feature", kind="Added")
        fix = repo.change("fix")
        repo.git("switch", "-q", "-c", "maint", "demo-0.1.0")
        repo.git("cherry-pick", fix)
        repo.git("tag", "demo-0.1.1")
        repo.git("switch", "-q", "main")
        repo.git("merge", "-q", "--no-edit", "maint")
        self.assertEqual(repo.tool("predecessor", "demo", "0.2.0").stdout.strip(), "demo-0.1.1")
        self.assertEqual(repo.draft_entries("0.2.0"), ["feature"])

    def test_maintenance_only_fix_reaches_the_next_release_after_a_newer_one(self) -> None:
        repo = self.repo
        fix = repo.change("fix")
        repo.git("tag", "demo-0.2.0")
        repo.git("switch", "-q", "-c", "maint", "demo-0.1.0")
        repo.git("cherry-pick", fix)
        repo.change("maint-only")
        repo.git("tag", "demo-0.1.1")
        repo.git("switch", "-q", "main")
        repo.git("merge", "-q", "--no-edit", "maint")
        self.assertEqual(repo.tool("predecessor", "demo", "0.2.1").stdout.strip(), "demo-0.2.0")
        self.assertEqual(repo.draft_entries("0.2.1"), ["maint-only"])

    def test_final_release_spans_its_pre_releases(self) -> None:
        repo = self.repo
        repo.change("first")
        repo.git("tag", "demo-0.2.0-pre.0")
        repo.change("second")
        self.assertEqual(repo.draft_entries("0.2.0-pre.1"), ["second"])
        self.assertEqual(repo.draft_entries("0.2.0"), ["first", "second"])

    def test_since_overrides_the_predecessor(self) -> None:
        repo = self.repo
        repo.change("first")
        repo.git("tag", "demo-0.2.0")
        repo.change("second")
        self.assertEqual(repo.draft_entries("0.3.0", "--since", "demo-0.1.0"), ["first", "second"])


class DraftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Repository(Path(self.directory.name))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_renders_kinds_in_order_with_indented_continuation_lines(self) -> None:
        repo = self.repo
        repo.write(".changes/log/demo/Fixed/20260101-000002-b.md", "`b` is fixed.\n")
        repo.write(
            ".changes/log/demo/Added/20260101-000001-a.md",
            "`demo::a`:\n- `one`\n- `two`\n\n  continued paragraph\n",
        )
        repo.write(".changes/log/demo/Added/20260101-000000-c.md", "`demo::c`\n")
        repo.commit("Add fragments")
        draft = repo.tool("draft", "demo", "0.1.0", "--date", "2026-01-02").stdout
        self.assertEqual(
            draft,
            textwrap.dedent(
                """\
                ## [0.1.0] - 2026-01-02

                ### Added
                - `demo::c`
                - `demo::a`:
                  - `one`
                  - `two`

                    continued paragraph

                ### Fixed
                - `b` is fixed.

                """
            ),
        )

    def test_write_saves_the_section_and_assemble_places_it(self) -> None:
        repo = self.repo
        repo.write(".changes/releases/demo/0.1.0.md", "## [0.1.0] - 2026-01-01\nInitial release.\n")
        repo.change("x")
        repo.tool("draft", "demo", "0.2.0", "--date", "2026-02-01", "--write")
        repo.tool("assemble")
        changelog_text = (repo.root / "demo/CHANGELOG.md").read_text()
        self.assertEqual(
            changelog_text,
            HEADER
            + "## [Unreleased]\n\n## [0.2.0] - 2026-02-01\n\n### Fixed\n- `x`\n\n"
            + "## [0.1.0] - 2026-01-01\nInitial release.\n",
        )
        repo.tool("draft", "demo", "0.2.0", "--write", expect=1)

    def test_final_release_names_the_pre_release_sections_to_fold(self) -> None:
        repo = self.repo
        repo.write(".changes/releases/demo/0.2.0-pre.0.md", "## [0.2.0-pre.0] - 2026-01-01\n")
        repo.write(".changes/releases/demo/0.1.0.md", "## [0.1.0] - 2025-01-01\n")
        repo.commit("Add sections")
        result = repo.tool("draft", "demo", "0.2.0")
        self.assertIn("0.2.0-pre.0.md", result.stderr)
        self.assertNotIn("0.1.0.md", result.stderr)


class CheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.repo = Repository(Path(self.directory.name))
        self.repo.change("x")
        self.base = self.repo.git("rev-parse", "HEAD").strip()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_accepts_a_consistent_tree(self) -> None:
        self.repo.tool("check", "--base", self.base)

    def test_rejects_editing_or_deleting_a_merged_fragment(self) -> None:
        path = ".changes/log/demo/Fixed/20260101-000000-x.md"
        self.repo.write(path, "edited\n")
        self.assertIn("changes a fragment", self.repo.tool("check", "--base", self.base, expect=1).stderr)
        (self.repo.root / path).unlink()
        self.assertIn("deletes a fragment", self.repo.tool("check", "--base", self.base, expect=1).stderr)

    def test_rejects_a_stale_changelog(self) -> None:
        self.repo.write(".changes/releases/demo/0.1.0.md", "## [0.1.0] - 2026-01-01\n")
        self.assertIn("differs from its sources", self.repo.tool("check", expect=1).stderr)

    def test_rejects_malformed_fragments(self) -> None:
        cases = {
            ".changes/log/demo/Fixes/20260101-000000-a.md": "not a changelog section",
            ".changes/log/demo/Fixed/a.md": "name a fragment",
            ".changes/log/demo/Fixed/20260101-000000-b.md": "without a leading bullet",
            ".changes/log/other/Fixed/20260101-000000-c.md": "not listed",
        }
        for path, message in cases.items():
            with self.subTest(path=path):
                self.repo.write(path, "- bulleted\n" if path.endswith("-b.md") else "text\n")
                self.assertIn(message, self.repo.tool("check", expect=1).stderr)
                (self.repo.root / path).unlink()


class MigrationTest(unittest.TestCase):
    ORIGINAL = textwrap.dedent(
        """\
        # Changelog

        ## [Unreleased]

        ### Added
        - `demo::a`

        ### Changed
        - `demo::b`:
          - takes an argument.

        ## [0.4.1, 0.5.1] - 2026-02-26
        ### Fixed
        - Both lines.

        ## [0.5.0] - 2026-01-01
        Five.

        ## [v0.4.0] - UNKNOWN
        Four.
        """
    )

    def test_round_trips_release_sections_and_converts_unreleased_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Repository(Path(directory))
            shutil.rmtree(repo.root / ".changes/releases/demo")
            repo.write("demo/CHANGELOG.md", self.ORIGINAL)
            repo.tool("migrate", "demo")
            names = sorted(p.name for p in (repo.root / ".changes/releases/demo").iterdir())
            self.assertEqual(names, ["0.4.1_0.5.1.md", "0.5.0.md", "header.md", "v0.4.0.md"])
            expected = self.ORIGINAL.replace(self.ORIGINAL[self.ORIGINAL.index("### Added") : self.ORIGINAL.index("## [0.4.1")], "")
            self.assertEqual((repo.root / "demo/CHANGELOG.md").read_text(), expected)
            repo.commit("Migrate")
            self.assertEqual(
                repo.tool("draft", "demo", "0.6.0", "--date", "D").stdout,
                "## [0.6.0] - D\n\n### Added\n- `demo::a`\n\n### Changed\n- `demo::b`:\n  - takes an argument.\n\n",
            )
            repo.tool("check")


class VersionTest(unittest.TestCase):
    def test_orders_versions_by_semver_precedence(self) -> None:
        texts = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "v1.0.1"]
        versions = [changelog.parse_version(text) for text in texts]
        self.assertEqual(sorted(versions), versions)


if __name__ == "__main__":
    unittest.main()
