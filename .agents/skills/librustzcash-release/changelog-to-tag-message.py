#!/usr/bin/env python3
"""Render a crate's release tag message from its CHANGELOG section.

Usage:
    changelog-to-tag-message.py <crate> <version> <changelog-path>

Emits on stdout the annotated-tag message used for crate release tags:
a `<crate> release version <version>` subject, then the CHANGELOG section for
that version with Markdown ATX headings converted to setext underlines.
"""

import re
import sys


def render(crate: str, version: str, changelog: str) -> str:
    lines = changelog.splitlines()

    heading = re.compile(r"^## +\[" + re.escape(version) + r"\](?: +- +(.*))?\s*$")
    start = next((i for i, ln in enumerate(lines) if heading.match(ln)), None)
    if start is None:
        raise SystemExit(f"no `## [{version}]` section found in the changelog")

    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )

    title = lines[start].removeprefix("##").strip()
    out = [f"{crate} release version {version}", "", title, "=" * len(title)]

    for line in lines[start + 1 : end]:
        if line.startswith("### "):
            section = line.removeprefix("###").strip()
            out += [section, "-" * len(section)]
        else:
            out.append(line.rstrip())

    # Collapse the blank-line runs that fall out of the heading rewrite, and
    # drop any leading/trailing blanks, matching `git tag` message cleanup.
    cleaned: list[str] = []
    for line in out:
        if not (line == "" and cleaned and cleaned[-1] == ""):
            cleaned.append(line)
    while cleaned and cleaned[-1] == "":
        cleaned.pop()

    return "\n".join(cleaned) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    _, crate_arg, version_arg, path = sys.argv
    with open(path) as f:
        sys.stdout.write(render(crate_arg, version_arg, f.read()))
