#!/usr/bin/env python3
"""Check the hand-drawn migration DAG comment against the real dependency graph.

The diagram in `wallet/init/migrations.rs` is drawn by hand, but the graph it
depicts is declared elsewhere: each `wallet/init/migrations/<name>.rs` has

    const DEPENDENCIES: &[Uuid] = &[<module>::MIGRATION_ID, ...];

Nothing kept the two in step, and they drifted: three migrations were missing
from the diagram entirely and one node was drawn with half its children. This
checks the parts of that correspondence a machine can check.

What is checked:
  * every migration module appears somewhere in the diagram;
  * every migration-looking name in the diagram is a real migration, so a
    renamed or deleted module cannot leave a ghost behind;
  * the leaves computed from the graph match `CURRENT_LEAF_MIGRATIONS`;
  * no diagram line exceeds the width budget.

What is NOT checked, and cannot be: the shape of the drawing. Whether an edge is
depicted, and whether it is depicted correctly, is not recoverable from free-form
ASCII art. This catches a migration that was forgotten, not one that was drawn in
the wrong place. Deciding to generate the diagram instead would close that gap;
see the discussion in the pull request that introduced this file.

Usage:
    migration_dag.py <crate_root>             check (exit 1 on any problem)
    migration_dag.py <crate_root> --mermaid   emit a Mermaid graph
    migration_dag.py <crate_root> --dot       emit a Graphviz graph

<crate_root> is the directory containing `src/`, i.e. `zcash_client_sqlite`.
"""

import os
import re
import sys
from collections import defaultdict

# Measured from the diagram itself: every line of it is at or under this. rustfmt
# does not reflow comments, so this is a convention rather than a tool constraint,
# but it is the one the file already had.
MAX_WIDTH = 118

DEPS_RE = re.compile(r"const DEPENDENCIES:\s*&\[Uuid\]\s*=\s*&\[(.*?)\];", re.S)
DEP_ITEM_RE = re.compile(r"(?:super::)?([a-z0-9_]+)::MIGRATION_ID")
LEAVES_RE = re.compile(r"CURRENT_LEAF_MIGRATIONS:\s*&\[Uuid\]\s*=\s*&\[(.*?)\];", re.S)
# A migration name as it appears in the drawing. Deliberately loose, then filtered
# against the real module list, so that box-drawing runs and prose do not match.
NAME_IN_ART_RE = re.compile(r"[a-z][a-z0-9_]{6,}")

# Words that appear in the diagram's prose but are not migrations.
ART_PROSE = {"migration", "migrations", "encountered", "included", "omitted", "versions"}
# Paths (this tool is named in the comment) are not nodes in the graph.
PATH_RE = re.compile(r"[\w./-]+\.(?:py|rs|toml|md)")


def load(crate_root):
    mig_dir = os.path.join(crate_root, "src", "wallet", "init", "migrations")
    parents = {}
    for fn in sorted(os.listdir(mig_dir)):
        if not fn.endswith(".rs"):
            continue
        body = open(os.path.join(mig_dir, fn), encoding="utf-8").read()
        m = DEPS_RE.search(body)
        parents[fn[:-3]] = DEP_ITEM_RE.findall(m.group(1)) if m else []
    return parents


def diagram_lines(mig_rs):
    """The comment block inside `all_migrations`, located structurally."""
    lines = open(mig_rs, encoding="utf-8").read().splitlines()
    try:
        start = next(
            i + 1
            for i, l in enumerate(lines)
            if l.startswith(") -> Vec<Box<dyn RusqliteMigration")
        )
    except StopIteration:
        raise SystemExit(f"error: could not find `all_migrations` in {mig_rs}")
    out = []
    for l in lines[start:]:
        if l.lstrip().startswith("//"):
            out.append(l)
        elif l.strip() == "":
            continue
        else:
            break
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    crate_root = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else None

    parents = load(crate_root)
    children = defaultdict(list)
    for n, ps in parents.items():
        for p in ps:
            children[p].append(n)

    if mode == "--mermaid":
        print("graph TD")
        for n in sorted(parents):
            for p in parents[n]:
                print(f"    {p} --> {n}")
        return 0

    if mode == "--dot":
        print("digraph migrations {")
        print("  rankdir=TB;")
        print("  node [shape=box, fontname=monospace];")
        for n in sorted(parents):
            for p in parents[n]:
                print(f'  "{p}" -> "{n}";')
        print("}")
        return 0

    mig_rs = os.path.join(crate_root, "src", "wallet", "init", "migrations.rs")
    art = diagram_lines(mig_rs)
    art_text = "\n".join(art)
    src = open(mig_rs, encoding="utf-8").read()

    problems = []

    missing = sorted(n for n in parents if n not in art_text)
    if missing:
        problems.append(
            "migrations missing from the diagram:\n"
            + "".join(f"    {n}   (after {', '.join(parents[n]) or 'nothing'})\n" for n in missing)
        )

    # A name drawn in the art that no longer exists as a module. Names are matched
    # loosely then intersected with reality, so only plausible ghosts are reported.
    # Strip file paths first: a reference to this tool is not a node in the graph.
    drawn = {w for l in art for w in NAME_IN_ART_RE.findall(PATH_RE.sub(" ", l))}
    ghosts = sorted(w for w in drawn - set(parents) - ART_PROSE if "_" in w)
    if ghosts:
        problems.append(
            "names in the diagram that are not migrations (renamed or deleted?):\n"
            + "".join(f"    {g}\n" for g in ghosts)
        )

    leaves = {n for n in parents if not children.get(n)}
    m = LEAVES_RE.search(src)
    declared = set(DEP_ITEM_RE.findall(m.group(1))) if m else set()
    if declared != leaves:
        problems.append(
            "CURRENT_LEAF_MIGRATIONS does not match the graph:\n"
            + f"    missing from the list: {sorted(leaves - declared)}\n"
            + f"    listed but not a leaf: {sorted(declared - leaves)}\n"
        )

    over = [(len(l), l) for l in art if len(l) > MAX_WIDTH]
    if over:
        problems.append(
            f"diagram lines wider than {MAX_WIDTH} columns:\n"
            + "".join(f"    {w}: {l}\n" for w, l in over)
        )

    if problems:
        print("migration DAG check failed.\n", file=sys.stderr)
        for p in problems:
            print("  " + p.rstrip() + "\n", file=sys.stderr)
        print(
            "The diagram is hand-drawn; edit it in wallet/init/migrations.rs.\n"
            "Run `zcash_client_sqlite/tools/migration_dag.py zcash_client_sqlite` to re-check.",
            file=sys.stderr,
        )
        return 1

    print(
        f"migration DAG check passed: {len(parents)} migrations, {len(leaves)} leaves, "
        f"widest diagram line {max(len(l) for l in art)} of {MAX_WIDTH} columns."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
