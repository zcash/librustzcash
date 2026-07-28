#!/usr/bin/env python3
"""Derive the migration DAG from the source and check or rewrite its diagram.

The source of truth is each `wallet/init/migrations/<name>.rs`, which declares

    const DEPENDENCIES: &[Uuid] = &[<module>::MIGRATION_ID, ...];

The module path names the parent directly, so the edges can be read without
resolving UUIDs. The diagram in `wallet/init/migrations.rs` is derived from
those edges rather than maintained by hand, because nothing else keeps a prose
comment honest: it had drifted by three migrations before this tool existed.

Usage:
    migration_dag.py <crate_root> --check     verify the diagram (exit 1 on drift)
    migration_dag.py <crate_root> --write     rewrite the diagram in place
    migration_dag.py <crate_root> --print     write the diagram to stdout
    migration_dag.py <crate_root> --mermaid   emit a Mermaid graph
    migration_dag.py <crate_root> --dot       emit a Graphviz graph

<crate_root> is the directory containing `src/`, i.e. `zcash_client_sqlite`.
"""

import os
import re
import sys
import textwrap
from collections import defaultdict

# The diagram lives between these two markers so the tool can find it without
# guessing at line numbers. Everything between them is generated.
BEGIN = "    // BEGIN GENERATED MIGRATION DAG"
END = "    // END GENERATED MIGRATION DAG"

# Width budget, measured from the hand-drawn diagram this replaced: every line
# of it was at or under 118 columns. rustfmt does not reflow comments, so this
# is a convention rather than a tool constraint, but it is the convention the
# file already had and there is no reason to widen it.
MAX_WIDTH = 118
PREFIX = "    //"
INDENT = 2

DEPS_RE = re.compile(r"const DEPENDENCIES:\s*&\[Uuid\]\s*=\s*&\[(.*?)\];", re.S)
DEP_ITEM_RE = re.compile(r"(?:super::)?([a-z0-9_]+)::MIGRATION_ID")
LEAVES_RE = re.compile(r"CURRENT_LEAF_MIGRATIONS:\s*&\[Uuid\]\s*=\s*&\[(.*?)\];", re.S)


class Dag:
    def __init__(self, crate_root):
        self.crate_root = crate_root
        self.mig_dir = os.path.join(crate_root, "src", "wallet", "init", "migrations")
        self.mig_rs = os.path.join(crate_root, "src", "wallet", "init", "migrations.rs")

        self.parents = {}
        for fn in sorted(os.listdir(self.mig_dir)):
            if not fn.endswith(".rs"):
                continue
            body = open(os.path.join(self.mig_dir, fn), encoding="utf-8").read()
            m = DEPS_RE.search(body)
            self.parents[fn[:-3]] = DEP_ITEM_RE.findall(m.group(1)) if m else []

        self.children = defaultdict(list)
        for node, ps in self.parents.items():
            for p in ps:
                self.children[p].append(node)
        for k in self.children:
            self.children[k].sort()

        self.roots = sorted(n for n, ps in self.parents.items() if not ps)
        self.leaves = sorted(n for n in self.parents if not self.children.get(n))

        # Longest-path depth, so every edge points strictly downward and the
        # indented rendering can never show a child above its parent.
        self.depth = {}
        for n in self.parents:
            self._depth(n)

    def _depth(self, n):
        if n in self.depth:
            return self.depth[n]
        # Guard against a cycle rather than recursing forever; a cycle is a real
        # error in the migration graph and should be reported, not hung on.
        self.depth[n] = None
        d = 0 if not self.parents[n] else 1 + max(self._depth(p) for p in self.parents[n])
        self.depth[n] = d
        return d

    def declared_leaves(self):
        src = open(self.mig_rs, encoding="utf-8").read()
        m = LEAVES_RE.search(src)
        return set(DEP_ITEM_RE.findall(m.group(1))) if m else set()

    def primary_parent(self, n):
        """The parent the tree hangs `n` from: the deepest one, ties broken by name.

        Choosing the deepest keeps the indentation monotonic, so a node always
        appears below every parent it has.
        """
        ps = self.parents[n]
        return max(sorted(ps), key=lambda p: self.depth[p]) if ps else None

    def render(self):
        """Render the diagram as comment lines, without the markers."""
        tree_children = defaultdict(list)
        for n in sorted(self.parents):
            p = self.primary_parent(n)
            if p is not None:
                tree_children[p].append(n)

        lines = [
            "The migration DAG, derived from each migration's DEPENDENCIES.",
            "Regenerate with `tools/migration_dag.py . --write`; CI checks it.",
            "",
            "Indentation is the dependency depth. A migration listed under another",
            "runs after it. Where a migration has more than one dependency, only the",
            "deepest is shown by the indentation and the rest follow the name.",
            "",
        ]

        def walk(node, level):
            pad = " " * (INDENT * level)
            extra = sorted(p for p in self.parents[node] if p != self.primary_parent(node))
            if not extra:
                lines.append(pad + node)
            else:
                annotation = f"(also after {', '.join(extra)})"
                one_line = f"{pad}{node}  {annotation}"
                if len(PREFIX) + 1 + len(one_line) <= MAX_WIDTH:
                    lines.append(one_line)
                else:
                    # A node with several extra dependencies does not fit beside its
                    # name. Wrap the annotation under it rather than overrun the
                    # width budget, which is what the hand-drawn diagram could not do.
                    lines.append(pad + node)
                    cont = pad + " " * INDENT
                    budget = MAX_WIDTH - len(PREFIX) - 1 - len(cont)
                    for chunk in textwrap.wrap(annotation, width=budget):
                        lines.append(cont + chunk)
            for c in tree_children.get(node, []):
                walk(c, level + 1)

        for r in self.roots:
            walk(r, 0)

        lines += ["", f"Leaves ({len(self.leaves)}), which CURRENT_LEAF_MIGRATIONS must match:"]
        lines += [" " * INDENT + n for n in self.leaves]

        out = []
        for l in lines:
            out.append((PREFIX + " " + l).rstrip() if l else PREFIX)
        return out

    def diagram_bounds(self, lines):
        try:
            b = next(i for i, l in enumerate(lines) if l.rstrip() == BEGIN)
            e = next(i for i, l in enumerate(lines) if l.rstrip() == END)
        except StopIteration:
            return None
        return b, e


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    crate_root, mode = sys.argv[1], sys.argv[2]
    dag = Dag(crate_root)

    if mode == "--mermaid":
        print("graph TD")
        for n in sorted(dag.parents):
            for p in dag.parents[n]:
                print(f"    {p} --> {n}")
        return 0

    if mode == "--dot":
        print("digraph migrations {")
        print("  rankdir=TB;")
        print("  node [shape=box, fontname=monospace];")
        for n in sorted(dag.parents):
            for p in dag.parents[n]:
                print(f'  "{p}" -> "{n}";')
        print("}")
        return 0

    rendered = dag.render()
    over = [l for l in rendered if len(l) > MAX_WIDTH]
    if over:
        print(f"error: {len(over)} rendered line(s) exceed {MAX_WIDTH} columns:", file=sys.stderr)
        for l in over:
            print(f"  {len(l)}: {l}", file=sys.stderr)
        return 1

    if mode == "--print":
        print("\n".join(rendered))
        return 0

    src_lines = open(dag.mig_rs, encoding="utf-8").read().splitlines()
    bounds = dag.diagram_bounds(src_lines)
    if bounds is None:
        print(f"error: markers not found in {dag.mig_rs}", file=sys.stderr)
        print(f"  expected {BEGIN!r} and {END!r}", file=sys.stderr)
        return 1
    b, e = bounds

    if mode == "--write":
        src_lines[b + 1 : e] = rendered
        open(dag.mig_rs, "w", encoding="utf-8").write("\n".join(src_lines) + "\n")
        print(f"wrote {len(rendered)} lines into {dag.mig_rs}")
        return 0

    if mode == "--check":
        failed = False
        current = src_lines[b + 1 : e]
        if current != rendered:
            print("error: the migration DAG comment is out of date.", file=sys.stderr)
            print("       run: tools/migration_dag.py . --write", file=sys.stderr)
            import difflib

            for d in difflib.unified_diff(current, rendered, "committed", "generated", lineterm=""):
                print("  " + d, file=sys.stderr)
            failed = True

        declared = dag.declared_leaves()
        if declared != set(dag.leaves):
            print("error: CURRENT_LEAF_MIGRATIONS does not match the computed leaves.", file=sys.stderr)
            print(f"  missing from the list: {sorted(set(dag.leaves) - declared)}", file=sys.stderr)
            print(f"  listed but not a leaf: {sorted(declared - set(dag.leaves))}", file=sys.stderr)
            failed = True

        if not failed:
            print(f"migration DAG comment is up to date ({len(dag.parents)} migrations, {len(dag.leaves)} leaves).")
        return 1 if failed else 0

    print(f"error: unknown mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
