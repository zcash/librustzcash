#!/usr/bin/env python3

import os
import subprocess
import sys

CRATES_IN_GRAPH = set([
    # ./components
    'eip681',
    'equihash',
    'f4jumble',
    'zcash_address',
    'zcash_encoding',
    'zcash_protocol',
    'zip321',
    # ./
    'pczt',
    'zcash_client_backend',
    'zcash_client_memory',
    'zcash_client_sqlite',
    'zcash_extensions',
    'zcash_history',
    'zcash_keys',
    'zcash_primitives',
    'zcash_proofs',
    'zcash_transparent',
    # Other repos
    'orchard',
    'sapling-crypto',
    'zcash_note_encryption',
    'zcash_spec',
    'zip32',
])

def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    base_dir = os.path.dirname(os.path.dirname(script_dir))
    readme = os.path.join(base_dir, 'README.md')

    # Extract the dependency graph edges from the readme.
    readme_edges = []
    with open(readme, 'r', encoding='utf8') as f:
        line = ''
        while not 'START mermaid-dependency-graph' in line:
            line = f.readline()
        line = f.readline()
        while not 'END mermaid-dependency-graph' in line:
            if '-->' in line:
                (crate, dependency) = line.strip().split(' --> ', 1)
                if crate in CRATES_IN_GRAPH and dependency in CRATES_IN_GRAPH:
                    readme_edges.append((crate, dependency))
            line = f.readline()

    # Check for duplicate edges.
    readme_edges_set = set(readme_edges)
    has_duplicate_edges = len(readme_edges) != len(readme_edges_set)
    if has_duplicate_edges:
        duplicate_edges = readme_edges
        for edge in readme_edges_set:
            duplicate_edges.remove(edge)
        duplicate_edges = ['%s --> %s' % edge for edge in duplicate_edges]
        print('WARNING: Duplicate edges in README.md dependency graph:')
        for edge in sorted(duplicate_edges):
            print('    %s --> %s' % edge)

    # Extract the dependency graph edges from the Rust workspace.
    cargo_graph = subprocess.run(
        ['cargo', 'tree', '--all-features', '-e', 'normal', '--prefix', 'depth', '-f', ' {p}'],
        stdout=subprocess.PIPE,
        universal_newlines=True)
    cargo_edges = set()
    crate_stack = []
    for line in cargo_graph.stdout.splitlines():
        if len(line.strip()) == 0:
            continue
        (depth, crate, _) = line.strip().split(' ', 2)
        depth = int(depth)

        if depth == 0:
            crate_stack = [crate]
            continue

        while len(crate_stack) > depth:
            crate_stack.pop()
        if crate_stack[-1] in CRATES_IN_GRAPH and crate in CRATES_IN_GRAPH:
            cargo_edges.add((crate_stack[-1], crate))
        crate_stack.append(crate)

    # Check for missing edges.
    missing_edges = cargo_edges.difference(readme_edges_set)
    has_missing_edges = len(missing_edges) > 0
    if has_missing_edges:
        print('ERROR: Missing edges from README.md dependency graph:')
        for edge in sorted(missing_edges):
            print('    %s --> %s' % edge)

    # Check for stale edges.
    stale_edges = readme_edges_set.difference(cargo_edges)
    has_stale_edges = len(stale_edges) > 0
    if has_stale_edges:
        print('ERROR: Stale edges in README.md dependency graph:')
        for edge in sorted(stale_edges):
            print('    %s --> %s' % edge)

    if has_duplicate_edges or has_missing_edges or has_stale_edges:
        sys.exit(1)

if __name__ == '__main__':
    main()
