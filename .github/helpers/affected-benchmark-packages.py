#!/usr/bin/env python3
"""Lists the workspace packages whose benchmarks a change can affect.

Usage: affected-benchmark-packages.py --base <commit> --head <commit>
       affected-benchmark-packages.py --all

Prints the name of each workspace package that has a `[[bench]]` target, one
per line. With `--base` and `--head`, prints only the packages that the files
changed between the two commits can affect: a changed file affects the package
whose directory contains it, and every benchmarked package that depends on
that package through workspace path dependencies. A change to a file in
`WORKSPACE_WIDE_PATHS` affects every benchmarked package. With `--all`, prints
every benchmarked package.
"""

import argparse
import json
import subprocess
from pathlib import PurePosixPath

# Repository paths whose changes can affect every benchmark: the workspace
# manifest and lockfile, the toolchain and Cargo configuration, and the
# workflow and helper that select and run the benchmarks.
WORKSPACE_WIDE_PATHS = [
    PurePosixPath('Cargo.toml'),
    PurePosixPath('Cargo.lock'),
    PurePosixPath('rust-toolchain.toml'),
    PurePosixPath('.cargo'),
    PurePosixPath('.github/workflows/benchmarks.yml'),
    PurePosixPath('.github/helpers/affected-benchmark-packages.py'),
]

# The dependency kinds that are compiled into a package's library.
LIBRARY_DEPENDENCY_KINDS = {None, 'build'}


def workspace_packages():
    """Returns the workspace root and the workspace packages from `cargo metadata`."""
    metadata = json.loads(subprocess.run(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps'],
        check=True, capture_output=True, text=True,
    ).stdout)
    return PurePosixPath(metadata['workspace_root']), metadata['packages']


def package_directory(package, workspace_root):
    return PurePosixPath(package['manifest_path']).parent.relative_to(workspace_root)


def path_dependencies(package, workspace_names, kinds):
    """Returns the names of the workspace packages that `package` depends on."""
    return {
        dependency['name'] for dependency in package['dependencies']
        if dependency.get('path') is not None
        and dependency['name'] in workspace_names
        and (kinds is None or dependency['kind'] in kinds)
    }


def benchmark_inputs(package, packages_by_name):
    """Returns the workspace packages that a package's benchmarks are built from.

    The benchmarks use the package itself, its development dependencies, and
    the library dependencies of all of those, transitively.
    """
    workspace_names = packages_by_name.keys()
    inputs = {package['name']}
    pending = path_dependencies(package, workspace_names, kinds=None)
    while pending:
        name = pending.pop()
        if name in inputs:
            continue
        inputs.add(name)
        pending |= path_dependencies(
            packages_by_name[name], workspace_names, LIBRARY_DEPENDENCY_KINDS)
    return inputs


def changed_paths(base, head):
    output = subprocess.run(
        ['git', 'diff', '--name-only', base, head],
        check=True, capture_output=True, text=True,
    ).stdout
    return [PurePosixPath(line) for line in output.splitlines()]


def owning_package(path, directories):
    """Returns the package whose directory most closely contains `path`, if any."""
    owners = [
        (len(directory.parts), name) for name, directory in directories.items()
        if directory == PurePosixPath('.') or directory in path.parents
    ]
    return max(owners)[1] if owners else None


def is_workspace_wide(path):
    return any(path == wide or wide in path.parents for wide in WORKSPACE_WIDE_PATHS)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--all', action='store_true')
    selection.add_argument('--base')
    parser.add_argument('--head')
    args = parser.parse_args()
    if (args.base is None) != (args.head is None):
        parser.error('--base and --head must be given together')
    return args


def main():
    args = parse_args()
    workspace_root, packages = workspace_packages()
    packages_by_name = {package['name']: package for package in packages}
    benchmarked = sorted(
        package['name'] for package in packages
        if any('bench' in target['kind'] for target in package['targets'])
    )

    if args.all:
        selected = benchmarked
    else:
        paths = changed_paths(args.base, args.head)
        if any(is_workspace_wide(path) for path in paths):
            selected = benchmarked
        else:
            directories = {
                name: package_directory(package, workspace_root)
                for name, package in packages_by_name.items()
            }
            changed_packages = {owning_package(path, directories) for path in paths}
            selected = [
                name for name in benchmarked
                if benchmark_inputs(packages_by_name[name], packages_by_name)
                & changed_packages
            ]

    for name in selected:
        print(name)


if __name__ == '__main__':
    main()
