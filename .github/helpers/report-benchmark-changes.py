#!/usr/bin/env python3
"""Summarizes a criterion comparison against a saved baseline as Markdown.

Usage: report-benchmark-changes.py <criterion output directory>
           --baseline-commit <sha> [--regression-output <path>]

Reads the results that `cargo bench` writes when it compares with a saved
baseline, and prints one table row per benchmark with the relative change in
its mean time. A change is flagged only when the whole confidence interval of
the change lies beyond `CHANGE_THRESHOLD`. With `--regression-output`, appends
`regressed=true` or `regressed=false` to the given file, in the GitHub Actions
step output format. Exits successfully whenever the report is printed.
"""

import argparse
import json
import sys
from pathlib import Path

# The relative change in mean time that a benchmark must exceed to be flagged.
#
# Shared GitHub-hosted runners commonly vary by 10% or more between runs, and
# the baseline and the comparison run on different machines, so smaller
# changes are indistinguishable from noise.
CHANGE_THRESHOLD = 0.25

REGRESSION = 'regression'
IMPROVEMENT = 'improvement'
WITHIN_NOISE = ''


def classify(change):
    """Returns the label for a criterion `ChangeEstimates.mean` value."""
    interval = change['confidence_interval']
    if interval['lower_bound'] > CHANGE_THRESHOLD:
        return REGRESSION
    if interval['upper_bound'] < -CHANGE_THRESHOLD:
        return IMPROVEMENT
    return WITHIN_NOISE


def percent(fraction):
    return f'{fraction * 100:+.1f}%'


def benchmark_results(criterion_dir):
    """Yields `(benchmark id, mean change or None)` for each benchmark run.

    Criterion writes `<benchmark>/new/benchmark.json` for every benchmark that
    ran, and `<benchmark>/change/estimates.json` only when the baseline holds
    a result for it.
    """
    for metadata_path in sorted(criterion_dir.glob('**/new/benchmark.json')):
        benchmark_dir = metadata_path.parent.parent
        benchmark_id = json.loads(metadata_path.read_text())['full_id']
        change_path = benchmark_dir / 'change' / 'estimates.json'
        if change_path.is_file():
            yield benchmark_id, json.loads(change_path.read_text())['mean']
        else:
            yield benchmark_id, None


def print_report(results, baseline_commit):
    print('## Benchmark comparison')
    print()
    print(f'Compared with the baseline for `{baseline_commit}`.')
    print()
    if not results:
        print('No benchmark results were found.')
        return

    flagged = [
        benchmark_id for benchmark_id, change in results
        if change is not None and classify(change) != WITHIN_NOISE
    ]
    threshold = f'{CHANGE_THRESHOLD * 100:.0f}%'
    if flagged:
        print(f'{len(flagged)} benchmark(s) changed by more than {threshold}.')
    else:
        print(f'No benchmark changed by more than {threshold}.')
    print()
    print('| Benchmark | Mean change | Confidence interval | |')
    print('| --- | ---: | ---: | --- |')
    for benchmark_id, change in results:
        if change is None:
            print(f'| `{benchmark_id}` | | | not in baseline |')
            continue
        interval = change['confidence_interval']
        print(
            f'| `{benchmark_id}` | {percent(change["point_estimate"])} '
            f'| {percent(interval["lower_bound"])} to '
            f'{percent(interval["upper_bound"])} | {classify(change)} |'
        )


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('criterion_dir', type=Path)
    parser.add_argument('--baseline-commit', required=True)
    parser.add_argument('--regression-output', type=Path)
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.criterion_dir.is_dir():
        sys.exit(f'{args.criterion_dir} is not a directory')
    results = list(benchmark_results(args.criterion_dir))
    print_report(results, args.baseline_commit)

    if args.regression_output is not None:
        regressed = any(
            change is not None and classify(change) == REGRESSION
            for _, change in results
        )
        with args.regression_output.open('a') as output:
            output.write(f'regressed={str(regressed).lower()}\n')


if __name__ == '__main__':
    main()
