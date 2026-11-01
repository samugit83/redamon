#!/usr/bin/env python3
"""Count what JS Recon's secret rules report on JavaScript known to hold no secret.

Runs `scan_js_content` (recon/helpers/js_recon/patterns.py) over every `.js`
file under the given directories and prints, per rule, how many hits it made,
in how many files, at which severity, with one redacted example. On a corpus of
clean open-source library code every hit at medium or above is a false positive,
so a before/after pair of censuses measures what a rule change removed.

    # the corpus the Phase 0 fixes were measured on: the 300 largest library
    # files, one per basename, plus the clean hosts of the JS secret lab
    python3 -I tooling/scripts/js_secret_fp_census.py --largest 300 webapp/node_modules
    python3 -I tooling/scripts/js_secret_fp_census.py testing/guinea_pigs/js_secret_lab/generated/vendor-only

patterns.py is loaded by file path, not through the `recon` package, whose
__init__ imports the scanner's third-party dependencies: the census needs only
the standard library, so host Python is enough. No value is printed whole.
"""
import argparse
import importlib.util
import json
import os
import sys
from collections import defaultdict

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_PATTERNS = os.path.join(_REPO, 'recon', 'helpers', 'js_recon', 'patterns.py')


def _load_patterns():
    spec = importlib.util.spec_from_file_location('js_recon_patterns', _PATTERNS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _js_files(roots: list) -> list:
    files = []
    for root in roots:
        if os.path.isfile(root):
            files.append(root)
            continue
        for dirpath, _dirs, names in os.walk(root):
            files.extend(os.path.join(dirpath, n) for n in names if n.endswith('.js'))
    return sorted(files)


def _largest_unique(files: list, n: int) -> list:
    """The `n` largest files, one per basename: a package vendored under many
    parents is one library, and counting it N times inflates its rules."""
    by_size = sorted(files, key=lambda p: (-os.path.getsize(p), p))
    picked, seen = [], set()
    for path in by_size:
        name = os.path.basename(path)
        if name in seen:
            continue
        seen.add(name)
        picked.append(path)
        if len(picked) >= n:
            break
    return sorted(picked)


def census(files: list, patterns) -> dict:
    rules: dict = defaultdict(lambda: {'hits': 0, 'files': set(), 'severity': defaultdict(int),
                                       'example': ''})
    for path in files:
        try:
            with open(path, encoding='utf-8', errors='replace') as fh:
                content = fh.read()
        except OSError:
            continue
        findings, _ = patterns.scan_js_content(content, path)
        for f in findings:
            row = rules[f['name']]
            row['hits'] += 1
            row['files'].add(path)
            row['severity'][f['severity']] += 1
            if not row['example']:
                row['example'] = f"{f['redacted_value']} ({os.path.basename(path)}:{f['line_number']})"
    return rules


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('roots', nargs='+', help='directories or .js files')
    ap.add_argument('--largest', type=int, metavar='N',
                    help='keep only the N largest files, one per basename')
    ap.add_argument('--json', metavar='PATH', help='also write the counts as JSON')
    args = ap.parse_args()

    patterns = _load_patterns()
    files = _js_files(args.roots)
    if args.largest:
        files = _largest_unique(files, args.largest)
    rules = census(files, patterns)

    order = patterns.SEVERITY_ORDER
    worst = lambda r: max((order.get(s, 0) for s in r['severity']), default=0)  # noqa: E731
    rows = sorted(rules.items(), key=lambda kv: (-worst(kv[1]), -kv[1]['hits'], kv[0]))
    total_bytes = sum(os.path.getsize(p) for p in files)
    print(f"# js_recon false-positive census: {len(files)} files, {total_bytes / 1024 / 1024:.1f} MB")
    print(f"{'rule':<36} {'hits':>5} {'files':>5}  severity            example")
    for name, row in rows:
        sev = ','.join(f"{s}:{n}" for s, n in sorted(row['severity'].items(),
                                                     key=lambda kv: -order.get(kv[0], 0)))
        print(f"{name:<36} {row['hits']:>5} {len(row['files']):>5}  {sev:<19} {row['example']}")
    medium_up = sum(n for row in rules.values() for s, n in row['severity'].items()
                    if order.get(s, 0) >= order['medium'])
    print(f"# total hits: {sum(r['hits'] for r in rules.values())}; at medium or above: {medium_up}")

    if args.json:
        with open(args.json, 'w') as fh:
            json.dump({'files': len(files), 'bytes': total_bytes, 'medium_or_above': medium_up,
                       'rules': {n: {'hits': r['hits'], 'files': len(r['files']),
                                     'severity': dict(r['severity'])} for n, r in rules.items()}},
                      fh, indent=1, sort_keys=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
