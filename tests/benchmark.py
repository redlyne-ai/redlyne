#!/usr/bin/env python3
"""
Performance benchmark for the Redlyne engine.

Runs the engine over every fixture (or a custom corpus) and records timing
statistics. Saves a JSON snapshot in `benchmarks/results/` that you can
diff against future runs after refactoring.

Usage:
    python tests/benchmark.py                    # run on all fixtures
    python tests/benchmark.py path/to/corpus     # run on a custom directory

Compare two snapshots:
    python tests/benchmark.py --compare A.json B.json

Engineering note:
- The engine is single-threaded; we don't parallelize because parallelism
  would mask per-snippet latency (the metric that matters for IDE UX).
- Each snippet is run only once. This is sufficient for noise-tolerant
  comparison (variance is dominated by I/O and process spawn overhead,
  not algorithm). For tighter measurements, increase `--repeat`.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from run_engine import run_engine


TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
DEFAULT_CORPUS = TESTS_DIR / "fixtures" / "detection"
RESULTS_DIR = REPO_ROOT / "benchmarks" / "results"


def _percentile(values: list[float], q: float) -> float:
    """Compute the q-th percentile (q in 0..100). Returns 0.0 if empty."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (q / 100)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def benchmark(corpus_dir: Path, repeat: int = 1) -> dict:
    """Run the engine over every .py file in `corpus_dir` and collect stats."""
    fixtures = sorted(corpus_dir.glob("*.py"))
    if not fixtures:
        raise FileNotFoundError(f"No .py fixtures found in {corpus_dir}")

    try:
        display_dir = corpus_dir.relative_to(REPO_ROOT)
    except ValueError:
        display_dir = corpus_dir
    print(f"Benchmarking {len(fixtures)} fixture(s) in {display_dir}/")
    if repeat > 1:
        print(f"  (each fixture run {repeat} times, taking the median)")
    print()

    per_fixture = []
    for fixture in fixtures:
        runs = []
        for _ in range(repeat):
            result = run_engine(fixture)
            runs.append(result.elapsed_s or 0.0)

        median = statistics.median(runs)
        per_fixture.append({
            "name": fixture.name,
            "size_lines": len(fixture.read_text(encoding="utf-8").splitlines()),
            "elapsed_s_median": round(median, 4),
            "elapsed_s_runs": [round(r, 4) for r in runs],
        })
        print(f"  {fixture.name:<40} {median:6.2f}s")

    elapsed_values = [f["elapsed_s_median"] for f in per_fixture]

    summary = {
        "n_fixtures": len(fixtures),
        "repeat_per_fixture": repeat,
        "total_elapsed_s": round(sum(elapsed_values), 2),
        "median_per_snippet_s": round(statistics.median(elapsed_values), 4),
        "p95_per_snippet_s": round(_percentile(elapsed_values, 95), 4),
        "min_per_snippet_s": round(min(elapsed_values), 4),
        "max_per_snippet_s": round(max(elapsed_values), 4),
        "stdev_s": round(statistics.stdev(elapsed_values), 4)
            if len(elapsed_values) > 1 else 0.0,
    }

    try:
        corpus_label = str(corpus_dir.relative_to(REPO_ROOT))
    except ValueError:
        corpus_label = str(corpus_dir)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "corpus": corpus_label,
        "summary": summary,
        "per_fixture": per_fixture,
    }


def save_snapshot(payload: dict) -> Path:
    """Persist a benchmark snapshot to disk and return its path."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"benchmark_{ts}.json"
    out.write_text(json.dumps(payload, indent=2) + "\n")
    return out


def print_summary(payload: dict) -> None:
    s = payload["summary"]
    print()
    print("=" * 60)
    print(f"Total snippets:  {s['n_fixtures']}")
    print(f"Total time:      {s['total_elapsed_s']} s")
    print(f"Median:          {s['median_per_snippet_s']} s/snippet")
    print(f"p95:             {s['p95_per_snippet_s']} s/snippet")
    print(f"Min - Max:       {s['min_per_snippet_s']} - {s['max_per_snippet_s']} s")
    print(f"Std deviation:   {s['stdev_s']} s")
    print("=" * 60)


def compare(snapshot_a_path: Path, snapshot_b_path: Path) -> None:
    """Side-by-side comparison of two benchmark snapshots."""
    a = json.loads(snapshot_a_path.read_text(encoding="utf-8"))
    b = json.loads(snapshot_b_path.read_text(encoding="utf-8"))

    print(f"\nA: {snapshot_a_path.name} ({a['timestamp']})")
    print(f"B: {snapshot_b_path.name} ({b['timestamp']})\n")

    metrics = [
        ("Total time (s)", "total_elapsed_s"),
        ("Median per snippet (s)", "median_per_snippet_s"),
        ("p95 per snippet (s)", "p95_per_snippet_s"),
        ("Max per snippet (s)", "max_per_snippet_s"),
    ]

    print(f"{'Metric':<30}{'A':>12}{'B':>12}{'Δ':>12}{'Δ %':>10}")
    print("-" * 76)
    for label, key in metrics:
        va = a["summary"][key]
        vb = b["summary"][key]
        delta = vb - va
        pct = (delta / va * 100) if va else 0
        sign = "+" if delta > 0 else ""
        print(f"{label:<30}{va:>12.3f}{vb:>12.3f}{sign}{delta:>11.3f}{sign}{pct:>9.1f}%")
    print()


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Benchmark the Redlyne engine performance"
    )
    p.add_argument(
        "corpus",
        nargs="?",
        type=Path,
        default=DEFAULT_CORPUS,
        help="Directory containing .py snippets to benchmark "
             f"(default: {DEFAULT_CORPUS.relative_to(REPO_ROOT)})",
    )
    p.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="How many times to run each fixture (median is reported). Default: 1",
    )
    p.add_argument(
        "--no-save",
        action="store_true",
        help="Don't persist the snapshot to benchmarks/results/",
    )
    p.add_argument(
        "--compare",
        nargs=2,
        metavar=("A", "B"),
        type=Path,
        help="Compare two existing benchmark snapshots and exit",
    )
    return p


def main() -> None:
    args = _build_argparser().parse_args()

    if args.compare:
        compare(args.compare[0], args.compare[1])
        return

    payload = benchmark(args.corpus, repeat=args.repeat)
    print_summary(payload)

    if not args.no_save:
        out = save_snapshot(payload)
        print(f"Saved snapshot: {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
