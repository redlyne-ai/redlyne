#!/usr/bin/env python3
"""
Regenerate golden files by running the legacy bash engine on every fixture.

Usage:
    python tests/regenerate_golden.py                  # regenerate all
    python tests/regenerate_golden.py detection        # only detection
    python tests/regenerate_golden.py detection/001    # only one fixture

Run this script when:
- you add a new fixture and need to capture its expected output
- the legacy bash engine is intentionally changed and you need to re-baseline
- you want to verify your local environment runs the engine the same as CI
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from run_engine import run_engine


TESTS_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
GOLDEN_DIR = TESTS_DIR / "golden"


DEFAULT_ENGINE = "python"  # since Step 5: Devaic-based Python engine is the
                            # new ground truth. Set to "bash" to capture the
                            # legacy engine's behavior instead.


def regenerate_one(fixture_path: Path, engine: str = DEFAULT_ENGINE) -> None:
    """Run the engine on a single fixture and write the golden file."""
    rel = fixture_path.relative_to(FIXTURES_DIR)
    golden_path = GOLDEN_DIR / rel.parent / f"{rel.stem}.json"
    golden_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"  → {rel} [{engine}] ... ", end="", flush=True)
    result = run_engine(fixture_path, engine=engine)
    payload = result.to_dict()
    golden_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    elapsed = result.elapsed_s or 0
    print(f"{result.status} ({elapsed:.2f}s)")


def regenerate_all(filter_path: str | None = None, engine: str = DEFAULT_ENGINE) -> None:
    """Walk the fixtures dir and regenerate golden files."""
    target_root = FIXTURES_DIR
    if filter_path:
        target_root = FIXTURES_DIR / filter_path

    if target_root.is_file():
        regenerate_one(target_root, engine=engine)
        return

    if not target_root.exists():
        print(f"Path not found: {target_root}", file=sys.stderr)
        sys.exit(1)

    fixtures = sorted(target_root.rglob("*.py"))
    try:
        rel = target_root.relative_to(TESTS_DIR)
    except ValueError:
        rel = target_root
    print(f"Regenerating {len(fixtures)} golden file(s) under {rel}/ using {engine} engine")

    for fixture in fixtures:
        regenerate_one(fixture, engine=engine)

    print("\nDone. Review the diff and commit if expected.")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default=None,
                   help="Optional fixture or directory under tests/fixtures/")
    p.add_argument("--engine", choices=["bash", "python"], default=DEFAULT_ENGINE,
                   help=f"Engine to capture as golden (default: {DEFAULT_ENGINE})")
    args = p.parse_args()
    regenerate_all(args.path, engine=args.engine)
