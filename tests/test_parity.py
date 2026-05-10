"""
Parity tests: ensure the engine under test produces output identical to
the captured golden files.

Each fixture in `tests/fixtures/<category>/` is run through the engine.
The result is compared field-by-field against the matching golden file
in `tests/golden/<category>/`.

When refactoring the engine (e.g. porting from bash to Python), you want
this test suite to keep passing. Any divergence either signals a real
regression OR an intended behavior change that requires regenerating the
golden file with `python tests/regenerate_golden.py`.

Run all parity tests:
    pytest tests/test_parity.py -v

Run a single fixture:
    pytest tests/test_parity.py::test_detection_parity[001_yaml_unsafe_load] -v

The test asserts on the full EngineResult: vulnerabilities, original_code,
remediated_code, comments, and imports. So this is both a detection-parity
and a remediation-parity test.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from conftest import FIXTURES_DIR, GOLDEN_DIR, list_fixtures, load_golden
from run_engine import run_engine


# The legacy bash engine is not byte-compatible across operating systems.
# BSD sed (macOS) and GNU sed (Linux) escape backslashes differently in
# the inline-encoding step, so the captured `original_code` field diverges
# by OS. Until the bash engine is retired in favor of the Python engine,
# we restrict its parity tests to Linux where the golden files were
# generated. The Python engine (test_python_engine.py) runs on all OSes.
LEGACY_BASH_LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "Legacy bash engine has BSD-vs-GNU sed inconsistencies; "
        "skipping bash parity on non-Linux. The Python engine is fully "
        "cross-platform and is exercised in test_python_engine.py."
    ),
)


def _detection_fixture_ids() -> list[str]:
    """Return all detection fixtures present on disk."""
    return list_fixtures("detection")


@LEGACY_BASH_LINUX_ONLY
@pytest.mark.parametrize(
    "fixture_name",
    _detection_fixture_ids(),
    ids=_detection_fixture_ids(),
)
def test_detection_parity(fixture_name: str):
    """
    For each detection fixture, run the engine and compare with golden.
    """
    fixture_path = FIXTURES_DIR / "detection" / f"{fixture_name}.py"
    expected = load_golden("detection", fixture_name)

    actual = run_engine(fixture_path).to_dict()

    # Field-by-field compare for friendlier failure messages.
    assert actual["status"] == expected["status"], (
        f"status mismatch: actual={actual['status']!r}, "
        f"expected={expected['status']!r}"
    )

    assert actual["vulnerabilities"] == expected["vulnerabilities"], (
        f"vulnerabilities mismatch:\n"
        f"  actual:   {actual['vulnerabilities']}\n"
        f"  expected: {expected['vulnerabilities']}"
    )

    assert actual["original_code"] == expected["original_code"], (
        f"original_code mismatch:\n"
        f"  actual:   {actual['original_code']!r}\n"
        f"  expected: {expected['original_code']!r}"
    )

    assert actual["remediated_code"] == expected["remediated_code"], (
        f"remediated_code mismatch:\n"
        f"  actual:   {actual['remediated_code']!r}\n"
        f"  expected: {expected['remediated_code']!r}"
    )

    assert actual["comments"] == expected["comments"], (
        f"comments mismatch:\n"
        f"  actual:   {actual['comments']}\n"
        f"  expected: {expected['comments']}"
    )

    assert actual["imports"] == expected["imports"], (
        f"imports mismatch:\n"
        f"  actual:   {actual['imports']}\n"
        f"  expected: {expected['imports']}"
    )


def test_no_orphan_golden_files():
    """
    Every golden file must correspond to a real fixture. If a golden has
    no matching fixture, it's stale — likely a fixture was renamed/deleted
    without removing its golden.
    """
    fixture_stems = {p.stem for p in (FIXTURES_DIR / "detection").glob("*.py")}
    golden_stems = {p.stem for p in (GOLDEN_DIR / "detection").glob("*.json")}

    orphans = golden_stems - fixture_stems
    assert not orphans, (
        f"Orphan golden files (no matching fixture): {sorted(orphans)}"
    )


def test_no_missing_golden_files():
    """
    Every fixture must have a golden file. If a fixture is added without
    its golden, the parity test silently skips it. Catch that here.
    """
    fixture_stems = {p.stem for p in (FIXTURES_DIR / "detection").glob("*.py")}
    golden_stems = {p.stem for p in (GOLDEN_DIR / "detection").glob("*.json")}

    missing = fixture_stems - golden_stems
    assert not missing, (
        f"Fixtures without a golden file: {sorted(missing)}\n"
        f"Generate them with: python tests/regenerate_golden.py"
    )
