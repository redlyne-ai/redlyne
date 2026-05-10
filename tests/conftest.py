"""
Pytest configuration and shared fixtures for Redlyne test suite.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
GOLDEN_DIR = TESTS_DIR / "golden"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(scope="session")
def golden_dir() -> Path:
    return GOLDEN_DIR


def load_golden(category: str, name: str) -> dict:
    """
    Load a golden expected result.

    Args:
        category: 'detection' or 'remediation'
        name: snippet name without extension (e.g. '001_yaml_unsafe_load')
    """
    golden_path = GOLDEN_DIR / category / f"{name}.json"
    if not golden_path.exists():
        raise FileNotFoundError(
            f"No golden file for {category}/{name}. "
            f"Generate it by running: python tests/regenerate_golden.py {category}/{name}"
        )
    # Force UTF-8: golden files contain non-ASCII characters (em-dashes,
    # smart quotes) inside fixture docstrings. On Windows, read_text()
    # without an encoding falls back to the system code page (cp1252 /
    # cp850), corrupts the bytes, and the comparison silently mismatches.
    return json.loads(golden_path.read_text(encoding="utf-8"))


def list_fixtures(category: str) -> list[str]:
    """List names of fixtures available in a category, sorted."""
    fixture_dir = FIXTURES_DIR / category
    if not fixture_dir.exists():
        return []
    return sorted(p.stem for p in fixture_dir.glob("*.py"))
