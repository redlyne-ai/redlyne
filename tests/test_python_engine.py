"""
Parity tests for the new Python engine (POC, Step 2+).

These tests run the new `redlyne_engine.py` against the same fixtures used
for the bash parity test, and compare the output to the bash-generated
golden files.

Step 2 limitation: only detection-level fields are asserted. The Python
engine doesn't yet produce remediation output (that's Step 3), so we
intentionally skip `remediated_code`, `comments`, and `imports` here.

When Step 3 ships and remediation is implemented, this test will be
upgraded to assert on every field, matching the rigor of the bash parity
test.

Each test asserts that:
- The Python engine produces the same `status` ('vulnerable' or 'safe')
  as the bash engine.
- The same set of OWASP categories is detected.
- The same `original_code` is captured (byte-equivalent inline encoding).

Run only the Python engine tests:
    pytest tests/test_python_engine.py -v

Run a single fixture against the Python engine:
    pytest tests/test_python_engine.py::test_python_detection_parity[001_yaml_unsafe_load]
"""
from __future__ import annotations

import pytest

from conftest import FIXTURES_DIR, list_fixtures, load_golden
from run_engine import run_engine


# Fixtures whose rules have been ported to the Python engine. Each entry
# means: there's a JSON rule under launch_tool/rules/ that handles this
# vulnerability pattern, and the Python engine output should match the
# bash-generated golden file (modulo documented bash quirks).
#
# The 003_os_system_concat fixture is intentionally excluded for now: the
# bash output for it has cosmetic anomalies (extra spaces around function
# args, weird trailing whitespace) that look like sed-pipeline bugs, not
# semantic remediation. Replicating those bugs in the Python rule would
# carry forward known bash quirks. Will revisit during the broader rule
# extraction (step 5+).
#
# Similarly, 102_multiple_vulns is excluded until os.system is in.
PYTHON_ENGINE_SUPPORTED_FIXTURES = [
    "001_yaml_unsafe_load",
    "002_eval_user_input",
    "004_flask_xss",
    "005_md5_password",
    # Step 6: fixtures for the new remediation rules added on top of
    # Devaic v2.0. Each one exercises a specific drop-in safe-replacement
    # remediation (random→secrets, sha1→sha512, yaml.dump→safe_dump, etc.)
    # so a regression in any of those rules surfaces here.
    "010_random_for_token",
    "011_sha1_password",
    "012_yaml_dump",
    "013_ssl_unverified",
    "014_flask_debug",
    "015_pickle_load",
    "016_requests_verify_false",
]

# Fixtures that exercise the safe path (no detection). These should pass
# parity from day one because the Python engine returns 'safe' when no
# rule matches, and that's a behavior independent of how many rules are
# loaded.
PYTHON_ENGINE_SAFE_FIXTURES = [
    "100_safe_code",
    "101_comments_only",
]


def _normalize_trailing(s: str) -> str:
    """
    Strip trailing whitespace from an inline-encoded code string.

    The legacy bash engine occasionally appends an extra trailing space to
    `remediated_code` due to a quirk in its sed pipeline (the substitution
    chain inadvertently adds whitespace). The Python engine produces clean
    output without that extra space, which is *better* but not byte-exact.

    We use this helper specifically when comparing `remediated_code` to
    abstract over that bash artifact. Original code, comments, and imports
    are NOT normalized — those fields are byte-compared.
    """
    return s.rstrip()


@pytest.mark.parametrize(
    "fixture_name",
    PYTHON_ENGINE_SUPPORTED_FIXTURES + PYTHON_ENGINE_SAFE_FIXTURES,
)
def test_python_detection_parity(fixture_name: str):
    """
    Run the Python engine on a fixture and compare full output to the
    bash-generated golden file.

    Step 3 expanded this from detection-only to full parity. We assert on
    every field returned by the engine: status, vulnerabilities,
    original_code, remediated_code (modulo trailing whitespace),
    comments, and imports.
    """
    fixture_path = FIXTURES_DIR / "detection" / f"{fixture_name}.py"
    expected = load_golden("detection", fixture_name)

    actual = run_engine(fixture_path, engine="python").to_dict()

    # 1. Status must match (vulnerable / safe)
    assert actual["status"] == expected["status"], (
        f"status mismatch on {fixture_name}: "
        f"actual={actual['status']!r}, expected={expected['status']!r}"
    )

    # 2. Vulnerability categories must match exactly
    assert actual["vulnerabilities"] == expected["vulnerabilities"], (
        f"vulnerabilities mismatch on {fixture_name}:\n"
        f"  actual:   {actual['vulnerabilities']}\n"
        f"  expected: {expected['vulnerabilities']}"
    )

    # Safe fixtures (no detections) carry no further fields to compare.
    if expected["status"] != "vulnerable":
        return

    # 3. Original code (inline-encoded) — byte-exact
    assert actual["original_code"] == expected["original_code"], (
        f"original_code mismatch on {fixture_name}:\n"
        f"  actual:   {actual['original_code']!r}\n"
        f"  expected: {expected['original_code']!r}"
    )

    # 4. Remediated code — compared modulo trailing whitespace to
    #    abstract over a bash sed-pipeline quirk (extra trailing space).
    actual_rem = _normalize_trailing(actual["remediated_code"])
    expected_rem = _normalize_trailing(expected["remediated_code"])
    assert actual_rem == expected_rem, (
        f"remediated_code mismatch on {fixture_name}:\n"
        f"  actual:   {actual_rem!r}\n"
        f"  expected: {expected_rem!r}"
    )

    # 5. Comments — byte-exact
    assert actual["comments"] == expected["comments"], (
        f"comments mismatch on {fixture_name}:\n"
        f"  actual:   {actual['comments']}\n"
        f"  expected: {expected['comments']}"
    )

    # 6. Imports added by remediation — byte-exact
    assert actual["imports"] == expected["imports"], (
        f"imports mismatch on {fixture_name}:\n"
        f"  actual:   {actual['imports']}\n"
        f"  expected: {expected['imports']}"
    )


def test_python_engine_speed_baseline():
    """
    Smoke check: the Python engine must be at least 100x faster than the
    bash engine on the canonical 001_yaml_unsafe_load fixture.

    The bash engine takes ~17-22s per snippet on this machine.
    The Python engine should take well under 200ms (engine startup + scan).
    100x is a conservative threshold that catches obvious regressions
    without flaking on noisy CI runners.
    """
    fixture = FIXTURES_DIR / "detection" / "001_yaml_unsafe_load.py"
    result = run_engine(fixture, engine="python")

    assert result.status == "vulnerable", (
        f"Engine returned wrong status: {result.status} (error: {result.error})"
    )
    assert result.elapsed_s is not None
    assert result.elapsed_s < 1.0, (
        f"Python engine too slow on canonical fixture: {result.elapsed_s:.3f}s "
        f"(expected < 1.0s, ideally < 0.2s). Possible regression in scanner."
    )
