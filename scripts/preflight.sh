#!/usr/bin/env bash
# Pre-flight checks before `vsce package`. Run from the repo root.
#
# Verifies:
#   - Python is on PATH and finds the engine
#   - Engine runs end-to-end on a known-vulnerable fixture
#   - All 14 parity tests pass
#   - Rule set loads cleanly (no compile errors)
#
# Usage:
#   bash scripts/preflight.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "== Redlyne pre-flight =="

# 1. Python detection
PY=""
for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" --version >/dev/null 2>&1; then
            PY="$cand"; break
        fi
    fi
done
if [ -z "$PY" ]; then
    echo "✗ Python not found on PATH"
    exit 1
fi
echo "✓ Python: $PY ($($PY --version))"

# 2. Engine smoke test
echo -n "✓ Engine smoke test: "
"$PY" launch_tool/redlyne_engine.py tests/fixtures/detection/011_sha1_password.py >/dev/null
echo "OK"

# 3. Rule load count
echo -n "✓ Rule load: "
"$PY" -c "
import sys
sys.path.insert(0, 'launch_tool')
from redlyne_engine import load_rules, RULES_DIR
rules, errors = load_rules(RULES_DIR, verbose=False)
print(f'{len(rules)} rules loaded, {len(errors)} errors')
assert len(errors) == 0, f'Rule compile errors: {len(errors)}'
"

# 4. Parity tests
echo "✓ Running pytest..."
"$PY" -m pytest tests/test_python_engine.py -q

echo
echo "All checks green. Safe to run: vsce package"
