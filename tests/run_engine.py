"""
Helper to invoke the Redlyne legacy bash engine and capture structured output.

Used by both parity tests (compare current vs new implementation) and the
benchmark script. Wraps the bash engine in a clean Python API that returns
a normalized dict — easy to compare and easy to JSON-serialize as a golden
file.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIR = REPO_ROOT / "launch_tool"
STARTER = TOOL_DIR / "patchitpy_starter.sh"
PYTHON_ENGINE = TOOL_DIR / "redlyne_engine.py"

DEFAULT_TIMEOUT_S = 120


@dataclass
class EngineResult:
    """
    Normalized output of the Redlyne engine on a single Python snippet.

    Use `.to_dict()` to serialize to JSON (golden file format).
    Two `EngineResult` instances are compared for equality field-by-field.
    """

    status: str
    """One of 'safe', 'vulnerable', 'no_detection', 'error'."""

    vulnerabilities: list[str] = field(default_factory=list)
    """OWASP categories detected, sorted alphabetically."""

    original_code: str = ""
    """Input code as the engine saw it (after preprocessing)."""

    remediated_code: str = ""
    """Patched code, or 'NO-REM' / 'REM-WITH-COMMENT' if patch unavailable."""

    comments: list[str] = field(default_factory=list)
    """Remediation guidance text shown to the user."""

    imports: list[str] = field(default_factory=list)
    """Module imports to add at the top of the file."""

    elapsed_s: Optional[float] = None
    """Wall-clock time (seconds) for the engine to process the snippet."""

    error: Optional[str] = None
    """Stderr or error message, only set if status == 'error'."""

    def to_dict(self) -> dict:
        d = asdict(self)
        # elapsed_s is non-deterministic — exclude from golden files
        d.pop("elapsed_s", None)
        return d


def run_engine(
    snippet_path: Path,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    engine: str = "bash",
) -> EngineResult:
    """
    Invoke a Redlyne engine on a Python snippet and return parsed result.

    Args:
        snippet_path: Path to the Python file to scan.
        timeout_s: Hard timeout for engine invocation.
        engine: 'bash' (legacy, default) or 'python' (new POC engine).

    Implementation notes:
    - The bash variant copies the snippet to a temp dir so the engine writes
      its outputs there (the engine creates `results_<basename>/` next to
      the input). It also ensures the scratch dir
      `launch_tool/generated_file/` exists.
    - The python variant invokes `redlyne_engine.py --format engine-result`
      and parses its JSON output directly (no intermediate files).
    - Both catch timeouts and non-zero exits, returning status='error'.
    """
    if engine == "python":
        return _run_python_engine(snippet_path, timeout_s)
    elif engine == "bash":
        return _run_bash_engine(snippet_path, timeout_s)
    else:
        return EngineResult(
            status="error",
            error=f"Unknown engine: {engine!r} (must be 'bash' or 'python')",
        )


def _run_python_engine(snippet_path: Path, timeout_s: int) -> EngineResult:
    """Invoke the new Python engine with --format engine-result and parse it."""
    if not PYTHON_ENGINE.exists():
        return EngineResult(
            status="error",
            error=f"Python engine not found at {PYTHON_ENGINE}",
        )

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["python3", str(PYTHON_ENGINE), str(snippet_path),
             "--format", "engine-result"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return EngineResult(
            status="error",
            error=f"Python engine timed out after {timeout_s}s",
            elapsed_s=float(timeout_s),
        )
    elapsed = time.perf_counter() - start

    if proc.returncode != 0:
        return EngineResult(
            status="error",
            error=f"Python engine exited with code {proc.returncode}: "
                  f"{proc.stderr[-500:]}",
            elapsed_s=elapsed,
        )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return EngineResult(
            status="error",
            error=f"Could not parse engine output as JSON: {e}",
            elapsed_s=elapsed,
        )

    return EngineResult(
        status=data.get("status", "error"),
        vulnerabilities=data.get("vulnerabilities", []),
        original_code=data.get("original_code", ""),
        remediated_code=data.get("remediated_code", ""),
        comments=data.get("comments", []),
        imports=data.get("imports", []),
        error=data.get("error"),
        elapsed_s=elapsed,
    )


def _run_bash_engine(snippet_path: Path, timeout_s: int) -> EngineResult:
    """Invoke the legacy bash engine and parse its REM_*.txt output."""
    if not STARTER.exists():
        return EngineResult(
            status="error",
            error=f"Bash starter not found at {STARTER}",
        )

    # Make sure the engine's scratch dir exists
    (TOOL_DIR / "generated_file").mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="redlyne_test_") as tmp:
        tmp_path = Path(tmp)
        # Use a stable filename ('input.py') so the results dir is predictable
        target = tmp_path / "input.py"
        shutil.copy(snippet_path, target)

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                ["bash", str(STARTER), str(target), str(TOOL_DIR)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return EngineResult(
                status="error",
                error=f"Engine timed out after {timeout_s}s",
                elapsed_s=float(timeout_s),
            )
        elapsed = time.perf_counter() - start

        if proc.returncode != 0:
            return EngineResult(
                status="error",
                error=f"Engine exited with code {proc.returncode}: {proc.stderr[-500:]}",
                elapsed_s=elapsed,
            )

        # Output file is at <tmp>/results_input/REM_*.txt
        results_dir = tmp_path / "results_input"
        if not results_dir.exists():
            return EngineResult(status="no_detection", elapsed_s=elapsed)

        rem_files = sorted(results_dir.glob("REM_*.txt"))
        if not rem_files:
            return EngineResult(status="no_detection", elapsed_s=elapsed)

        result = _parse_rem_file(rem_files[-1])
        result.elapsed_s = elapsed
        return result


def _parse_rem_file(rem_path: Path) -> EngineResult:
    """
    Parse the engine's text output format into an EngineResult.

    Format (one item per line, in order):
      [0] vulnerability categories ('SAFE-CODE' if no vulns found)
      [1] original code (inline-encoded with \\n separators) OR
          'NO-REM' / 'REM-WITH-COMMENT' marker
      [2] remediated code (inline-encoded with \\n separators)
      [3..N] comments, one per line, until the 'imports' sentinel
      [N+1..] imports to add, one per line
    """
    raw = rem_path.read_text(encoding="utf-8", errors="replace")
    lines = raw.split("\n")

    if not lines:
        return EngineResult(status="error", error="Empty REM file")

    vuln_line = lines[0]

    if vuln_line.strip() == "SAFE-CODE":
        return EngineResult(status="safe")

    # Parse vulnerability categories
    vulnerabilities = sorted(
        {v.strip() for v in vuln_line.split(",") if v.strip()}
    )

    second_line = lines[1] if len(lines) > 1 else ""
    if second_line == "NO-REM":
        original = ""
        remediated = "NO-REM"
        rest_starts_at = 2
    elif second_line == "REM-WITH-COMMENT":
        original = ""
        remediated = "REM-WITH-COMMENT"
        rest_starts_at = 2
    else:
        original = second_line
        remediated = lines[2] if len(lines) > 2 else ""
        rest_starts_at = 3

    # Comments until 'imports' sentinel
    comments: list[str] = []
    i = rest_starts_at
    while i < len(lines) and lines[i].strip() != "imports":
        if lines[i].strip():
            comments.append(lines[i])
        i += 1
    # Skip the 'imports' sentinel itself
    i += 1

    # Imports (the rest)
    imports = [line for line in lines[i:] if line.strip()]

    return EngineResult(
        status="vulnerable",
        vulnerabilities=vulnerabilities,
        original_code=original,
        remediated_code=remediated,
        comments=comments,
        imports=imports,
    )


if __name__ == "__main__":
    # CLI for quick manual tests:
    #   python tests/run_engine.py path/to/snippet.py
    import json
    import sys

    if len(sys.argv) != 2:
        print("Usage: python run_engine.py <snippet.py>", file=sys.stderr)
        sys.exit(1)

    result = run_engine(Path(sys.argv[1]))
    payload = result.to_dict()
    payload["_elapsed_s"] = round(result.elapsed_s or 0, 3)
    print(json.dumps(payload, indent=2))
