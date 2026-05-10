# Change Log

## [0.1.1] - 2026-05-10

### Fixed
- Import duplication check could be fooled by comments or strings
  containing the import statement (e.g. `# please add: import ast`
  would suppress the insertion of a real `import ast`). The check now
  matches the import statement only at the start of a line, the way
  Python actually parses it.

## [0.1.0] - 2026-05-10

### Changed (breaking)
- **Cross-platform**: the engine no longer requires WSL or bash. The
  extension now runs natively on Windows, macOS, and Linux. The only
  runtime dependency is Python 3.10+ on `PATH`.
- **Engine**: rewrote the detection and remediation core in Python (was
  bash + sed + jq). Same interface, same JSON shape, faster and portable.
- **OWASP Top 10:2025**: category names emitted by detections now follow
  the 2025 taxonomy (finalized January 2026). Notably `Identification
  and Authentication Failures` → `Authentication Failures`, and
  `Server-Side Request Forgery` is folded into `Injection`.

### Added
- Devaic v2.0 rule schema integrated. **459 detection rules** load,
  up from 8 in v0.0.1.
- **70+ rules now ship with auto-remediation** (drop-in safer
  alternatives for crypto, TLS, deserialization, Flask debug, JWT,
  subprocess shell, password hashing, Jinja2 autoescape, SQL parametrization,
  LDAP escape, and 14 multi-line templates that rewrite vulnerable
  blocks of code) — up from 4 in v0.0.1.
- **Multi-line template engine** for remediation: a single rule can
  rewrite an entire vulnerable block (e.g. `with open(file) as f: yaml.load(f)`
  → `os.path.join + isfile guard + safe_load`) preserving indentation
  and adding required imports.
- **Scope-aware suppression** (`pattern_not_file`): file-level negative
  lookahead lets rules recognize sanitization helpers (`escape()`,
  `secure_filename()`, `os.path.isfile()`, parameterized SQL) on lines
  other than the matched one — cuts ~21 percentage points of FPR.
- **Detection bench**: `tests/bench_dataset.py` measures recall on
  1,455 known-vulnerable Python files from three benchmarks:
  - SecurityEval (s2e-lab): 47.1% recall (57/121)
  - Copilot CWE Scenarios (Pearce et al.): 61.6% recall (631/1024)
  - **PoisonPy (Cotroneo et al.)**, the dataset Devaic was originally
    benchmarked on, now reproducible apples-to-apples:
    - **Recall 97.4%** | **Precision 71.2%** | **F1 0.823** (n=310 paired)
- **Patching bench**: `tests/bench_patching.py` measures fix safety
  on PoisonPy and SecurityEval. Headline:
  - **38.4%** of detected vulnerabilities receive an auto-fix (paper
    Devaic baseline: 80%, but their patches contained latent
    NameError bugs we explicitly avoid)
  - **100% syntax + 100% regression safety** on all 58 generated
    patches — every auto-fix compiles as valid Python and the rule
    that triggered the fix no longer fires after the patch
- Regression test suite expanded to 14 fixtures + golden files with
  parity tests on every push.
- UTF-8 encoding enforced everywhere — Windows code-page corruption
  fixed.

### Performance
- Per-snippet analysis: ~70-100 ms (was 17-22 s in v0.0.1) — roughly
  **250× faster**.
- Engine startup + 459-rule load: ~85 ms.
- Detection bench on 1,455 files: ~6 s wall-clock.
- Patching bench on PoisonPy + SecurityEval: ~0.5 s.

### Fixed
- 121 detection rules that previously failed to compile due to bash
  POSIX-vs-Python regex incompatibilities now load successfully.
- `REQUESTS-VERIFY-001` pattern (was a typo with two consecutive dots
  that never matched any real `requests.X(verify=False)` call).
- Cross-platform character encoding: rule and fixture files were being
  read with the system code page on Windows, corrupting non-ASCII
  characters in docstrings and producing different scan results than
  on macOS/Linux.

## [0.0.1] - 2026-05-01

### Added
- Initial release of Redlyne
- Vulnerability detection for Python code
- Automated patch suggestions via context menu

### Notes
- Windows + WSL only. Cross-platform support planned for v0.1.0.
