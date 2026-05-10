# Redlyne patching benchmark — 20260510_184208

- Engine rules loaded: **459**

Two correctness checks per patch:
  1. **Syntax** — patched code compiles as valid Python.
  2. **Regression** — re-scanning the patched code does not re-emit the same rule.

## SecurityEval (insecure-code only)

- Entries with ≥1 real-patch rule firing: **31** (skipped 90 entries with no real patch)
- Syntax pass rate:     **100.0%**  (31/31)
- Regression pass rate: **100.0%**  (31/31)
- Fully clean (both):   **100.0%**  (31/31)
- Time: 0.58s

### Per-rule breakdown

| Rule | Applied | Syntax fail | Regression fail | Clean |
|---|---|---|---|---|
| `PICKLE-FAILURE-001` | 3 | 0 | 0 | 3 |
| `REDIRECT-VAR-CONCAT-001` | 3 | 0 | 0 | 3 |
| `YAML-LOAD-001` | 2 | 0 | 0 | 2 |
| `LDAP-FORMAT-INJECTION-001` | 2 | 0 | 0 | 2 |
| `MD5-001` | 2 | 0 | 0 | 2 |
| `RANDOM-001` | 2 | 0 | 0 | 2 |
| `MAKE-RESPONSE-IDENT-001` | 1 | 0 | 0 | 1 |
| `OS-REMOVE-USER-INPUT-001` | 1 | 0 | 0 | 1 |
| `OPEN-USER-VAR-001` | 1 | 0 | 0 | 1 |
| `OS-SYSTEM-VAR-001` | 1 | 0 | 0 | 1 |
| `TEMPLATE-RENDER-USER-INPUT-001` | 1 | 0 | 0 | 1 |
| `MAKE-RESPONSE-CONCAT-001` | 1 | 0 | 0 | 1 |
| `MAKE-RESPONSE-HTML-CONCAT-001` | 1 | 0 | 0 | 1 |
| `SQL-PERCENT-FORMAT-001` | 1 | 0 | 0 | 1 |
| `EVAL-001` | 1 | 0 | 0 | 1 |
| `DEBUG-TRUE-001` | 1 | 0 | 0 | 1 |
| `CHECK-HOSTNAME-001` | 1 | 0 | 0 | 1 |
| `REQUESTS-005` | 1 | 0 | 0 | 1 |
| `REQUESTS-VERIFY-001` | 1 | 0 | 0 | 1 |
| `DSA-001` | 1 | 0 | 0 | 1 |
| `RANDOM-CHOICE-001` | 1 | 0 | 0 | 1 |
| `JWT-DECODE-001` | 1 | 0 | 0 | 1 |
| `XML-SAX-MAKE-PARSER-001` | 1 | 0 | 0 | 1 |
| `PBKDF2-HMAC-001` | 1 | 0 | 0 | 1 |

## PoisonPy (paper-comparison: paired vulnerable/clean, Cotroneo et al.)

- Total vulnerable: **155**
- Detected: **150** (detection rate 96.8%)
- Patches attempted: **58**
- Patches clean (syntax + regression): **58**
  - Syntax failures: 0
  - Regression failures: 0

**Headline metrics (paper patchitpy comparison):**
- A. Patch rate on detected (`patched / detected`): **38.7%** _(paper: 80%)_
- B. Total fix rate (`patched / total vulnerable`): **37.4%** _(paper: 70%)_
- Time: 0.39s

### Per-category breakdown

| Cat | Total | Detected | Patched clean | A: detect→patch | B: total→fix |
|---|---|---|---|---|---|
| DPI | 40 | 39 | 16 | 41.0% | 40.0% |
| ICI | 40 | 39 | 14 | 35.9% | 35.0% |
| TPI | 75 | 72 | 28 | 38.9% | 37.3% |
