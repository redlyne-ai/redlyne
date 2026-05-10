# Coverage

Redlyne ships with **459 deterministic detection rules** mapped to the **OWASP Top 10:2025**, of which **71 carry auto-remediation** (regex sub or multi-line template) verified to be syntax + regression safe.

Measured detection performance on the two reference benchmarks (1,145 known-vulnerable Python files):

| Benchmark | Files | Recall |
|---|---|---|
| [SecurityEval](https://github.com/s2e-lab/SecurityEval) (hand-curated) | 121 | **47.1%** |
| [Copilot CWE Scenarios](https://zenodo.org/records/5225651) (Pearce et al.) | 1,024 | **61.6%** |
| **Combined** | **1,145** | **60.0%** |

Full per-CWE recall breakdown lives in [`benchmarks/dataset_results/baseline_v0.1.0.md`](benchmarks/dataset_results/baseline_v0.1.0.md). Reproduce the numbers locally with `python tests/bench_dataset.py`.

The CWE list below is the complete set Redlyne detects today, organized by OWASP Top 10:2025 category.

---

## A01: Broken Access Control

- ⭐ [CWE-022](https://cwe.mitre.org/data/definitions/22.html) — Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- [CWE-377](https://cwe.mitre.org/data/definitions/377.html) — Insecure Temporary File
- [CWE-425](https://cwe.mitre.org/data/definitions/425.html) — Direct Request ('Forced Browsing')
- [CWE-601](https://cwe.mitre.org/data/definitions/601.html) — URL Redirection to Untrusted Site (Open Redirect)

## A02: Cryptographic Failures

- [CWE-319](https://cwe.mitre.org/data/definitions/319.html) — Cleartext Transmission of Sensitive Information
- [CWE-321](https://cwe.mitre.org/data/definitions/321.html) — Use of Hard-coded Cryptographic Key
- [CWE-326](https://cwe.mitre.org/data/definitions/326.html) — Inadequate Encryption Strength
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Use of a Broken or Risky Cryptographic Algorithm
- [CWE-329](https://cwe.mitre.org/data/definitions/329.html) — Generation of Predictable IV with CBC Mode
- [CWE-330](https://cwe.mitre.org/data/definitions/330.html) — Use of Insufficiently Random Values
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html) — Improper Verification of Cryptographic Signature
- [CWE-759](https://cwe.mitre.org/data/definitions/759.html) — Use of a One-Way Hash without a Salt
- [CWE-760](https://cwe.mitre.org/data/definitions/760.html) — Use of a One-Way Hash with a Predictable Salt

## A03: Injection

- ⭐ [CWE-020](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation
- ⭐ [CWE-078](https://cwe.mitre.org/data/definitions/78.html) — OS Command Injection
- ⭐ [CWE-079](https://cwe.mitre.org/data/definitions/79.html) — Cross-site Scripting (XSS)
- [CWE-080](https://cwe.mitre.org/data/definitions/80.html) — Basic XSS (Improper Neutralization of Script-Related HTML Tags)
- [CWE-090](https://cwe.mitre.org/data/definitions/90.html) — LDAP Injection
- ⭐ [CWE-094](https://cwe.mitre.org/data/definitions/94.html) — Code Injection
- [CWE-095](https://cwe.mitre.org/data/definitions/95.html) — Eval Injection (Dynamically Evaluated Code)
- [CWE-096](https://cwe.mitre.org/data/definitions/96.html) — Static Code Injection
- [CWE-099](https://cwe.mitre.org/data/definitions/99.html) — Resource Injection
- [CWE-113](https://cwe.mitre.org/data/definitions/113.html) — HTTP Request/Response Splitting
- [CWE-116](https://cwe.mitre.org/data/definitions/116.html) — Improper Encoding or Escaping of Output
- [CWE-643](https://cwe.mitre.org/data/definitions/643.html) — XPath Injection
- [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) — CSV / Formula Injection

## A04: Insecure Design

- [CWE-209](https://cwe.mitre.org/data/definitions/209.html) — Generation of Error Message Containing Sensitive Information
- ⭐ [CWE-269](https://cwe.mitre.org/data/definitions/269.html) — Improper Privilege Management
- ⭐ [CWE-434](https://cwe.mitre.org/data/definitions/434.html) — Unrestricted Upload of File with Dangerous Type

## A05: Security Misconfiguration

- ⭐ [CWE-611](https://cwe.mitre.org/data/definitions/611.html) — Improper Restriction of XML External Entity Reference (XXE)

## A07: Authentication Failures

- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation
- [CWE-297](https://cwe.mitre.org/data/definitions/297.html) — Improper Validation of Certificate with Host Mismatch
- [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function
- [CWE-321](https://cwe.mitre.org/data/definitions/321.html) — Use of Hard-coded Cryptographic Key
- [CWE-522](https://cwe.mitre.org/data/definitions/522.html) — Insufficiently Protected Credentials (password hashed with fast hash)
- ⭐ [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Use of Hard-coded Credentials

## A08: Software and Data Integrity Failures

- ⭐ [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data (yaml, pickle, jsonpickle, marshal)

## A09: Security Logging and Monitoring Failures

- [CWE-117](https://cwe.mitre.org/data/definitions/117.html) — Improper Output Neutralization for Logs
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html) — Generation of Error Message Containing Sensitive Information

> **Note on SSRF**: in OWASP Top 10:2025 the standalone SSRF category (A10:2021) was merged into Injection. CWE-918 detections still fire — they now surface under "Injection" rather than a dedicated SSRF tag.

---

## At a glance

| OWASP 2025 category | Recall on benchmarks |
|---|---|
| A01: Broken Access Control | strong on CWE-732 (100%), CWE-022 (~70%) |
| A02: Cryptographic Failures | very strong (CWE-327/295/297/319 all ≥90%) |
| A03: Software Supply Chain Failures | not covered yet (out of scope for snippet-level) |
| A04: Cryptographic Failures (was A02) | see A02 |
| A05: Injection | strong on CWE-089 SQL (81%), gaps on CWE-079 XSS (24%), CWE-078 cmd (17%) |
| A06: Insecure Design | partial coverage |
| A07: Authentication Failures | very strong on CWE-295/798, partial on CWE-522 (30%) |
| A08: Software and Data Integrity Failures | strong on CWE-502 (50-100% depending on dataset) |
| A09: Security Logging and Monitoring Failures | partial |
| A10: Mishandling of Exceptional Conditions | not covered yet (new category in 2025) |

---

## What's not covered (yet)

Honest gap analysis:

- **A03: Software Supply Chain Failures** — out of scope for snippet-level analysis. Use a Software Composition Analysis tool (Dependabot, Snyk, OWASP Dependency-Check) for dependency-level supply chain risks.
- **A10: Mishandling of Exceptional Conditions** — new in OWASP 2025; we're studying which CWEs (CWE-703, CWE-754, CWE-755) are tractable as regex rules.
- **CVE-specific patterns** — Redlyne detects vulnerability *classes* (CWE), not specific exploits in named libraries.
- **Logic bugs and authorization flaws** that depend on application context (e.g., a missing permission check in a specific flow) — these need full-application analysis, not snippet-level scanning.

If you find a vulnerability class you'd like Redlyne to cover, please [open an issue](https://github.com/redlyne-ai/redlyne/issues) or contribute a detection rule via pull request.
