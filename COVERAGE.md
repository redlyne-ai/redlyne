# Coverage

Redlyne ships with **85 deterministic detection rules** covering **35 CWE categories** mapped to the **OWASP Top 10:2021**. Of these:

- **10 CWEs are in MITRE's Top 25 list** of the most dangerous software weaknesses (in any year between 2021 and 2023). They are marked with a ⭐ below.
- **9 of the 10 OWASP categories** are covered. The only one not yet covered is *A06: Vulnerable and Outdated Components*, which we consider out of scope for snippet-level analysis (it requires dependency tree scanning, a separate tool category).

The full mapping below is the complete list of CWEs Redlyne detects today. The detection rules behind these CWEs were derived from analysis of 240 real vulnerable Python samples sourced from [SecurityEval](https://github.com/s2e-lab/SecurityEval) and the [Copilot CWE Scenarios Dataset](https://zenodo.org/records/5225651).

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

## A07: Identification and Authentication Failures

- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation
- [CWE-384](https://cwe.mitre.org/data/definitions/384.html) — Session Fixation

## A08: Software and Data Integrity Failures

- ⭐ [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data

## A09: Security Logging and Monitoring Failures

- [CWE-117](https://cwe.mitre.org/data/definitions/117.html) — Improper Output Neutralization for Logs

## A10: Server-Side Request Forgery (SSRF)

- ⭐ [CWE-918](https://cwe.mitre.org/data/definitions/918.html) — Server-Side Request Forgery (SSRF)

---

## At a glance

| OWASP 2021 category | CWEs covered |
|---|---|
| A01: Broken Access Control | 4 |
| A02: Cryptographic Failures | 9 |
| A03: Injection | 13 |
| A04: Insecure Design | 3 |
| A05: Security Misconfiguration | 1 |
| A07: Identification and Authentication Failures | 2 |
| A08: Software and Data Integrity Failures | 1 |
| A09: Security Logging and Monitoring Failures | 1 |
| A10: Server-Side Request Forgery (SSRF) | 1 |
| **Total** | **35** |

---

## What's not covered (yet)

Honest gap analysis:

- **A06: Vulnerable and Outdated Components** — out of scope for snippet-level analysis. Use a Software Composition Analysis tool (Dependabot, Snyk, OWASP Dependency-Check) for this.
- **CVE-specific patterns** — Redlyne detects vulnerability *classes* (CWE), not specific exploits in named libraries.
- **Logic bugs and authorization flaws** that depend on application context (e.g., a missing permission check in a specific flow) — these need full-application analysis, not snippet-level scanning.

If you find a vulnerability class you'd like Redlyne to cover, please [open an issue](https://github.com/redlyne-ai/redlyne/issues) or contribute a detection rule via pull request.
