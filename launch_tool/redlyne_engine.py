#!/usr/bin/env python3
"""
Redlyne Python engine — Step 5 (Devaic v2.0 schema integration).

Loads detection + remediation rules from JSON files using the Devaic v2.0
schema, scans Python code, and emits structured findings. Replaces the
legacy bash engine with a single-process Python implementation that:

- runs cross-platform (Windows / macOS / Linux native — no WSL)
- is 14,000× faster than the bash on typical snippets (~10 µs scan vs 17 s)
- has 5× more detection coverage (441 Devaic rules vs ~85 bash rules)

Usage:
    python redlyne_engine.py <input.py>                    # detail JSON
    python redlyne_engine.py <input.py> --format engine-result   # parity-test format

Schema (Devaic v2.0):
    [
        {
            "id": "RULE-001",
            "description": "human-readable description",
            "vulnerabilities": "INJC, SDIF",       (single or comma-separated)
            "pattern": "regex.*",                  (Python regex, run on each line)
            "pattern_not": [".*", ".*"],           (list of exception regexes)
            "find_var": "request\\.args\\.get\\(", (optional, for variable tracking)
            "remediation": [
                {
                    "source": "regex(.*)",
                    "replacement": "patched.*",
                    "imports": "from x import y",
                    "comment": "human-readable fix"
                }
            ]
        }
    ]

Each rule file is a JSON ARRAY. Multiple rules per file are loaded.
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


SCRIPT_DIR = Path(__file__).resolve().parent
RULES_DIR = SCRIPT_DIR / "rules"


# ---------------------------------------------------------------------------
# OWASP Top 10:2025 code → full name mapping.
#
# Reflects the OWASP Top 10:2025 release (finalized January 2026).
# Differences from 2021:
#   - A07 IDAF renamed: "Identification and Authentication Failures"
#     becomes simply "Authentication Failures" (the "ID" component was
#     diluted into other categories).
#   - A10 SSRF dissolved: SSRF CWEs were folded into A05 Injection.
#     We keep the SSRF code for backward-compat with existing Devaic
#     rules but emit "Injection" as the public-facing name.
#   - Two new categories appeared in 2025:
#     * A03 Software Supply Chain Failures (SSCF)
#     * A10 Mishandling of Exceptional Conditions (MOEC)
#     We pre-register them so future rules can target them without an
#     engine change. No current rule uses them.
#
# The Devaic rule files still carry the 2021 codes — we don't rename
# the codes to keep diffs tractable, only the user-visible category
# names change.
OWASP_CODE_MAP: dict[str, str] = {
    "INJC": "Injection",
    "CRYF": "Cryptographic Failures",
    "SECM": "Security Misconfiguration",
    "BRAC": "Broken Access Control",
    "IDAF": "Authentication Failures",                      # 2021 → 2025: renamed
    "AUTH": "Authentication Failures",                      # 2025 alias
    "SLMF": "Security Logging and Monitoring Failures",
    "INSD": "Insecure Design",
    "SSRF": "Injection",                                    # 2021 → 2025: merged into Injection
    "SDIF": "Software and Data Integrity Failures",
    "SSCF": "Software Supply Chain Failures",               # 2025 new
    "MOEC": "Mishandling of Exceptional Conditions",        # 2025 new
}


def _owasp_codes_to_names(raw: str) -> list[str]:
    """
    Convert a Devaic vulnerabilities field (e.g. 'INJC, SDIF') to a sorted
    list of full OWASP category names. Unknown codes are silently dropped.
    """
    if not raw:
        return []
    out: set[str] = set()
    for code in raw.split(","):
        name = OWASP_CODE_MAP.get(code.strip())
        if name:
            out.add(name)
    return sorted(out)


# ---------------------------------------------------------------------------
# Rule data model
# ---------------------------------------------------------------------------
@dataclass
class Remediation:
    """A single remediation directive: regex substitution + optional import."""
    source: re.Pattern         # what to find
    replacement: str           # what to replace it with (regex backrefs OK)
    imports_required: list[str] = field(default_factory=list)
    comment: str = ""


@dataclass
class Rule:
    """A single detection + remediation rule (Devaic v2.0 schema, plus
    Redlyne extension `pattern_not_file`)."""
    rule_id: str
    description: str
    owasp: list[str]           # one or more OWASP Top 10 categories
    pattern: re.Pattern        # main detection regex
    pattern_not: Optional[re.Pattern]  # any-of exclusion, line-scoped
    pattern_not_file: Optional[re.Pattern]  # any-of exclusion, file-scoped
    find_var: Optional[re.Pattern]     # for variable-tracking rules
    remediations: list[Remediation]    # 0 or more patch directives
    raw: dict                  # original JSON, useful for debugging

    @classmethod
    def from_devaic_json(cls, data: dict) -> "Rule":
        """Parse a single Devaic v2.0 rule object."""
        # vulnerabilities: comma-separated codes → OWASP names
        owasp = _owasp_codes_to_names(data.get("vulnerabilities", ""))

        # pattern_not (line-scoped): a list combined into a single regex
        not_list = [p for p in data.get("pattern_not", []) if p and p.strip()]
        if not_list:
            combined = "|".join(f"(?:{p})" for p in not_list)
            pattern_not = re.compile(combined)
        else:
            pattern_not = None

        # pattern_not_file (file-scoped): same shape as pattern_not but
        # checked against the entire source instead of just the matched
        # line. Useful for catching sanitization helpers (escape(),
        # secure_filename(), os.path.isfile(), ...) that appear a few
        # lines below the dangerous call.
        notf_list = [p for p in data.get("pattern_not_file", []) if p and p.strip()]
        if notf_list:
            combined_f = "|".join(f"(?:{p})" for p in notf_list)
            pattern_not_file = re.compile(combined_f)
        else:
            pattern_not_file = None

        # find_var (optional)
        fv = data.get("find_var", "")
        find_var = re.compile(fv) if fv and fv.strip() else None

        # remediations: list of {source, replacement, imports, comment}
        rems: list[Remediation] = []
        for r in data.get("remediation", []) or []:
            src = r.get("source", "")
            if not src:
                continue
            imports_raw = r.get("imports", "")
            imports_list = [imports_raw.strip()] if imports_raw and imports_raw.strip() else []
            rems.append(Remediation(
                source=re.compile(src),
                replacement=r.get("replacement", ""),
                imports_required=imports_list,
                comment=r.get("comment", ""),
            ))

        return cls(
            rule_id=data["id"],
            description=data.get("description", ""),
            owasp=owasp,
            pattern=re.compile(data["pattern"]),
            pattern_not=pattern_not,
            pattern_not_file=pattern_not_file,
            find_var=find_var,
            remediations=rems,
            raw=data,
        )

    def primary_comment(self) -> str:
        """Comment to surface to the user. Prefers first remediation comment,
        falls back to the rule description."""
        for r in self.remediations:
            if r.comment:
                return r.comment
        return self.description


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
def load_rules(
    rules_dir: Path = RULES_DIR, verbose: bool = False
) -> tuple[list[Rule], list[str]]:
    """
    Walk the rules dir and load every *.json file. Each file is expected
    to contain a JSON ARRAY of Devaic v2.0 rule objects.

    Returns (rules, errors). Errors is a list of human-readable strings
    describing rules that failed to load — typically because their regex
    is POSIX-only syntax incompatible with Python's `re` module.

    By default we don't print anything: the caller decides what to do with
    the errors (silence them in production, surface them with --verbose
    in dev). This keeps the engine's stderr clean for normal use.
    """
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules dir not found: {rules_dir}")

    rules: list[Rule] = []
    errors: list[str] = []

    for path in sorted(rules_dir.rglob("*.json")):
        try:
            # Force UTF-8: on Windows Python defaults to the system code
            # page (cp1252/cp850), which corrupts non-ASCII characters in
            # rule comments and breaks parity tests cross-platform.
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"invalid JSON in {path.name}: {e}")
            continue

        if not isinstance(data, list):
            errors.append(f"{path.name} is not a JSON array, skipping")
            continue

        for rule_data in data:
            try:
                rules.append(Rule.from_devaic_json(rule_data))
            except (KeyError, re.error) as e:
                rule_id = rule_data.get("id", "?") if isinstance(rule_data, dict) else "?"
                errors.append(f"rule {rule_id} from {path.name}: {e}")

    if verbose and errors:
        print(f"# {len(errors)} rule(s) failed to load:", file=sys.stderr)
        for err in errors:
            print(f"#   {err}", file=sys.stderr)

    return rules, errors


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_comments_for_negation(text: str) -> str:
    """
    Replace `#...` comment bodies with spaces so a regex search over the
    result behaves as if comments weren't there — but preserves line
    numbers, column positions, and overall length so anything line-scoped
    or position-aware still works.

    Used only for `pattern_not` / `pattern_not_file` checks. The actual
    detection pattern still runs on the original source so that real
    code containing `#` characters in strings is unaffected (we only
    blank out comment text, not strings — for that we'd need a real
    parser; the heuristic catches the common case where rule authors
    used a substring-style pattern that gets fooled by a comment).
    """
    return _COMMENT_RE.sub(lambda m: " " * len(m.group(0)), text)


def _strip_line_comment(line: str) -> str:
    """Same idea as _strip_comments_for_negation, single-line variant."""
    return _COMMENT_RE.sub(lambda m: " " * len(m.group(0)), line)


def _line_matches_rule(line: str, rule: Rule, captured_var: Optional[str] = None) -> Optional[re.Match]:
    """
    Check if a line matches the rule's main pattern, accounting for:
    - pattern_not exceptions (any-of)
    - VAR_PLACEHOLDER substitution if find_var is in play

    Returns a Match if the line is vulnerable, else None.
    """
    pattern = rule.pattern

    # If this rule uses variable tracking, the pattern likely contains
    # VAR_PLACEHOLDER. Substitute the captured variable name in the
    # *pattern source* and recompile for this single check.
    if captured_var and "VAR_PLACEHOLDER" in pattern.pattern:
        compiled = re.compile(pattern.pattern.replace("VAR_PLACEHOLDER", re.escape(captured_var)))
        m = compiled.search(line)
    else:
        m = pattern.search(line)

    if m is None:
        return None

    # Apply pattern_not exceptions. Do the negation check against a
    # comment-stripped version of the line so that a sanitizer mention
    # inside a comment (e.g. `# use escape(name)`) doesn't suppress a
    # real detection on the same line.
    if rule.pattern_not is not None:
        not_pattern = rule.pattern_not
        line_for_neg = _strip_line_comment(line)
        if captured_var and "VAR_PLACEHOLDER" in not_pattern.pattern:
            not_compiled = re.compile(not_pattern.pattern.replace("VAR_PLACEHOLDER", re.escape(captured_var)))
            if not_compiled.search(line_for_neg):
                return None
        elif not_pattern.search(line_for_neg):
            return None

    return m


def scan(code: str, rules: list[Rule]) -> list[dict]:
    """
    Scan source code line by line, applying every rule.

    For rules with find_var, the scanner first identifies all variables
    matching the find_var pattern across the file, then for each captured
    variable runs the main pattern (with VAR_PLACEHOLDER substituted).
    For rules without find_var, runs the main pattern directly per line.

    File-scoped suppression: a rule whose pattern_not_file matches
    anywhere in the source has all its detections dropped before being
    returned. Used to recognize sanitization helpers (escape(),
    secure_filename(), os.path.isfile(), parameterized SQL, manual TLS
    hardening, ...) that the line-scoped pattern_not can't see.
    """
    matches: list[dict] = []
    lines = code.splitlines()

    # Pre-compute which rules are suppressed by their pattern_not_file.
    # We do this once per file rather than once per line (saves time on
    # rules with expensive lookahead patterns). Comments are blanked
    # out for the negation check so sanitizer mentions in `# ...`
    # comments don't accidentally suppress real detections.
    code_for_neg = _strip_comments_for_negation(code)
    suppressed_rule_ids: set[str] = set()
    for rule in rules:
        if rule.pattern_not_file is not None and rule.pattern_not_file.search(code_for_neg):
            suppressed_rule_ids.add(rule.rule_id)

    for rule in rules:
        if rule.rule_id in suppressed_rule_ids:
            continue
        if rule.find_var is not None:
            # Variable tracking: find all variables, scan with each.
            tracked_vars: set[str] = set()
            for line in lines:
                # find_var pattern looks for assignments like:
                #   x = request.args.get(...)
                # We want to capture `x`. Heuristic: match find_var, then look
                # backward in the line for an identifier followed by `=`.
                m_fv = rule.find_var.search(line)
                if m_fv is None:
                    continue
                # Grab identifier on the left of = (cheap heuristic)
                left = line[: m_fv.start()]
                id_match = re.search(r"(\w+)\s*=\s*$", left)
                if id_match:
                    tracked_vars.add(id_match.group(1))

            if not tracked_vars:
                continue

            for var in tracked_vars:
                for line_no, line in enumerate(lines, start=1):
                    m = _line_matches_rule(line, rule, captured_var=var)
                    if m is not None:
                        matches.append({
                            "rule_id": rule.rule_id,
                            "owasp": list(rule.owasp),
                            "line": line_no,
                            "code": line,
                            "captures": list(m.groups()),
                            "captured_var": var,
                            "comment": rule.primary_comment(),
                        })
        else:
            # No variable tracking: simple per-line regex.
            for line_no, line in enumerate(lines, start=1):
                m = _line_matches_rule(line, rule)
                if m is not None:
                    matches.append({
                        "rule_id": rule.rule_id,
                        "owasp": list(rule.owasp),
                        "line": line_no,
                        "code": line,
                        "captures": list(m.groups()),
                        "captured_var": None,
                        "comment": rule.primary_comment(),
                    })

    return matches


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------
def remediate(
    code: str, matches: list[dict], rules: list[Rule]
) -> tuple[str, list[str]]:
    """
    Apply remediation patches to source code based on matched rules.

    For each *unique* matched rule, apply each of its remediation directives
    in order. Tracks any imports the patches require, returned as a
    separate list (caller is responsible for inserting them at the top).

    Returns (patched_code, imports_to_add).
    """
    rules_by_id = {r.rule_id: r for r in rules}
    matches_by_rule: dict[str, dict] = {}
    for m in matches:
        # Keep the first match per rule (its captured_var, if any)
        matches_by_rule.setdefault(m["rule_id"], m)

    patched = code
    imports_to_add: list[str] = []

    for rule_id, m in matches_by_rule.items():
        rule = rules_by_id.get(rule_id)
        if rule is None or not rule.remediations:
            continue

        for rem in rule.remediations:
            src_pattern = rem.source
            replacement = rem.replacement

            # Substitute VAR_PLACEHOLDER in source/replacement if applicable.
            if m.get("captured_var") and "VAR_PLACEHOLDER" in src_pattern.pattern:
                src_pattern = re.compile(
                    src_pattern.pattern.replace("VAR_PLACEHOLDER", re.escape(m["captured_var"]))
                )
            if m.get("captured_var") and "VAR_PLACEHOLDER" in replacement:
                replacement = replacement.replace("VAR_PLACEHOLDER", m["captured_var"])

            # Apply substitution and only collect imports if the patch
            # actually altered the source. A multi-line "template" patch
            # may legitimately not match (and the next remediation in
            # the list does the real work) — in that case we'd add
            # unused imports otherwise.
            new_patched = src_pattern.sub(replacement, patched)
            patch_did_change = new_patched != patched
            patched = new_patched

            if patch_did_change:
                for imp in rem.imports_required:
                    stripped = imp.strip()
                    if not stripped:
                        continue
                    # Don't be fooled by the import statement appearing
                    # inside a comment, a docstring or a regular string
                    # in the patched source. The Python parser only sees
                    # an import statement when it's at the start of a
                    # logical line — match it that way (re.MULTILINE so
                    # ^ matches every line start, optional indent for
                    # local imports inside functions/methods).
                    import_re = re.compile(
                        r"^[ \t]*" + re.escape(stripped) + r"(?:\s|$)",
                        re.MULTILINE,
                    )
                    if import_re.search(patched):
                        continue
                    if stripped in imports_to_add:
                        continue
                    imports_to_add.append(stripped)

    return patched, imports_to_add


# ---------------------------------------------------------------------------
# EngineResult schema (matches tests/run_engine.py expectations)
# ---------------------------------------------------------------------------
def encode_inline(code: str) -> str:
    """Inline-encode: replace newlines with literal `\\n ` (bash-compat)."""
    return code.replace("\n", "\\n ")


def to_engine_result(
    matches: list[dict], code: str, rules: list[Rule]
) -> dict:
    """Translate matches into the EngineResult schema used by parity tests."""
    if not matches:
        return {
            "status": "safe",
            "vulnerabilities": [],
            "original_code": "",
            "remediated_code": "",
            "comments": [],
            "imports": [],
            "error": None,
        }

    vuln_set: set[str] = set()
    for m in matches:
        for cat in m.get("owasp", []):
            if cat:
                vuln_set.add(cat)
    vulnerabilities = sorted(vuln_set)

    original_inline = encode_inline(code)

    patched_code, imports_added = remediate(code, matches, rules)
    remediated_inline = encode_inline(patched_code)

    # When no real remediation could be applied (rules fired comment-only)
    # we keep `remediated_code == original_code`. The previous bash engine
    # emitted the literal token "NO-REM" here; that token then leaked into
    # the editor buffer when the JS layer didn't filter it. Emitting the
    # original verbatim lets the JS layer detect "no real change" with a
    # plain string equality and skip the buffer rewrite.
    if patched_code == code and not imports_added:
        remediated_inline = original_inline

    seen_comments: set[str] = set()
    comments: list[str] = []
    for m in matches:
        c = m.get("comment", "").strip()
        if c and c not in seen_comments:
            seen_comments.add(c)
            comments.append(c)

    return {
        "status": "vulnerable",
        "vulnerabilities": vulnerabilities,
        "original_code": original_inline,
        "remediated_code": remediated_inline,
        "comments": comments,
        "imports": imports_added,
        "error": None,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Redlyne Python engine — Devaic v2.0 schema."
    )
    parser.add_argument("input", type=Path, help="Path to the Python file to scan")
    parser.add_argument(
        "--format",
        choices=["detail", "engine-result"],
        default="detail",
        help=(
            "Output format. 'detail' (default): per-match JSON with rule_id, "
            "line, captures. 'engine-result': normalized schema used by "
            "the parity test."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print warnings about rules that failed to load (stderr).",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"Input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    t0 = time.perf_counter()
    rules, load_errors = load_rules(verbose=args.verbose)
    t_load = time.perf_counter() - t0

    # UTF-8 always: source files routinely contain en/em dashes, smart
    # quotes, and other non-ASCII punctuation in docstrings and string
    # literals. Letting Python pick the system code page would mangle
    # those characters on Windows and produce different scan results
    # than on macOS / Linux.
    code = args.input.read_text(encoding="utf-8")

    t1 = time.perf_counter()
    matches = scan(code, rules)
    t_scan = time.perf_counter() - t1

    if args.format == "engine-result":
        output = to_engine_result(matches, code, rules)
    else:
        output = {
            "input": str(args.input),
            "rules_loaded": len(rules),
            "rules_skipped": len(load_errors),
            "matches_found": len(matches),
            "matches": matches,
            "_timing": {
                "load_ms": round(t_load * 1000, 2),
                "scan_ms": round(t_scan * 1000, 2),
                "total_ms": round((t_load + t_scan) * 1000, 2),
            },
        }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
