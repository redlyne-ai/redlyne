"""
Patching benchmark for the Redlyne engine.

For every vulnerable file in SecurityEval (and optionally Copilot CWE
Scenarios) where at least one rule with a real remediation triggers,
we apply the patch and verify two correctness properties:

  1. SYNTAX — the patched source still compiles as valid Python.
     A patch that produces broken code is unusable, no matter how
     conceptually right the fix is.

  2. REGRESSION — re-running the engine on the patched code must NOT
     re-emit the same OWASP category for that file. If the rule still
     fires, the patch didn't actually neutralize the pattern.

Comment-only rules (where `source == replacement` so no real rewrite
happens) are excluded — they're advisory by design and have nothing
to verify against these properties.

Usage:
    python tests/bench_patching.py
    python tests/bench_patching.py --copilot-sample 3   # also Copilot

Outputs to benchmarks/patching_results/run_<ts>.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "launch_tool"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from redlyne_engine import load_rules, scan, remediate  # noqa: E402
from bench_dataset import (  # noqa: E402
    load_securityeval, load_copilot, load_poisonpy,
    CWE_TO_OWASP,
)

RESULTS_DIR = REPO_ROOT / "benchmarks" / "patching_results"


def assess_patch(entry: dict, rules) -> dict | None:
    """
    Apply patches to a vulnerable entry and assess the result.

    Definition of "real patch" we use here: after running remediate(),
    the patched code is *actually different* from the original. This
    catches both cases at once:
      * Comment-only rules whose source == replacement.
      * Rules whose source/replacement differ as strings but whose
        re.sub() turns out to be a no-op on this particular file
        (e.g. source=`open\\(` replacement=`open(` — same regex result).

    Returns a dict with the per-rule outcome, or None if no patch
    actually altered the source.
    """
    code = entry["code"]
    matches = scan(code, rules)
    if not matches:
        return None

    patched_code, imports = remediate(code, matches, rules)

    # Real-patch test: does the patch actually change the source?
    if patched_code == code and not imports:
        return None

    # Identify which rules are responsible for the visible change.
    # A rule is "responsible" if (a) it fired AND (b) at least one of
    # its remediation rewrites would alter this specific source line.
    # We approximate: any rule whose remediation regex has at least one
    # match in the original code is a candidate. Cheap and good enough.
    import re as _re
    rules_by_id = {r.rule_id: r for r in rules}
    real_match_rule_ids: set[str] = set()
    for m in matches:
        rid = m["rule_id"]
        rule = rules_by_id.get(rid)
        if rule is None or not rule.remediations:
            continue
        for rem in rule.remediations:
            try:
                # Apply remediation (with VAR_PLACEHOLDER substitution if any)
                src_str = rem.source.pattern
                rep_str = rem.replacement
                cap_var = m.get("captured_var")
                if cap_var and "VAR_PLACEHOLDER" in src_str:
                    src_str = src_str.replace("VAR_PLACEHOLDER", _re.escape(cap_var))
                    rep_str = rep_str.replace("VAR_PLACEHOLDER", cap_var)
                trial = _re.sub(src_str, rep_str, code, count=1)
                if trial != code:
                    real_match_rule_ids.add(rid)
                    break
            except _re.error:
                pass

    # If we couldn't pin the change to any specific rule, still treat
    # it as a real patch (e.g. only imports were added).
    if not real_match_rule_ids and patched_code == code and imports:
        # Only imports added — no in-place rewrite. Counts as a (weak)
        # real patch; record it under a synthetic id.
        real_match_rule_ids = {"<imports-only>"}

    # OWASP categories the original code triggered (only those rules
    # we attribute the change to)
    original_cats: set[str] = set()
    for m in matches:
        if m["rule_id"] in real_match_rule_ids:
            original_cats.update(m.get("owasp") or [])

    # 1. SYNTAX check: prepend the new imports + patched code, compile.
    # Important: many benchmark samples (especially PoisonPy) are
    # snippets that don't compile as standalone Python — missing imports
    # at top, informal indentation, partial defs. We must compare against
    # the *original* compile status: a patch is only a "syntax fail" if
    # it makes a previously-valid file invalid.
    try:
        compile(code, "<orig>", "exec")
        original_compiles = True
    except (SyntaxError, ValueError):
        original_compiles = False

    full = "\n".join(imp for imp in imports if imp) + "\n" + patched_code
    try:
        compile(full, "<patched>", "exec")
        patched_compiles = True
        syntax_err = ""
    except (SyntaxError, ValueError) as e:
        patched_compiles = False
        syntax_err = f"{type(e).__name__}: {getattr(e, 'msg', repr(e))}"

    if original_compiles:
        # Strict: original was valid → patch must keep it valid.
        syntax_ok = patched_compiles
    else:
        # Lenient: original already broken → don't blame the patch.
        syntax_ok = True
        if not patched_compiles:
            syntax_err = f"original-already-invalid; {syntax_err}"

    # 2. REGRESSION check: re-scan patched code; the original OWASP
    # categories triggered by real-patch rules must not still fire from
    # those same rules. (We don't care if NEW rules trigger after the
    # patch; we only care about the rules that we tried to fix.)
    rescanned = scan(patched_code, rules)
    still_firing_rules = {
        m["rule_id"] for m in rescanned
        if m["rule_id"] in real_match_rule_ids
    }
    regression_ok = not still_firing_rules

    return {
        "source": entry.get("source", "?"),
        "cwe": entry.get("cwe", entry.get("category", "?")),
        "rules_fired": sorted(real_match_rule_ids),
        "rules_still_firing": sorted(still_firing_rules),
        "imports_added": list(imports),
        "syntax_ok": syntax_ok,
        "syntax_error": syntax_err,
        "regression_ok": regression_ok,
        "patch_clean": syntax_ok and regression_ok,
    }


def bench_paired_dataset(entries: list[dict], rules, label: str) -> dict:
    """
    Patching benchmark on a labeled paired dataset (PoisonPy-style).
    Computes the two key metrics from the patchitpy paper:

      A. Patch rate on detected:
         (vulnerable files that were both detected AND cleanly patched)
         / (vulnerable files that were detected)
         — paper reports 80%

      B. Patch rate on total vulnerable:
         (vulnerable files that were both detected AND cleanly patched)
         / (all vulnerable files in the dataset)
         — paper reports 70%

    Plus the syntax / regression checks on every patch produced.
    Only entries with vulnerable=1 are processed; clean samples are
    used for precision/recall in the detection bench, not here.
    """
    vuln = [e for e in entries if e.get("vulnerable")]
    print(f"\n[{label}] {len(vuln)} vulnerable entries", flush=True)
    t0 = time.perf_counter()

    total = len(vuln)
    detected = 0           # rule fired (any rule)
    patch_attempted = 0    # at least one *real* patch fired (assess_patch != None)
    patch_clean = 0        # patch passed both syntax AND regression
    syntax_fail = 0
    regression_fail = 0

    per_cat = defaultdict(lambda: {
        "total": 0, "detected": 0, "patch_attempted": 0,
        "patch_clean": 0, "syntax_fail": 0, "regression_fail": 0,
    })

    for i, entry in enumerate(vuln):
        cat = entry.get("category", "?")
        per_cat[cat]["total"] += 1

        # Detection step
        matches = scan(entry["code"], rules)
        if matches:
            detected += 1
            per_cat[cat]["detected"] += 1

        # Patching step (only meaningful if detected)
        a = assess_patch(entry, rules)
        if a is None:
            continue
        patch_attempted += 1
        per_cat[cat]["patch_attempted"] += 1
        if not a["syntax_ok"]:
            syntax_fail += 1
            per_cat[cat]["syntax_fail"] += 1
        if not a["regression_ok"]:
            regression_fail += 1
            per_cat[cat]["regression_fail"] += 1
        if a["patch_clean"]:
            patch_clean += 1
            per_cat[cat]["patch_clean"] += 1

        if (i + 1) % 50 == 0:
            print(f"  ...{i+1}/{total}", flush=True)

    elapsed = time.perf_counter() - t0

    # Headline metrics from the patchitpy paper
    rate_A = patch_clean / detected if detected else 0.0
    rate_B = patch_clean / total if total else 0.0

    return {
        "label": label,
        "total_vulnerable": total,
        "detected": detected,
        "patch_attempted": patch_attempted,
        "patch_clean": patch_clean,
        "syntax_fail": syntax_fail,
        "regression_fail": regression_fail,
        "rate_detected_then_patched": round(rate_A, 3),  # paper: 0.80
        "rate_total_detected_and_patched": round(rate_B, 3),  # paper: 0.70
        "elapsed_s": round(elapsed, 2),
        "by_category": {
            cat: {
                **stats,
                "detect_rate": round(stats["detected"] / stats["total"], 3) if stats["total"] else 0.0,
                "rate_detected_then_patched": round(
                    stats["patch_clean"] / stats["detected"], 3) if stats["detected"] else 0.0,
                "rate_total_detected_and_patched": round(
                    stats["patch_clean"] / stats["total"], 3) if stats["total"] else 0.0,
            }
            for cat, stats in per_cat.items()
        },
    }


def bench_patches(entries: list[dict], rules, label: str) -> dict:
    print(f"\n[{label}] {len(entries)} entries", flush=True)
    t0 = time.perf_counter()

    results = []
    skipped_no_patch_fired = 0
    syntax_fail = 0
    regression_fail = 0
    fully_clean = 0
    per_rule = defaultdict(lambda: {"applied": 0, "syntax_fail": 0,
                                    "regression_fail": 0, "clean": 0})

    for i, entry in enumerate(entries):
        a = assess_patch(entry, rules)
        if a is None:
            skipped_no_patch_fired += 1
            continue
        results.append(a)
        if not a["syntax_ok"]:
            syntax_fail += 1
        if not a["regression_ok"]:
            regression_fail += 1
        if a["patch_clean"]:
            fully_clean += 1
        for rid in a["rules_fired"]:
            per_rule[rid]["applied"] += 1
            if not a["syntax_ok"]:
                per_rule[rid]["syntax_fail"] += 1
            if rid in a["rules_still_firing"]:
                per_rule[rid]["regression_fail"] += 1
            elif a["syntax_ok"]:
                per_rule[rid]["clean"] += 1

        if (i + 1) % 100 == 0:
            print(f"  ...{i+1}/{len(entries)}", flush=True)

    elapsed = time.perf_counter() - t0
    n_assessed = len(results)
    return {
        "label": label,
        "entries_total": len(entries),
        "entries_assessed": n_assessed,  # had ≥1 real-patch rule fire
        "entries_skipped_no_real_patch": skipped_no_patch_fired,
        "syntax_fail": syntax_fail,
        "regression_fail": regression_fail,
        "fully_clean": fully_clean,
        "syntax_pass_rate": round(1 - syntax_fail / n_assessed, 3) if n_assessed else None,
        "regression_pass_rate": round(1 - regression_fail / n_assessed, 3) if n_assessed else None,
        "fully_clean_rate": round(fully_clean / n_assessed, 3) if n_assessed else None,
        "elapsed_s": round(elapsed, 2),
        "per_rule": [
            {"rule": rid, **stats}
            for rid, stats in sorted(per_rule.items(), key=lambda kv: -kv[1]["applied"])
        ],
        # Keep top failing examples for inspection (cap output size)
        "syntax_failures": [r for r in results if not r["syntax_ok"]][:10],
        "regression_failures": [r for r in results if not r["regression_ok"]][:10],
    }


def write_reports(payload: dict, ts: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"run_{ts}.json"
    md_path = RESULTS_DIR / f"run_{ts}.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    out = []
    out.append(f"# Redlyne patching benchmark — {ts}")
    out.append("")
    out.append(f"- Engine rules loaded: **{payload['rules_loaded']}**")
    out.append("")
    out.append("Two correctness checks per patch:")
    out.append("  1. **Syntax** — patched code compiles as valid Python.")
    out.append("  2. **Regression** — re-scanning the patched code does not re-emit the same rule.")
    out.append("")

    for s in payload["sections"]:
        out.append(f"## {s['label']}")
        out.append("")
        # Paired-dataset section (PoisonPy-style with category labels)
        if "rate_detected_then_patched" in s:
            out.append(f"- Total vulnerable: **{s['total_vulnerable']}**")
            out.append(f"- Detected: **{s['detected']}** "
                       f"(detection rate {s['detected']/s['total_vulnerable']:.1%})")
            out.append(f"- Patches attempted: **{s['patch_attempted']}**")
            out.append(f"- Patches clean (syntax + regression): **{s['patch_clean']}**")
            out.append(f"  - Syntax failures: {s['syntax_fail']}")
            out.append(f"  - Regression failures: {s['regression_fail']}")
            out.append("")
            out.append("**Headline metrics (paper patchitpy comparison):**")
            out.append(f"- A. Patch rate on detected (`patched / detected`): "
                       f"**{s['rate_detected_then_patched']:.1%}** "
                       f"_(paper: 80%)_")
            out.append(f"- B. Total fix rate (`patched / total vulnerable`): "
                       f"**{s['rate_total_detected_and_patched']:.1%}** "
                       f"_(paper: 70%)_")
            out.append(f"- Time: {s['elapsed_s']}s")
            out.append("")
            out.append("### Per-category breakdown")
            out.append("")
            out.append("| Cat | Total | Detected | Patched clean | A: detect→patch | B: total→fix |")
            out.append("|---|---|---|---|---|---|")
            for cat, stats in sorted(s["by_category"].items()):
                out.append(
                    f"| {cat} | {stats['total']} | {stats['detected']} | "
                    f"{stats['patch_clean']} | "
                    f"{stats['rate_detected_then_patched']:.1%} | "
                    f"{stats['rate_total_detected_and_patched']:.1%} |"
                )
            out.append("")
            continue

        # Original (SecurityEval / Copilot) recall-only patch report
        out.append(f"- Entries with ≥1 real-patch rule firing: **{s['entries_assessed']}** "
                   f"(skipped {s['entries_skipped_no_real_patch']} entries with no real patch)")
        if s["entries_assessed"]:
            out.append(f"- Syntax pass rate:     **{s['syntax_pass_rate']:.1%}**  "
                       f"({s['entries_assessed'] - s['syntax_fail']}/{s['entries_assessed']})")
            out.append(f"- Regression pass rate: **{s['regression_pass_rate']:.1%}**  "
                       f"({s['entries_assessed'] - s['regression_fail']}/{s['entries_assessed']})")
            out.append(f"- Fully clean (both):   **{s['fully_clean_rate']:.1%}**  "
                       f"({s['fully_clean']}/{s['entries_assessed']})")
        out.append(f"- Time: {s['elapsed_s']}s")
        out.append("")
        if s["per_rule"]:
            out.append("### Per-rule breakdown")
            out.append("")
            out.append("| Rule | Applied | Syntax fail | Regression fail | Clean |")
            out.append("|---|---|---|---|---|")
            for r in s["per_rule"]:
                out.append(f"| `{r['rule']}` | {r['applied']} | "
                           f"{r['syntax_fail']} | {r['regression_fail']} | {r['clean']} |")
            out.append("")
        if s["syntax_failures"]:
            out.append("### Syntax failure examples")
            out.append("")
            for r in s["syntax_failures"][:5]:
                out.append(f"- `{r['source']}` ({r['cwe']}): {r['syntax_error']} "
                           f"— rules: {', '.join(r['rules_fired'])}")
            out.append("")
        if s["regression_failures"]:
            out.append("### Regression failure examples (rule still fires after patch)")
            out.append("")
            for r in s["regression_failures"][:5]:
                out.append(f"- `{r['source']}` ({r['cwe']}): rules still firing: "
                           f"{', '.join(r['rules_still_firing'])}")
            out.append("")

    md_path.write_text("\n".join(out), encoding="utf-8")
    return json_path, md_path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--copilot-sample", type=int, default=0,
                   help="Also include Copilot CWE Scenarios, ≤N files per scenario "
                        "(default 0 = SecurityEval only)")
    p.add_argument("--no-poisonpy", action="store_true",
                   help="Skip the PoisonPy paired bench (paper-comparison metrics)")
    args = p.parse_args()

    print("Loading rules...", flush=True)
    rules, errors = load_rules(verbose=False)
    print(f"  loaded {len(rules)} rules, {len(errors)} errors")

    sections = []
    se = load_securityeval()
    if se:
        sections.append(bench_patches(se, rules, "SecurityEval (insecure-code only)"))

    if args.copilot_sample > 0:
        co = load_copilot(sample_per_scenario=args.copilot_sample)
        if co:
            sections.append(bench_patches(
                co, rules, f"Copilot CWE Scenarios (sampled ≤{args.copilot_sample}/scenario)"
            ))

    if not args.no_poisonpy:
        pp = load_poisonpy()
        if pp:
            sections.append(bench_paired_dataset(
                pp, rules,
                "PoisonPy (paper-comparison: paired vulnerable/clean, Cotroneo et al.)"
            ))

    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "rules_loaded": len(rules),
        "sections": sections,
    }
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path, md_path = write_reports(payload, ts)
    print()
    print(f"Wrote {json_path.relative_to(REPO_ROOT)}")
    print(f"Wrote {md_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
