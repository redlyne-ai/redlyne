"""
Head-to-head remediation benchmark.

Auto-remediation is what makes Redlyne different from most static
analyzers. The three open-source Python-security tools we compare:

  - Redlyne v0.1.2 — DeVAIC v2 engine + 71 remediation rules + 14
    multi-line template rules + verified safety pipeline.
  - PatchitPy — the original DeVAIC v1 + remediation bash pipeline.
    Same lineage as Redlyne (both extend DeVAIC with patch generation),
    making it the apples-to-apples scientific baseline.
  - Semgrep --autofix — the industrial baseline. Limited to rules
    carrying a `fix:` block (historically ~5% of the registry).

DeVAIC v2 stock is intentionally NOT in the default remediation
comparison: the upstream rule set ships only 2 remediation blocks out
of 441 rules (0.5%), so DeVAIC v2 doesn't function as a remediation
tool. It remains a peer in the detection benchmark
(`tests/bench_baselines.py`), where it ranks against the same tools on
precision/recall/F1. Use `--tools redlyne,devaic_v2,...` to include it
explicitly here — useful to demonstrate the detection-only gap.

Datasets:
  - PoisonPy (Cotroneo et al., ICPC 2024) — 155 paired vuln+clean.
  - SafeCoder (He et al., ICML 2024) — ~526 real commit-based fixes.

Per-patch evaluation (five properties):

  1. Applied         — did the tool change the source?
  2. Syntax-safe     — does the patched source still compile?
  3. Targeted-clean  — do the SPECIFIC rule IDs that fired pre-patch
                       (and that ship a remediation block) stop firing?
                       This is the honest "did the fix work?" metric.
                       Detection-only rules (taint sources, etc.) that
                       lack remediation are excluded — the engine never
                       promised to fix those.
  4. Regression-free — no NEW rule IDs appear in the patched source.
  5. Cross-clean     — strictest: post-patch source has zero findings
                       overall. Penalizes single-fix tools on multi-vuln
                       samples.

Two reported "fully clean" flavors:

  - targeted_full = syntax_safe AND regression_free AND targeted_clean
    → headline metric, "did the patch fix what it targeted?"
  - strict_full  = syntax_safe AND regression_free AND cross_clean
    → strict stress test.

Optionally we report ground-truth similarity (normalized Levenshtein)
vs PoisonPy's `code_clean` or SafeCoder's commit `func_src_after`.
Informative, not authoritative — different idiomatic fixes can be
equally correct.

Usage:
    python tests/bench_remediation.py
    python tests/bench_remediation.py --no-patchitpy      # skip ~40 min bash run
    python tests/bench_remediation.py --datasets poisonpy  # one dataset only
    python tests/bench_remediation.py --tools redlyne,devaic_v2,patchitpy,semgrep
"""
from __future__ import annotations

import argparse
import json
import os
import re as _re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "launch_tool"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from redlyne_engine import load_rules, scan, remediate  # noqa: E402
from bench_dataset import load_poisonpy, load_safecoder  # noqa: E402

RESULTS_DIR = REPO_ROOT / "benchmarks" / "remediation_results"
DEVAIC_V2_RULES = REPO_ROOT / "baselines" / "DeVAIC-main" / "version_2.0" / "ruleset"
PATCHITPY_DIR = REPO_ROOT / "baselines" / "PatchitPy-main" / "extension_PatchitPy" / "launch_tool"
PATCHITPY_STARTER = PATCHITPY_DIR / "patchitpy_starter.sh"


# ---------------------------------------------------------------------------
# Per-tool patch generators. Each returns the patched source string or None
# if the tool did not produce a fix (or failed).
# ---------------------------------------------------------------------------
def patch_redlyne(code: str, rules) -> str | None:
    matches = scan(code, rules)
    if not matches:
        return None
    patched, imports = remediate(code, matches, rules)
    if patched == code and not imports:
        return None
    # Prepend any new imports the same way Remediation.js would
    if imports:
        patched = "\n".join(imports) + "\n" + patched
    return patched


def patch_devaic_v2(code: str, devaic_rules) -> str | None:
    """Same engine as Redlyne, original DeVAIC v2 rule set."""
    return patch_redlyne(code, devaic_rules)


def patch_semgrep(code: str) -> str | None:
    """Semgrep with --autofix --dryrun. Returns the patched text or None."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                      delete=False, encoding="utf-8") as tf:
        tf.write(code)
        tmp_path = Path(tf.name)
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config=auto", "--autofix", "--quiet",
             "--no-git-ignore", str(tmp_path)],
            capture_output=True, text=True, timeout=120,
        )
        # --autofix writes changes back to the file; read it
        patched = tmp_path.read_text(encoding="utf-8")
        return patched if patched != code else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def patch_patchitpy(code: str) -> str | None:
    """Run PatchitPy bash pipeline; parse REM_*.txt result file."""
    if not PATCHITPY_STARTER.exists():
        return None
    # PatchitPy writes results next to the input file
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        src_path = tmpdir / "sample.py"
        src_path.write_text(code, encoding="utf-8")
        try:
            subprocess.run(
                ["bash", str(PATCHITPY_STARTER), str(src_path), str(PATCHITPY_DIR)],
                capture_output=True, text=True, timeout=120,
                cwd=str(PATCHITPY_DIR),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        # Look for the result file PatchitPy generated
        res_dir = tmpdir / "results_sample"
        if not res_dir.exists():
            return None
        rem_files = list(res_dir.glob("REM_*"))
        if not rem_files:
            return None
        rem = rem_files[0].read_text(encoding="utf-8", errors="replace")
        lines = rem.splitlines()
        if len(lines) < 3:
            return None
        # Format: line 0 = vuln category, line 1 = NO-REM / REM-WITH-COMMENT /
        # actual encoded patched code, line 2 = (if line 1 was a real fix
        # marker) actually patched_code inline-encoded.
        marker = lines[1].strip()
        if marker in ("NO-REM", "REM-WITH-COMMENT", "SAFE-CODE"):
            return None
        # The patched code in PatchitPy is on line 2, inline-encoded with
        # \n as a literal separator
        patched_encoded = lines[2] if len(lines) > 2 else marker
        patched = patched_encoded.replace("\\n ", "\n").lstrip("\n")
        return patched if patched.strip() else None


# ---------------------------------------------------------------------------
# Evaluation: given a patched source, score the four properties.
# ---------------------------------------------------------------------------
def _rule_ids(matches) -> set[str]:
    """Extract the rule_id set from a list of engine matches."""
    ids = set()
    for m in matches or []:
        rid = m.get("rule_id") or m.get("id") or m.get("rule")
        if rid:
            ids.add(rid)
    return ids


def _patchable_rule_ids(rules) -> set[str]:
    """
    Return the set of rule IDs that ship at least one remediation directive.
    A rule without remediation is detection-only — when it fires after a
    patch, it's not a remediation failure (the engine never claimed it
    would fix that pattern). Used to define the honest `targeted_clean`
    metric: did the rules we PROMISED to fix actually get fixed?
    """
    out: set[str] = set()
    for r in rules or []:
        rid = getattr(r, "rule_id", None)
        rems = getattr(r, "remediations", None)
        if rid and rems:
            out.add(rid)
    return out


def evaluate_patch(original: str, patched: str | None, redlyne_rules,
                   patchable_ids: set[str] | None = None) -> dict:
    """
    Five-way evaluation of a single patch:

      - applied:         the tool changed the source.
      - syntax_safe:     patched still compiles.
      - targeted_clean:  the SPECIFIC rule IDs that fired on the original
                         no longer fire on the patched source. This is the
                         honest "did the fix work?" metric — a per-vuln
                         success rate, agnostic to whether the file carried
                         additional unrelated vulnerabilities.
      - regression_free: no NEW rule IDs appear post-patch (the patch
                         didn't introduce a vulnerability of a different
                         class). Existing untargeted ones may remain.
      - cross_clean:     post-patch source has ZERO findings overall.
                         Strictest possible; can be unfair to remediation
                         tools when the source carries multiple unrelated
                         vulnerabilities (e.g. PoisonPy poisoned files).
    """
    out = {
        "applied":          False,
        "syntax_safe":      None,
        "targeted_clean":   None,
        "regression_free":  None,
        "cross_clean":      None,
    }
    if patched is None or patched == original:
        return out
    out["applied"] = True

    # Syntax safety — relative to the original
    try:
        compile(original, "<orig>", "exec")
        orig_ok = True
    except (SyntaxError, ValueError):
        orig_ok = False
    try:
        compile(patched, "<patched>", "exec")
        patched_ok = True
    except (SyntaxError, ValueError):
        patched_ok = False
    if orig_ok:
        out["syntax_safe"] = patched_ok
    else:
        # Original wasn't valid Python anyway → don't punish the patch
        out["syntax_safe"] = True

    matches_before = scan(original, redlyne_rules)
    matches_after  = scan(patched,  redlyne_rules)
    ids_before = _rule_ids(matches_before)
    ids_after  = _rule_ids(matches_after)

    # Targeted: did the specific rule IDs that fired pre-patch — *and
    # carry a remediation block* — all stop firing post-patch?
    # Taint-source / detection-only rules that lack a `remediation`
    # block are excluded: the engine never promised to fix those, so
    # them still firing after the sink was patched is informational,
    # not a remediation failure. Honest "did the fix work?" metric.
    if patchable_ids is None:
        patchable_ids = _patchable_rule_ids(redlyne_rules)
    targeted_before = ids_before & patchable_ids
    if targeted_before:
        out["targeted_clean"] = not (targeted_before & ids_after)
    else:
        # Nothing remediable to begin with — can't measure targeting.
        out["targeted_clean"] = None

    # Regression: no NEW rule IDs introduced. Untargeted pre-existing
    # findings still in `ids_after` are tolerated here.
    out["regression_free"] = not (ids_after - ids_before)

    # Cross-clean: zero findings overall. Strictest, retained for
    # backward-compatibility with the existing summary.
    out["cross_clean"] = len(matches_after) == 0
    return out


def levenshtein_normalized(a: str, b: str) -> float:
    """Normalized Levenshtein similarity (0..1). Used for ground-truth distance."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Tiny DP — fine for snippet-sized strings
    n, m = len(a), len(b)
    if n > 1000 or m > 1000:
        # cap for runtime
        return 0.0
    prev = list(range(m + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * m
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j-1] + 1, prev[j] + 1, prev[j-1] + cost)
        prev = cur
    distance = prev[m]
    return 1 - distance / max(n, m)


# ---------------------------------------------------------------------------
# Main bench loop.
# ---------------------------------------------------------------------------
def bench_one_tool(tool_label: str, patch_fn, vuln_entries, clean_lookup,
                   redlyne_rules) -> dict:
    print(f"\n[{tool_label}] patching {len(vuln_entries)} vulnerable samples...", flush=True)
    t0 = time.perf_counter()
    patchable_ids = _patchable_rule_ids(redlyne_rules)
    rows = []
    counts = {
        "applied":          0,
        "syntax_safe":      0,
        "targeted_clean":   0,  # the rule_id(s) that fired pre-patch stopped
        "targeted_measurable": 0,  # samples where Redlyne saw ≥1 pre-patch hit
        "regression_free":  0,
        "cross_clean":      0,
        # Two flavors of "fully clean":
        #   targeted_full: syntax_safe + regression_free + targeted_clean
        #                  → "the fix worked on its target without breaking anything"
        #   strict_full:   syntax_safe + regression_free + cross_clean
        #                  → "the whole file is now vuln-free"
        "targeted_full":    0,
        "strict_full":      0,
    }
    similarities = []

    for i, entry in enumerate(vuln_entries):
        code = entry["code"]
        try:
            patched = patch_fn(code)
        except Exception:
            patched = None
        ev = evaluate_patch(code, patched, redlyne_rules, patchable_ids)
        rows.append({"source": entry["source"], "evaluation": ev})

        if ev["applied"]:
            counts["applied"] += 1
            if ev["syntax_safe"]:
                counts["syntax_safe"] += 1
            if ev["regression_free"]:
                counts["regression_free"] += 1
            if ev["cross_clean"]:
                counts["cross_clean"] += 1
            if ev["targeted_clean"] is not None:
                counts["targeted_measurable"] += 1
                if ev["targeted_clean"]:
                    counts["targeted_clean"] += 1
            # Two fully-clean flavors
            if (ev["syntax_safe"] and ev["regression_free"]
                    and ev["targeted_clean"]):
                counts["targeted_full"] += 1
            if (ev["syntax_safe"] and ev["regression_free"]
                    and ev["cross_clean"]):
                counts["strict_full"] += 1
            # Ground truth similarity (if available)
            ground = clean_lookup.get(entry["source"])
            if ground and patched:
                similarities.append(levenshtein_normalized(patched, ground))

        if (i + 1) % 25 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  ...{i+1}/{len(vuln_entries)} "
                  f"(applied={counts['applied']}, "
                  f"targeted_full={counts['targeted_full']}, "
                  f"strict_full={counts['strict_full']}, "
                  f"{elapsed:.1f}s)", flush=True)

    elapsed = time.perf_counter() - t0
    n = len(vuln_entries)
    tm = counts["targeted_measurable"]
    appl = counts["applied"]
    return {
        "tool":     tool_label,
        "total":    n,
        "applied":  appl,
        "syntax_safe":          counts["syntax_safe"],
        "targeted_clean":       counts["targeted_clean"],
        "targeted_measurable":  tm,
        "regression_free":      counts["regression_free"],
        "cross_clean":          counts["cross_clean"],
        # Headline (honest) — patch fixed its target, didn't break syntax,
        # didn't introduce new rule IDs. Reported as the primary metric.
        "targeted_full":        counts["targeted_full"],
        # Strict — whole file vuln-free post-patch. Reported for parity
        # with the legacy "cross_clean" headline. Penalizes single-fix
        # tools on multi-vuln samples.
        "strict_full":          counts["strict_full"],
        # Backward-compat alias kept for any consumer that still reads
        # `fully_clean_patch` (defaults to the *strict* notion).
        "fully_clean_patch":    counts["strict_full"],
        # Rates
        "applied_rate":              round(appl / n, 3) if n else 0,
        "rate_safe_of_applied":      round(counts["syntax_safe"] / appl, 3) if appl else 0,
        # Headline rate — used by post & website
        "rate_targeted_of_applied":  round(counts["targeted_full"] / appl, 3) if appl else 0,
        "rate_targeted_of_total":    round(counts["targeted_full"] / n, 3) if n else 0,
        # Strict (kept for backward compat & for the bottom of the table)
        "rate_clean_of_applied":     round(counts["strict_full"] / appl, 3) if appl else 0,
        "rate_clean_of_total":       round(counts["strict_full"] / n, 3) if n else 0,
        "mean_similarity_to_truth":  round(sum(similarities) / len(similarities), 3) if similarities else None,
        "elapsed_s":                 round(elapsed, 2),
        "ms_per_sample":             round(elapsed / n * 1000, 1) if n else 0,
    }


def write_reports(payload: dict, ts: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"run_{ts}.json"
    md_path = RESULTS_DIR / f"run_{ts}.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    out = []
    out.append(f"# Redlyne remediation head-to-head — {ts}")
    out.append("")
    out.append("Five properties measured per patch:")
    out.append("")
    out.append("- **Applied** — the tool emitted a code change (vs declining / silent).")
    out.append("- **Syntax-safe** — the patched source still compiles.")
    out.append("- **Targeted-clean** — the *specific* rule IDs that fired pre-patch no longer fire post-patch. This is the honest \"did the fix work?\" metric: success per targeted vulnerability, agnostic to whether the file carried other unrelated issues.")
    out.append("- **Regression-free** — no new rule IDs appear in the patched source. The patch didn't introduce a different vulnerability class.")
    out.append("- **Cross-validated clean** — strictest: the patched source has *zero* findings overall. Penalizes single-fix tools when the original file carries multiple unrelated vulnerabilities (common in PoisonPy).")
    out.append("")
    out.append("Two \"fully clean\" definitions:")
    out.append("")
    out.append("- **Targeted-full** = syntax-safe AND regression-free AND targeted-clean. *Headline metric.*")
    out.append("- **Strict-full** = syntax-safe AND regression-free AND cross-validated clean. Strictest, reported for parity with prior runs.")
    out.append("")

    # Per-dataset breakdown (new layout). Falls back to the legacy flat
    # `results` for old consumers if `datasets` is not present.
    sections = payload.get("datasets")
    if not sections:
        sections = [{
            "label": "PoisonPy (Cotroneo et al., ICPC 2024)",
            "vulnerable_total": payload.get("vulnerable_total", 0),
            "ground_truths": payload.get("vulnerable_total", 0),
            "results": payload.get("results", []),
        }]

    for section in sections:
        out.append(f"## {section['label']}")
        out.append("")
        out.append(f"Vulnerable samples: **{section['vulnerable_total']}** — "
                   f"ground-truth fixes available: **{section.get('ground_truths', 0)}**.")
        out.append("")
        out.append("### Honest headline — targeted-full")
        out.append("")
        out.append("| Tool | Applied | Targeted-full | Applied → Targeted-full | Total → Targeted-full | Sim. to ground truth | Latency |")
        out.append("|---|---|---|---|---|---|---|")
        for r in section["results"]:
            sim = f"{r['mean_similarity_to_truth']:.2f}" if r["mean_similarity_to_truth"] is not None else "—"
            tf = r.get("targeted_full", r.get("fully_clean_patch", 0))
            rate_app = r.get("rate_targeted_of_applied", r.get("rate_clean_of_applied", 0))
            rate_tot = r.get("rate_targeted_of_total",   r.get("rate_clean_of_total", 0))
            out.append(
                f"| **{r['tool']}** | {r['applied']}/{r['total']} ({r['applied_rate']:.0%}) | "
                f"{tf}/{r['total']} | "
                f"{rate_app:.1%} | {rate_tot:.1%} | "
                f"{sim} | {r['ms_per_sample']:.1f} ms |"
            )
        out.append("")
        out.append("### Strict — whole-file vuln-free post-patch")
        out.append("")
        out.append("| Tool | Strict-full | Applied → Strict-full | Total → Strict-full |")
        out.append("|---|---|---|---|")
        for r in section["results"]:
            sf = r.get("strict_full", r.get("fully_clean_patch", 0))
            out.append(
                f"| **{r['tool']}** | {sf}/{r['total']} | "
                f"{r['rate_clean_of_applied']:.1%} | {r['rate_clean_of_total']:.1%} |"
            )
        out.append("")

    out.append("## Reading the tables")
    out.append("")
    out.append("- **Applied → Targeted-full** is the rate of *correct* fixes among the ones actually generated. A tool that patches aggressively but most patches break syntax, introduce new vulns, or fail to actually remove the targeted bug ends up with a low number here. This is the metric we publish.")
    out.append("- **Total → Targeted-full** is the absolute coverage: of every vulnerable sample, how many ended with the targeted bug actually fixed and nothing broken.")
    out.append("- The **strict** table answers the harder question: is the *whole file* vuln-free post-patch? On datasets like PoisonPy, where a single sample can carry SQL injection + weak crypto + path traversal simultaneously, a tool that fixes one of three will pass *targeted-full* but fail *strict-full* — the latter is then a stress test, not a correctness metric.")
    out.append("- **Similarity to ground truth** is the normalized Levenshtein distance to the dataset's hand-written `code_clean` (PoisonPy) or commit `func_src_after` (SafeCoder). Informative, not authoritative — different idiomatic fixes can both be correct.")

    md_path.write_text("\n".join(out), encoding="utf-8")
    return json_path, md_path


def _build_poisonpy() -> tuple[list[dict], dict[str, str]]:
    """Return (vulnerable entries, source→clean-code ground-truth lookup)."""
    all_entries = load_poisonpy()
    vuln = [e for e in all_entries if e.get("vulnerable")]
    clean_lookup: dict[str, str] = {}
    for e in all_entries:
        if not e.get("vulnerable"):
            key = (e["source"]
                   .replace("120_clean", "120_poisoned")
                   .replace("/clean_", "/unsafe_")
                   .replace("/safe_", "/unsafe_"))
            clean_lookup[key] = e["code"]
    return vuln, clean_lookup


def _build_safecoder() -> tuple[list[dict], dict[str, str]]:
    """
    Same shape as _build_poisonpy() but on SafeCoder's commit-based pairs.
    SafeCoder sources end with '#vuln' or '#fixed'; we map each vuln to
    its #fixed counterpart for the ground-truth similarity.
    """
    all_entries = load_safecoder(include_fixes=True)
    vuln = [e for e in all_entries if e.get("vulnerable")]
    clean_lookup: dict[str, str] = {}
    for e in all_entries:
        if not e.get("vulnerable"):
            # SafeCoder/...row{i}#fixed → SafeCoder/...row{i}#vuln
            key = e["source"].replace("#fixed", "#vuln")
            clean_lookup[key] = e["code"]
    return vuln, clean_lookup


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tools", default="semgrep,patchitpy,redlyne",
                   help="Comma-separated subset (default: redlyne, patchitpy, "
                        "semgrep). DeVAIC v2 stock is intentionally excluded "
                        "from the default — it ships only 2 remediation rules "
                        "out of 441 (0.5%%) and isn't a remediation tool. Pass "
                        "'--tools redlyne,devaic_v2,...' to include it explicitly "
                        "(useful to demonstrate the detection-only baseline gap).")
    p.add_argument("--datasets", default="poisonpy,safecoder",
                   help="Comma-separated remediation datasets with ground-truth fixes "
                        "(default: poisonpy,safecoder).")
    p.add_argument("--no-patchitpy", action="store_true",
                   help="Skip PatchitPy (the bash subprocess pipeline) — saves ~40 min.")
    args = p.parse_args()

    active = [t.strip() for t in args.tools.split(",") if t.strip()]
    if args.no_patchitpy and "patchitpy" in active:
        active.remove("patchitpy")
    active_datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]

    print("Loading rule sets...", flush=True)
    redlyne_rules, _ = load_rules(verbose=False)
    devaic_v2_rules, _ = load_rules(DEVAIC_V2_RULES, verbose=False)
    print(f"  Redlyne v0.1.2: {len(redlyne_rules)} rules")
    print(f"  DeVAIC v2 stock: {len(devaic_v2_rules)} rules")

    dataset_builders = {
        "poisonpy":  ("PoisonPy (Cotroneo et al., ICPC 2024) — 155 paired synthetic samples",
                      _build_poisonpy),
        "safecoder": ("SafeCoder (He et al., ICML 2024) — ~526 real commit-based Python fixes",
                      _build_safecoder),
    }

    runners = {
        "redlyne":   ("Redlyne v0.1.2", lambda c: patch_redlyne(c, redlyne_rules)),
        "devaic_v2": ("DeVAIC v2 stock", lambda c: patch_devaic_v2(c, devaic_v2_rules)),
        "semgrep":   ("Semgrep --autofix", patch_semgrep),
        "patchitpy": ("PatchitPy (bash)", patch_patchitpy),
    }

    dataset_sections = []
    for ds_id in active_datasets:
        if ds_id not in dataset_builders:
            print(f"  ! unknown dataset: {ds_id}, skipping")
            continue
        ds_label, builder = dataset_builders[ds_id]
        print(f"\nLoading {ds_label}...", flush=True)
        try:
            vuln, clean_lookup = builder()
        except Exception as exc:
            print(f"  ! failed to load {ds_id}: {exc}")
            continue
        if not vuln:
            print(f"  ! dataset {ds_id} produced 0 vulnerable samples, skipping")
            continue
        print(f"  {len(vuln)} vulnerable samples, {len(clean_lookup)} clean ground truths available")

        results = []
        for tool_id in active:
            if tool_id not in runners:
                print(f"  ! unknown tool: {tool_id}, skipping")
                continue
            label, fn = runners[tool_id]
            results.append(bench_one_tool(label, fn, vuln, clean_lookup, redlyne_rules))

        dataset_sections.append({
            "dataset": ds_id,
            "label":   ds_label,
            "vulnerable_total": len(vuln),
            "ground_truths":    len(clean_lookup),
            "results": results,
        })

    # Backward-compat: keep the top-level fields the website/README scripts
    # already consume (results, vulnerable_total) populated from the FIRST
    # dataset (typically PoisonPy). New `datasets` field holds the full
    # per-dataset breakdown.
    primary = dataset_sections[0] if dataset_sections else {
        "results": [], "vulnerable_total": 0
    }
    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "dataset": primary.get("dataset", "?"),
        "vulnerable_total": primary["vulnerable_total"],
        "results": primary["results"],
        "datasets": dataset_sections,
    }
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path, md_path = write_reports(payload, ts)
    print()
    print(f"Wrote {json_path.relative_to(REPO_ROOT)}")
    print(f"Wrote {md_path.relative_to(REPO_ROOT)}")
    print()
    print("=== Summary ===")
    for section in dataset_sections:
        print(f"\n--- {section['label']} ---")
        for r in section["results"]:
            sim = f"{r['mean_similarity_to_truth']:.2f}" if r['mean_similarity_to_truth'] is not None else "n/a"
            tf_total = r.get("rate_targeted_of_total", 0)
            tf_app   = r.get("rate_targeted_of_applied", 0)
            sf_total = r.get("rate_clean_of_total", 0)
            sf_app   = r.get("rate_clean_of_applied", 0)
            print(f"  {r['tool']:<25} applied={r['applied_rate']:.0%}  "
                  f"targeted_full={tf_total:.0%} ({tf_app:.0%} of applied)  "
                  f"strict_full={sf_total:.0%} ({sf_app:.0%} of applied)  "
                  f"sim={sim}  ({r['ms_per_sample']:.1f} ms/file)")


if __name__ == "__main__":
    main()
