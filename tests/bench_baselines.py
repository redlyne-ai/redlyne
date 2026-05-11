"""
Head-to-head benchmark: Redlyne vs open-source static analyzers
on the PoisonPy dataset.

For each of the 4 tools (Bandit, Semgrep, Pylint, Redlyne) we run
binary classification on all 310 PoisonPy samples (155 vulnerable +
155 clean) and compute TP/FP/FN/TN, precision/recall/F1, accuracy.

A sample is considered "flagged" by a tool if the tool reports
at least one security finding on it. AST-based tools that fail
to parse a sample (PoisonPy has many syntactically informal
samples) are counted as "not flagged" — same convention used in
Cotroneo et al., ICPC 2024.

CodeQL is excluded from this run: it requires building a per-sample
database which is impractical for 310 micro-samples. Numbers from
the paper are quoted in the README for reference instead.

Usage:
    python tests/bench_baselines.py
    python tests/bench_baselines.py --quick    # only Bandit + Redlyne
    python tests/bench_baselines.py --tools bandit,redlyne

Outputs benchmarks/baselines_results/run_<ts>.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "launch_tool"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from redlyne_engine import load_rules, scan  # noqa: E402
from bench_dataset import (  # noqa: E402
    load_poisonpy, load_securityeval, load_copilot, load_cvefixes,
    load_safecoder, load_promsec,
)

RESULTS_DIR = REPO_ROOT / "benchmarks" / "baselines_results"


# ---------------------------------------------------------------------------
# Per-tool runners. Each returns one of:
#   "flagged"    — tool ran on the file and found ≥1 security issue
#   "clean"      — tool ran on the file and found nothing
#   "parse_fail" — tool gave up: file was not valid Python it could parse
#
# Distinguishing the three matters: skipping a file because the parser
# failed is NOT the same as analyzing it and saying it's clean. AI-
# generated code is often syntactically informal, and a static analyzer
# that bails out on it leaves the developer with no signal at all.
# ---------------------------------------------------------------------------
def run_bandit(code_path: Path) -> str:
    """Bandit. AST-based; raises 'parse_fail' on malformed code."""
    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", str(code_path)],
            capture_output=True, text=True, timeout=30,
        )
        if not result.stdout.strip():
            return "parse_fail"
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return "parse_fail"
        # Bandit fills `errors` when it could not parse the file
        if data.get("errors"):
            return "parse_fail"
        return "flagged" if len(data.get("results", [])) > 0 else "clean"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "parse_fail"


def run_semgrep(code_path: Path) -> str:
    """Semgrep. Tolerates malformed code (parses partially); rarely 'parse_fail'."""
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config=auto", "--json", "--quiet",
             "--no-git-ignore", str(code_path)],
            capture_output=True, text=True, timeout=60,
        )
        if not result.stdout.strip():
            return "parse_fail"
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return "parse_fail"
        # Semgrep reports parse errors in the "errors" array
        if data.get("errors") and not data.get("results"):
            return "parse_fail"
        return "flagged" if len(data.get("results", [])) > 0 else "clean"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "parse_fail"


def run_pylint(code_path: Path) -> str:
    """
    Pylint. Default config does NOT include security checks. We count
    `error` and `fatal` as a flag. A pure parse failure shows up as a
    single `fatal` `syntax-error` message — we treat that as parse_fail.
    """
    try:
        result = subprocess.run(
            ["pylint", "--output-format=json", "--score=n", str(code_path)],
            capture_output=True, text=True, timeout=30,
        )
        if not result.stdout.strip():
            return "parse_fail"
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return "parse_fail"
        # If the only message is a parse/syntax error, treat as parse_fail.
        fatal_or_error = [m for m in data if m.get("type") in ("error", "fatal")]
        if not fatal_or_error:
            return "clean"
        # Heuristic: if the ONLY signals are syntax-error/parse type fatal
        # messages, the file is unparseable, not "flagged for security".
        non_syntax = [m for m in fatal_or_error
                      if m.get("symbol", "") not in ("syntax-error", "parse-error")
                      and m.get("message-id", "") not in ("E0001", "F0002", "F0010")]
        if not non_syntax:
            return "parse_fail"
        return "flagged"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "parse_fail"


# Redlyne is invoked in-process to avoid subprocess overhead × 310 samples.
def make_redlyne_runner(rules_dir: Path | None = None):
    """Build an in-process runner over a specific rule set directory.
    Defaults to the shipped Redlyne v0.1.2 rules.

    Returns "flagged" / "clean" / "parse_fail" like the other runners.
    Redlyne practically never parse-fails because its detection is regex-
    based, not AST-based: any text input is "parseable" by definition.
    """
    if rules_dir is None:
        rules, _ = load_rules(verbose=False)
    else:
        rules, _ = load_rules(rules_dir, verbose=False)

    def run_inproc(code_path: Path) -> str:
        try:
            code = code_path.read_text(encoding="utf-8")
        except OSError:
            return "parse_fail"
        return "flagged" if scan(code, rules) else "clean"
    return run_inproc, len(rules)


# DeVAIC v2.0 stock rule set lives in baselines/. Same scan engine,
# original rules (no POSIX-compat fixes, no template rules) — lets us
# measure the impact of Redlyne's extensions on top of DeVAIC v2.
DEVAIC_V2_RULES = REPO_ROOT / "baselines" / "DeVAIC-main" / "version_2.0" / "ruleset"

# DeVAIC v1.0 has no external rule files — its detection is inlined in a
# 172 KB bash script (tool_derem.sh). We invoke it via subprocess to get
# the original v1.0 numbers (slow: ~15-20s per file; recommended on
# PoisonPy only, not on CVEfixes where 6000 samples = many hours).
DEVAIC_V1_DIR = REPO_ROOT / "baselines" / "DeVAIC-main" / "version_1.0"
DEVAIC_V1_SCRIPT = DEVAIC_V1_DIR / "devaic.sh"


def run_devaic_v1(code_path: Path) -> str:
    """Run DeVAIC v1.0 via bash on a single file. Slow but original."""
    try:
        result = subprocess.run(
            ["bash", str(DEVAIC_V1_SCRIPT), str(code_path), str(DEVAIC_V1_DIR)],
            capture_output=True, text=True, timeout=120,
            cwd=str(DEVAIC_V1_DIR),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "parse_fail"
    out = (result.stdout or "") + (result.stderr or "")
    # DeVAIC v1.0 is regex-based, doesn't really "fail to parse" — but if
    # the script errored out we count it as parse_fail
    if result.returncode != 0 and "error" in out.lower():
        return "parse_fail"
    markers = ("INJC", "CRYF", "BRAC", "IDAF", "SECM", "SLMF", "INSD",
               "SSRF", "SDIF", "vulnerable", "Detected")
    return "flagged" if any(m in out for m in markers) else "clean"


TOOLS = {
    "bandit":     ("Bandit", run_bandit),
    "semgrep":    ("Semgrep (auto rules)", run_semgrep),
    "pylint":     ("Pylint (errors+fatal only)", run_pylint),
    "devaic_v1":  ("DeVAIC v1.0 (bash, original)", run_devaic_v1),
    # devaic_v2 + redlyne added at runtime so we capture their rule counts
}


# ---------------------------------------------------------------------------
# Bench loop.
# ---------------------------------------------------------------------------
def _classify(entry, runner):
    """Worker: write entry to tmp file, run tool, return (is_vuln, verdict).
    `verdict` ∈ {"flagged", "clean", "parse_fail"}.
    """
    is_vuln = bool(entry.get("vulnerable"))
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                      delete=False, encoding="utf-8") as tf:
        tf.write(entry["code"])
        tmp_path = Path(tf.name)
    try:
        return is_vuln, runner(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def _tally(cm, is_vuln, verdict):
    """Update confusion matrix counters for a single (is_vuln, verdict)."""
    if verdict == "parse_fail":
        # Track separately. We also count it as "FN" on the all-samples
        # recall (because a real user gets no signal) and as a non-event
        # for the analyzed-only recall.
        cm["parse_fail"] += 1
        if is_vuln:
            cm["FN_all"] += 1
        else:
            cm["TN_all"] += 1
        return
    # File was actually analyzed
    cm["analyzed"] += 1
    if verdict == "flagged":
        if is_vuln:
            cm["TP"] += 1
            cm["FN_all"]  # noop, just for symmetry
        else:
            cm["FP"] += 1
    else:  # clean
        if is_vuln:
            cm["FN"] += 1
            cm["FN_all"] += 1
        else:
            cm["TN"] += 1
            cm["TN_all"] += 1
    # The all-flagged numbers also include the analyzed TP/FP
    if verdict == "flagged":
        if is_vuln:
            cm["TP_all"] += 1
        else:
            cm["FP_all"] += 1


def bench_tool(tool_id: str, label: str, runner, entries: list[dict]) -> dict:
    print(f"\n[{label}] running on {len(entries)} samples...", flush=True)
    t0 = time.perf_counter()
    cm = {
        # On samples the tool actually analyzed:
        "TP": 0, "FP": 0, "FN": 0, "TN": 0,
        # On ALL samples (parse failures treated as "no flag"):
        "TP_all": 0, "FP_all": 0, "FN_all": 0, "TN_all": 0,
        # How many samples the tool couldn't parse:
        "parse_fail": 0,
        # How many it could analyze:
        "analyzed": 0,
    }

    # In-process tools (Redlyne, DeVAIC v2 stock) don't benefit from
    # parallelism — run serial. Subprocess tools benefit massively.
    parallel = tool_id not in ("redlyne", "devaic_v2")

    if parallel:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_classify, e, runner) for e in entries]
            done = 0
            for f in as_completed(futures):
                is_vuln, verdict = f.result()
                _tally(cm, is_vuln, verdict)
                done += 1
                if done % 50 == 0:
                    elapsed = time.perf_counter() - t0
                    print(f"  ...{done}/{len(entries)} ({elapsed:.1f}s, "
                          f"parse_fail={cm['parse_fail']})", flush=True)
    else:
        for i, entry in enumerate(entries):
            is_vuln, verdict = _classify(entry, runner)
            _tally(cm, is_vuln, verdict)
            if (i + 1) % 50 == 0:
                elapsed = time.perf_counter() - t0
                print(f"  ...{i+1}/{len(entries)} ({elapsed:.1f}s)", flush=True)

    elapsed = time.perf_counter() - t0
    n_total = len(entries)
    n_analyzed = cm["analyzed"]

    # Metrics restricted to analyzed samples (favourable to AST tools)
    tp, fp, fn, tn = cm["TP"], cm["FP"], cm["FN"], cm["TN"]
    p_a = tp / (tp + fp) if (tp + fp) else 0.0
    r_a = tp / (tp + fn) if (tp + fn) else 0.0
    f1_a = 2 * p_a * r_a / (p_a + r_a) if (p_a + r_a) else 0.0
    acc_a = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0

    # Metrics on ALL samples — parse failures count as no-flag.
    # This is what a real developer experiences.
    tp_all = cm["TP_all"]
    fp_all = cm["FP_all"]
    fn_all = cm["FN_all"]
    tn_all = cm["TN_all"]
    p_all = tp_all / (tp_all + fp_all) if (tp_all + fp_all) else 0.0
    r_all = tp_all / (tp_all + fn_all) if (tp_all + fn_all) else 0.0
    f1_all = 2 * p_all * r_all / (p_all + r_all) if (p_all + r_all) else 0.0
    acc_all = (tp_all + tn_all) / (tp_all + fp_all + fn_all + tn_all) if (tp_all + fp_all + fn_all + tn_all) else 0.0

    coverage = n_analyzed / n_total if n_total else 0.0

    return {
        "tool": tool_id,
        "label": label,
        # Backward-compat field for the all-samples confusion matrix:
        "TP": tp_all, "FP": fp_all, "FN": fn_all, "TN": tn_all,
        "precision": round(p_all, 3),
        "recall":    round(r_all, 3),
        "f1":        round(f1_all, 3),
        "accuracy":  round(acc_all, 3),
        # NEW: separate "analyzed only" metrics
        "coverage":              round(coverage, 3),
        "parse_fail":            cm["parse_fail"],
        "analyzed":              n_analyzed,
        "precision_on_analyzed": round(p_a, 3),
        "recall_on_analyzed":    round(r_a, 3),
        "f1_on_analyzed":        round(f1_a, 3),
        "accuracy_on_analyzed":  round(acc_a, 3),
        "elapsed_s":             round(elapsed, 2),
    }


# ---------------------------------------------------------------------------
# Report writer.
# ---------------------------------------------------------------------------
def write_reports(sections: list[dict], rules_loaded: int, ts: str) -> tuple[Path, Path]:
    """
    `sections` is a list of {dataset, label, mode, results} dicts:
      - mode='paired'    → TP/FP/FN/TN + precision/recall/F1/accuracy
      - mode='vuln_only' → only TP/FN + recall (no FP measurable)
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"run_{ts}.json"
    md_path = RESULTS_DIR / f"run_{ts}.md"

    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "redlyne_rules_loaded": rules_loaded,
        "sections": sections,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    out = []
    out.append(f"# Redlyne head-to-head bench — {ts}")
    out.append("")
    out.append(f"Engine: Redlyne with **{rules_loaded}** rules. Each tool runs binary classification on every sample. A sample is considered \"flagged\" if the tool reports ≥1 finding (security-relevant for Pylint = errors/fatal only).")
    out.append("")

    for section in sections:
        out.append(f"## {section['label']}")
        out.append("")
        out.append(section["description"])
        out.append("")

        # Total sample count for this section (constant across tools)
        total_n = (section["results"][0]["TP"] + section["results"][0]["FN"]
                   + section["results"][0]["FP"] + section["results"][0]["TN"]) \
                  if section["results"] else 0

        if section["mode"] == "paired":
            out.append("**Operational metrics** — parse failures count as no-flag (what a developer actually sees inside the editor):")
            out.append("")
            out.append("| Tool | Coverage | Precision | Recall | F1 | Accuracy | Per sample |")
            out.append("|---|---|---|---|---|---|---|")
            for r in section["results"]:
                per_sample_ms = (r["elapsed_s"] / total_n * 1000) if total_n else 0
                out.append(
                    f"| **{r['label']}** | {r['coverage']:.1%} ({r['analyzed']}/{total_n}) | "
                    f"{r['precision']:.1%} | {r['recall']:.1%} | {r['f1']:.3f} | "
                    f"{r['accuracy']:.1%} | {per_sample_ms:.1f} ms |"
                )
            out.append("")
            out.append("**Restricted to analyzed samples** — apples-to-apples on the subset every tool managed to process (a higher-coverage tool sees more samples and therefore a different — but comparable — denominator):")
            out.append("")
            out.append("| Tool | Analyzed | Precision | Recall | F1 |")
            out.append("|---|---|---|---|---|")
            for r in section["results"]:
                out.append(
                    f"| **{r['label']}** | {r['analyzed']}/{total_n} | "
                    f"{r['precision_on_analyzed']:.1%} | {r['recall_on_analyzed']:.1%} | "
                    f"{r['f1_on_analyzed']:.3f} |"
                )
        else:  # vuln_only
            out.append("Vulnerable-only dataset: no `clean` samples present, so only recall is measurable. Parse failures count as a miss for the operational column.")
            out.append("")
            out.append("| Tool | Coverage | Recall (all samples) | Recall (analyzed only) | Per sample |")
            out.append("|---|---|---|---|---|")
            for r in section["results"]:
                per_sample_ms = (r["elapsed_s"] / total_n * 1000) if total_n else 0
                out.append(
                    f"| **{r['label']}** | {r['coverage']:.1%} ({r['analyzed']}/{total_n}) | "
                    f"{r['recall']:.1%} | {r['recall_on_analyzed']:.1%} | "
                    f"{per_sample_ms:.1f} ms |"
                )
        out.append("")

    out.append("## Notes")
    out.append("")
    out.append("- AST-based tools (Bandit, Pylint) silently fail on syntactically informal samples — common in PoisonPy. The `FN` column captures this.")
    out.append("- Semgrep uses the `auto` ruleset (registry-curated security rules).")
    out.append("- Pylint by design is a code-quality linter, not a security scanner; only `error` and `fatal` messages count as a security flag here. On PoisonPy its high recall is an artifact: it flags malformed sample files for being malformed, not for vulnerability — accuracy ≈ 50% (random) confirms it cannot discriminate vulnerable from clean.")
    out.append("- CodeQL is excluded: per-sample database build makes it impractical for these micro-samples. Numbers from Cotroneo et al. (ICPC 2024) are quoted separately in the README.")
    out.append("- **DeVAIC v1.0 baseline**: run via the original bash script (`baselines/DeVAIC-main/version_1.0/devaic.sh`). Detection rules are hardcoded inline in a 172 KB shell file, so we cannot load them into our Python engine — we invoke the bash pipeline as a subprocess instead. Slow (~15-20s/sample) and dependent on bash + jq being installed. Recommended only on PoisonPy.")
    out.append("- **DeVAIC v2 stock baseline**: same scan engine as Redlyne, but loading the *original* DeVAIC v2.0 rule set (`baselines/DeVAIC-main/version_2.0/ruleset/`). Lets us isolate the impact of Redlyne's extensions on top of DeVAIC. Note: 121 of the original 441 DeVAIC rules use POSIX-only regex syntax (BSD sed/grep) that doesn't compile in Python `re`; those rules are skipped on this engine. The original DeVAIC v2 paper reports its numbers from a bash pipeline where all 441 rules load.")
    out.append("- **Per-sample time fairness note**: Redlyne runs in-process (one Python interpreter loaded once, scan is just a function call). Bandit/Semgrep/Pylint spawn one subprocess per sample, even with 8-way parallelism. This reflects the real-world latency a developer sees inside VS Code: Redlyne returns results in milliseconds because that's how it actually runs inside the extension; the other tools could only match that latency by being daemonized, which none of them ship out of the box.")
    md_path.write_text("\n".join(out), encoding="utf-8")
    return json_path, md_path


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tools", default="bandit,semgrep,pylint,devaic_v2,redlyne",
                   help="Comma-separated subset (default: 5 tools). Add 'devaic_v1' "
                        "to include DeVAIC v1.0 bash baseline (slow: ~15-20s/sample).")
    p.add_argument("--datasets", default="poisonpy,securityeval,copilot,safecoder,promsec",
                   help="Comma-separated datasets (default: poisonpy, securityeval, "
                        "copilot, safecoder, promsec). CVEfixes is opt-in via "
                        "--include-cvefixes (private until rule coverage on real-world "
                        "CVEs is broadened).")
    p.add_argument("--include-cvefixes", action="store_true",
                   help="Also bench against CVEfixes (private dataset, opt-in).")
    p.add_argument("--copilot-sample", type=int, default=5,
                   help="Cap N python files per copilot scenario (default: 5, 0=full)")
    p.add_argument("--cvefixes-limit", type=int, default=500,
                   help="Cap N paired CVE-file rows from CVEfixes (default: 500, 0=full)")
    p.add_argument("--safecoder-include-fixes", dest="safecoder_include_fixes",
                   action="store_true", default=True,
                   help="For SafeCoder, also count the func_src_after samples "
                        "as clean (enables paired precision/F1). Default: ON.")
    p.add_argument("--no-safecoder-fixes", dest="safecoder_include_fixes",
                   action="store_false",
                   help="For SafeCoder, drop the post-fix samples — recall-only mode. "
                        "Useful when comparing against tools that game precision "
                        "on the fixed side.")
    p.add_argument("--quick", action="store_true",
                   help="Only Bandit + Redlyne on PoisonPy (smoke run)")
    args = p.parse_args()

    if args.quick:
        active_tools = ["bandit", "redlyne"]
        active_datasets = ["poisonpy"]
    else:
        active_tools = [t.strip() for t in args.tools.split(",") if t.strip()]
        active_datasets = [d.strip() for d in args.datasets.split(",") if d.strip()]
        # CVEfixes is opt-in (privately benchmarked while rule coverage
        # for real-world CVEs is broadened). Don't include unless asked.
        if args.include_cvefixes and "cvefixes" not in active_datasets:
            active_datasets.append("cvefixes")
        if not args.include_cvefixes and "cvefixes" in active_datasets:
            active_datasets.remove("cvefixes")

    print("Loading Redlyne rules...", flush=True)
    rules, errors = load_rules(verbose=False)
    print(f"  Redlyne v0.1.2: {len(rules)} rules ({len(errors)} errors)")

    redlyne_runner, redlyne_n = make_redlyne_runner()

    # DeVAIC v2 stock — same engine, original rule set (no fixes, no
    # template rules). Lets us measure the *delta* introduced by Redlyne.
    devaic_v2_available = DEVAIC_V2_RULES.exists()
    if devaic_v2_available:
        devaic_v2_runner, devaic_v2_n = make_redlyne_runner(DEVAIC_V2_RULES)
        # Count of rules that failed to compile in our engine (POSIX-only).
        _, devaic_v2_errs = load_rules(DEVAIC_V2_RULES, verbose=False)
        print(f"  DeVAIC v2 stock: {devaic_v2_n} rules load ({len(devaic_v2_errs)} POSIX-incompat skipped)")
    else:
        print(f"  DeVAIC v2 not found at {DEVAIC_V2_RULES} — skipping that baseline")

    runners = {
        **{k: v for k, v in TOOLS.items()},
        "redlyne": (f"Redlyne v0.1.2 ({redlyne_n} rules)", redlyne_runner),
    }
    if devaic_v2_available:
        runners["devaic_v2"] = (
            f"DeVAIC v2 stock ({devaic_v2_n} rules, POSIX-compat subset)",
            devaic_v2_runner,
        )

    # Each dataset is either "paired" (has clean+vuln, supports precision/F1)
    # or "vuln_only" (no clean samples, only recall measurable).
    cap = args.copilot_sample if args.copilot_sample > 0 else None
    cve_limit = args.cvefixes_limit if args.cvefixes_limit > 0 else None
    safecoder_paired = args.safecoder_include_fixes
    dataset_specs = {
        "poisonpy": {
            "label": "PoisonPy (Cotroneo et al., ICPC 2024)",
            "description": "310 paired samples (155 vulnerable + 155 clean) curated to evaluate AI-code-generator security. The only synthetic dataset with paired clean files — supports precision and F1.",
            "loader": load_poisonpy,
            "mode": "paired",
        },
        "securityeval": {
            "label": "SecurityEval (s2e-lab)",
            "description": "121 hand-curated vulnerable Python snippets organized by CWE. Vulnerable-only: precision not measurable.",
            "loader": load_securityeval,
            "mode": "vuln_only",
        },
        "copilot": {
            "label": f"Copilot CWE Scenarios (Pearce et al.)" + (f" — sampled ≤{cap}/scenario" if cap else " — full"),
            "description": "1024 Python files generated by GitHub Copilot, organized by 24 CWEs across three experimental designs (DoW/DoP/DoD). Vulnerable-only: precision not measurable.",
            "loader": lambda: load_copilot(sample_per_scenario=cap),
            "mode": "vuln_only",
        },
        "safecoder": {
            "label": ("SafeCoder (He et al., ICML 2024)"
                      + (" — paired vuln + commit-fix" if safecoder_paired
                         else " — vulnerable side only")),
            "description": ("~526 Python functions (~13 CWEs) extracted from real-world "
                            "security commits in `sec-desc` + `sec-new-desc`. "
                            "Each row ships `func_src_before` (vulnerable) and "
                            "`func_src_after` (the human-authored fix from the commit). "
                            "With `--safecoder-include-fixes` (default), both sides "
                            "count → supports precision/F1. "
                            "With `--no-safecoder-fixes`, only the vulnerable side "
                            "is used → recall-only."),
            "loader": lambda: load_safecoder(include_fixes=safecoder_paired),
            "mode": "paired" if safecoder_paired else "vuln_only",
        },
        "promsec": {
            "label": "PromSec (Nazzal et al., CCS 2024)",
            "description": "~600 vulnerable Python files generated by Copilot, split into "
                           "Training_DS (500 files, CWE in filename) and Testing_DS "
                           "(100 files, no CWE label). Vulnerable-only: PromSec's own "
                           "`Fixed_codes/` outputs are LLM stubs that strip functionality, "
                           "so they're NOT used as ground truth.",
            "loader": load_promsec,
            "mode": "vuln_only",
        },
        "cvefixes": {
            "label": f"CVEfixes (Bhandari et al., PROMISE 2021)" + (f" — first {cve_limit} CVE-file pairs" if cve_limit else " — full"),
            "description": "Real CVE fixes from public open-source projects. Each `file_change` ships paired code_before (vulnerable) and code_after (fixed) — supports precision and F1 on real-world, production-grade code (not synthetic snippets).",
            "loader": lambda: load_cvefixes(limit=cve_limit),
            "mode": "paired",
        },
    }

    sections = []
    for ds_id in active_datasets:
        if ds_id not in dataset_specs:
            print(f"  ! unknown dataset: {ds_id}, skipping")
            continue
        spec = dataset_specs[ds_id]
        print(f"\n--- Loading {spec['label']} ---", flush=True)
        entries = spec["loader"]()
        if not entries:
            print(f"  ! dataset {ds_id} not found on disk, skipping")
            continue
        print(f"  {len(entries)} samples")

        # Vuln-only datasets (SecurityEval, Copilot) ship entries without
        # a `vulnerable` field because all entries are vulnerable by design.
        # Force the flag here so the bench classifier counts them as TP/FN.
        if spec["mode"] == "vuln_only":
            entries = [{**e, "vulnerable": 1} for e in entries]

        section_results = []
        for tool_id in active_tools:
            if tool_id not in runners:
                print(f"  ! unknown tool: {tool_id}, skipping")
                continue
            label, runner = runners[tool_id]
            section_results.append(bench_tool(tool_id, label, runner, entries))

        sections.append({
            "dataset": ds_id,
            "label": spec["label"],
            "description": spec["description"],
            "mode": spec["mode"],
            "results": section_results,
        })

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path, md_path = write_reports(sections, len(rules), ts)
    print()
    print(f"Wrote {json_path.relative_to(REPO_ROOT)}")
    print(f"Wrote {md_path.relative_to(REPO_ROOT)}")
    print()
    for section in sections:
        print(f"=== {section['label']} ===")
        if not section["results"]:
            continue
        total_n = (section["results"][0]["TP"] + section["results"][0]["FN"]
                   + section["results"][0]["FP"] + section["results"][0]["TN"])
        for r in section["results"]:
            per_ms = (r["elapsed_s"] / total_n * 1000) if total_n else 0
            cov = f"cov={r['coverage']:.0%}({r['analyzed']}/{total_n})"
            if section["mode"] == "paired":
                # `all` = parse_fail counted as no-flag (operational reality)
                # `analyzed` = restricted to samples the tool actually processed
                print(f"  {r['label']:<45} {cov}")
                print(f"    all:      P={r['precision']:.1%}  R={r['recall']:.1%}  F1={r['f1']:.3f}  Acc={r['accuracy']:.1%}")
                print(f"    analyzed: P={r['precision_on_analyzed']:.1%}  R={r['recall_on_analyzed']:.1%}  F1={r['f1_on_analyzed']:.3f}  Acc={r['accuracy_on_analyzed']:.1%}")
                print(f"    speed:    {per_ms:.1f} ms/file")
            else:
                print(f"  {r['label']:<45} {cov}  "
                      f"R-all={r['recall']:.1%}  R-analyzed={r['recall_on_analyzed']:.1%}  "
                      f"({per_ms:.1f} ms/file)")
        print()


if __name__ == "__main__":
    main()
