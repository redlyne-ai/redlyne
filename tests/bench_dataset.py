"""
Dataset benchmark for the Redlyne engine.

Runs the engine over two public Python-vulnerability datasets and
measures detection rate per CWE. Maps CWE → OWASP Top 10:2021 (the
mapping the rules currently emit) and reports both layers.

Datasets expected under ./dataset/ (gitignored):

  - SecurityEval-main/dataset.jsonl
        121 entries with {"ID": "CWE-XXX_<source>_<n>.py",
                          "Prompt": "...",
                          "Insecure_code": "..."}
        Source: github.com/s2e-lab/SecurityEval

  - copilot-cwe-scenarios-dataset/experiments_{dow,dop,dod}/cwe-NNN/.../*.py
        Python files with copilot-generated code targeting a known CWE.
        Source: zenodo.org/records/5225651

Outputs:
  benchmarks/dataset_results/run_<timestamp>.json   (raw, machine-readable)
  benchmarks/dataset_results/run_<timestamp>.md     (human-readable)

Usage:
  python tests/bench_dataset.py                # both datasets
  python tests/bench_dataset.py --securityeval  # only SecurityEval
  python tests/bench_dataset.py --copilot       # only Copilot CWE Scenarios
  python tests/bench_dataset.py --copilot-sample 5  # cap N files per scenario

Design choices:
  * We invoke the engine through `redlyne_engine.scan()` directly rather
    than spawning a subprocess per file: 1031+ subprocess starts would
    dominate the wall-clock; in-process saves ~85ms × 1100 = ~90s.
  * For Copilot scenarios we sample N files per (cwe, scenario_dir)
    by default — the dataset has 25 generations per scenario which is
    redundant for our recall measurement.
  * The CWE→OWASP mapping is in CWE_TO_OWASP. Rules emit OWASP names
    (e.g. "Injection"); we consider a detection correct if the engine
    emits any OWASP category that the expected CWE maps to.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Make redlyne_engine importable.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "launch_tool"))

from redlyne_engine import load_rules, scan, RULES_DIR  # noqa: E402

DATASET_DIR = REPO_ROOT / "dataset"
SECURITYEVAL_JSONL = DATASET_DIR / "SecurityEval-main" / "dataset.jsonl"
COPILOT_DIR = DATASET_DIR / "copilot-cwe-scenarios-dataset"
POISONPY_DIR = DATASET_DIR / "PoisonPy"
# CVEfixes is unpacked under dataset/CVEfixes_v1.0.8/Data/CVEfixes.db
# (db is built locally via `sqlite3 CVEfixes.db < CVEfixes_v1.0.8.sql`).
CVEFIXES_DB = DATASET_DIR / "CVEfixes_v1.0.8" / "Data" / "CVEfixes.db"
# SafeCoder (ETH Zurich, ICML 2024) — paired commit-based fixes.
SAFECODER_DIR = DATASET_DIR / "SafeCoder-main"
# PromSec (NJIT, CCS 2024) — Copilot-generated vulnerable Python files.
# Results_cfg_*/Fixed_codes/ exists but is NOT a usable ground truth: the
# "fixed" outputs are functionality-stripped stubs, not real fixes.
PROMSEC_DIR = DATASET_DIR / "PromSec-main"
RESULTS_DIR = REPO_ROOT / "benchmarks" / "dataset_results"


# ---------------------------------------------------------------------------
# CWE → OWASP Top 10:2025 mapping.
#
# Rules emit OWASP names (Injection, Cryptographic Failures, ...) per
# the 2025 taxonomy. A detection counts as a hit if the engine emits
# any OWASP category this CWE maps to.
#
# Notable 2025 changes vs 2021:
#   - "Identification and Authentication Failures" → "Authentication
#     Failures" (renamed)
#   - "Server-Side Request Forgery" merged into "Injection"
#
# Memory-safety CWEs (119/125/416/476/787) are intentionally absent —
# they're inapplicable to Python and mostly come from C scenarios in
# the Copilot dataset, which we filter out anyway.
# ---------------------------------------------------------------------------
CWE_TO_OWASP: dict[str, list[str]] = {
    "CWE-020": ["Injection"],
    "CWE-022": ["Broken Access Control"],
    "CWE-078": ["Injection"],
    "CWE-079": ["Injection"],
    "CWE-089": ["Injection"],
    "CWE-094": ["Injection"],
    "CWE-095": ["Injection"],
    "CWE-113": ["Injection"],
    "CWE-117": ["Security Logging and Monitoring Failures"],
    "CWE-190": ["Insecure Design"],  # integer overflow
    "CWE-200": ["Broken Access Control"],
    "CWE-209": ["Security Logging and Monitoring Failures"],
    "CWE-215": ["Security Misconfiguration"],
    "CWE-250": ["Broken Access Control"],
    "CWE-252": ["Software and Data Integrity Failures"],
    "CWE-259": ["Authentication Failures"],
    "CWE-269": ["Broken Access Control"],
    "CWE-285": ["Broken Access Control"],
    "CWE-295": ["Authentication Failures"],
    "CWE-297": ["Authentication Failures"],
    "CWE-306": ["Authentication Failures"],
    "CWE-319": ["Cryptographic Failures"],
    "CWE-321": ["Cryptographic Failures"],
    "CWE-326": ["Cryptographic Failures"],
    "CWE-327": ["Cryptographic Failures"],
    "CWE-329": ["Cryptographic Failures"],
    "CWE-330": ["Cryptographic Failures"],
    "CWE-331": ["Cryptographic Failures"],
    "CWE-339": ["Cryptographic Failures"],
    "CWE-347": ["Cryptographic Failures"],
    "CWE-352": ["Broken Access Control"],
    "CWE-377": ["Insecure Design"],
    "CWE-379": ["Insecure Design"],
    "CWE-385": ["Cryptographic Failures"],  # covert timing channel
    "CWE-400": ["Insecure Design"],
    "CWE-406": ["Insecure Design"],
    "CWE-414": ["Insecure Design"],
    "CWE-434": ["Insecure Design"],
    "CWE-462": ["Insecure Design"],
    "CWE-463": ["Insecure Design"],
    "CWE-477": ["Software and Data Integrity Failures"],
    "CWE-502": ["Software and Data Integrity Failures"],
    "CWE-521": ["Authentication Failures"],
    "CWE-522": ["Authentication Failures"],
    "CWE-595": ["Insecure Design"],
    "CWE-601": ["Broken Access Control"],
    "CWE-605": ["Insecure Design"],
    "CWE-611": ["Security Misconfiguration"],
    "CWE-641": ["Insecure Design"],
    "CWE-643": ["Injection"],
    "CWE-703": ["Insecure Design"],
    "CWE-732": ["Broken Access Control"],
    "CWE-759": ["Cryptographic Failures"],
    "CWE-760": ["Cryptographic Failures"],
    "CWE-776": ["Insecure Design"],
    "CWE-798": ["Authentication Failures"],
    "CWE-827": ["Software and Data Integrity Failures"],
    "CWE-841": ["Insecure Design"],
    "CWE-918": ["Injection"],
    "CWE-941": ["Injection"],
    "CWE-943": ["Injection"],
    "CWE-1004": ["Authentication Failures"],
    "CWE-1204": ["Cryptographic Failures"],
    "CWE-1333": ["Insecure Design"],  # ReDoS
}

# Memory-safety / C-only CWEs we never expect to detect on Python.
PYTHON_INAPPLICABLE_CWES = {
    "CWE-119", "CWE-120", "CWE-125", "CWE-416", "CWE-457",
    "CWE-476", "CWE-787", "CWE-1234", "CWE-1242", "CWE-1245",
    "CWE-1254", "CWE-1271", "CWE-1294",
}


CWE_RE = re.compile(r"CWE-(\d{2,4})", re.IGNORECASE)


def normalize_cwe(raw: str) -> str | None:
    """Normalize 'cwe-79', 'CWE-079', 'CWE-79_xxx' → 'CWE-079'."""
    m = CWE_RE.search(raw)
    if not m:
        return None
    n = int(m.group(1))
    return f"CWE-{n:03d}"


# ---------------------------------------------------------------------------
# Engine wrapper.
# ---------------------------------------------------------------------------
def detected_owasp_categories(code: str, rules) -> set[str]:
    """Run engine on a code blob; return the set of OWASP names emitted."""
    cats: set[str] = set()
    matches = scan(code, rules)
    for m in matches:
        # scan() returns plain dicts (not Match objects). Each carries
        # an `owasp` key with the category names already resolved from
        # the rule's OWASP_CODE_MAP entries.
        for cat in (m.get("owasp") or []):
            cats.add(cat)
    return cats


# ---------------------------------------------------------------------------
# Dataset loaders.
# ---------------------------------------------------------------------------
def load_securityeval() -> list[dict]:
    """
    Load the SecurityEval dataset.jsonl as a list of {cwe, code, source}.

    Each entry: {"ID": "CWE-094_author_1.py", "Prompt": "...", "Insecure_code": "..."}
    """
    if not SECURITYEVAL_JSONL.exists():
        return []
    out = []
    with SECURITYEVAL_JSONL.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            cwe = normalize_cwe(entry.get("ID", ""))
            if not cwe or cwe in PYTHON_INAPPLICABLE_CWES:
                continue
            out.append({
                "cwe": cwe,
                "code": entry.get("Insecure_code", ""),
                "source": f"SecurityEval/{entry.get('ID', '?')}",
            })
    return out


def load_copilot(sample_per_scenario: int | None = None) -> list[dict]:
    """
    Load Python files from the Copilot CWE Scenarios dataset.

    Skips C/non-Python scenarios (cwe-119, cwe-125, cwe-416, etc.) and
    optionally caps per-scenario file count to `sample_per_scenario`.
    """
    if not COPILOT_DIR.exists():
        return []
    out = []
    for cwe_dir in sorted(COPILOT_DIR.rglob("cwe-*")):
        if not cwe_dir.is_dir():
            continue
        cwe = normalize_cwe(cwe_dir.name)
        if not cwe or cwe in PYTHON_INAPPLICABLE_CWES:
            continue
        # Group .py files per scenario directory and cap
        for scenario_dir in cwe_dir.iterdir():
            if not scenario_dir.is_dir():
                continue
            # Filter: keep only Python scenarios. The dir name often
            # contains "python" or the file extension is .py — we just
            # check .py files.
            py_files = sorted(scenario_dir.rglob("*.py"))
            if not py_files:
                continue
            if sample_per_scenario:
                py_files = py_files[:sample_per_scenario]
            for f in py_files:
                try:
                    code = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                out.append({
                    "cwe": cwe,
                    "code": code,
                    "source": f"Copilot/{f.relative_to(COPILOT_DIR)}",
                })
    return out


def load_poisonpy() -> list[dict]:
    """
    Load the PoisonPy benchmark — paired clean / poisoned samples
    organized by category. PoisonPy is the dataset Devaic itself was
    benchmarked on (Cotroneo et al.), so producing numbers on it lets
    us compare apples-to-apples with the published Devaic paper.

    Returns a list of {category, code, vulnerable (0/1), source}.
    Each "logical sample" appears twice in the output: once as the
    poisoned (vulnerable=1) version and once as the clean (=0) version.
    The bench_pairs() function below relies on this pairing.

    Categories (Cotroneo et al. taxonomy):
      - TPI: Tainted Path Injection
      - DPI: Data Persistent Injection
      - ICI: Insecure Code Implementation
    """
    if not POISONPY_DIR.exists():
        return []
    out = []

    # 120 paired samples (40 TPI + 40 DPI + 40 ICI)
    paired_dir = POISONPY_DIR / "Unsafe samples with Safe implementation"
    for jfile in sorted(paired_dir.glob("*.json")):
        kind = "clean" if "clean" in jfile.name else "poisoned"
        for i, entry in enumerate(json.loads(jfile.read_text(encoding="utf-8"))):
            out.append({
                "category": entry.get("category", "?"),
                "code": entry.get("code", ""),
                "vulnerable": entry.get("vulnerable", 1 if kind == "poisoned" else 0),
                "source": f"PoisonPy/{jfile.stem}/sample_{i}",
            })

    # 35 additional TPI pairs (released later as supplementary benchmark)
    add_dir = POISONPY_DIR / "Additional TPI Samples"
    for jname in ("additional_35_TPI_SAFE.json", "additional_35_TPI_UNSAFE.json"):
        jpath = add_dir / jname
        if not jpath.exists():
            continue
        is_unsafe = "UNSAFE" in jname
        for i, entry in enumerate(json.loads(jpath.read_text(encoding="utf-8"))):
            out.append({
                "category": entry.get("category", "TPI"),
                "code": entry.get("code", ""),
                "vulnerable": entry.get("vulnerable", 1 if is_unsafe else 0),
                "source": f"PoisonPy/additional_TPI/{'unsafe' if is_unsafe else 'safe'}_{i}",
            })

    return out


def load_cvefixes(db_path: Path = CVEFIXES_DB,
                  limit: int | None = 1000,
                  max_file_lines: int = 400) -> list[dict]:
    """
    Load Python paired vulnerable/fixed file_change samples from the
    CVEfixes SQLite database (Bhandari, Naseer, Moonen — PROMISE 2021).

    Each row in `file_change` with `programming_language='Python'` and
    change_type='MODIFY' carries both `code_before` (vulnerable) and
    `code_after` (fixed). We expand each row into two bench entries:
      - vulnerable=1 with code_before
      - vulnerable=0 with code_after

    `limit` caps the number of CVE-file pairs (not entries) to keep
    the bench time predictable. `max_file_lines` skips very large
    files where running every static analyzer would dominate the
    wall-clock without changing the conclusions.
    """
    if not db_path.exists():
        return []
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Join with fixes + cwe_classification to surface the CVE id and CWE.
    # CVEfixes stores change_type as the repr of pydriller's enum,
    # e.g. 'ModificationType.MODIFY', not a clean 'MODIFY'.
    q = """
    SELECT
        fc.file_change_id,
        fc.filename,
        fc.code_before,
        fc.code_after,
        f.cve_id,
        (SELECT cwe_id FROM cwe_classification
         WHERE cve_id = f.cve_id LIMIT 1) AS cwe_id
    FROM file_change fc
    JOIN fixes f ON fc.hash = f.hash
    WHERE fc.programming_language = 'Python'
      AND fc.change_type = 'ModificationType.MODIFY'
      AND fc.code_before IS NOT NULL
      AND fc.code_after IS NOT NULL
      AND length(fc.code_before) > 0
      AND length(fc.code_after) > 0
    """
    if limit:
        q += f" LIMIT {int(limit)}"

    out: list[dict] = []
    try:
        for row in conn.execute(q):
            code_before = row["code_before"] or ""
            code_after = row["code_after"] or ""
            # Skip files that are too large — keeps the bench tractable
            # and avoids one giant CVE dominating wall-clock time.
            if code_before.count("\n") > max_file_lines:
                continue
            if code_after.count("\n") > max_file_lines:
                continue
            cve = row["cve_id"] or "?"
            fname = row["filename"] or "?"
            cwe = row["cwe_id"] or "?"
            out.append({
                "cwe": cwe,
                "category": cwe,
                "code": code_before,
                "vulnerable": 1,
                "source": f"CVEfixes/{cve}/{fname}#vuln",
            })
            out.append({
                "cwe": cwe,
                "category": cwe,
                "code": code_after,
                "vulnerable": 0,
                "source": f"CVEfixes/{cve}/{fname}#fixed",
            })
    finally:
        conn.close()
    return out


def load_safecoder(include_fixes: bool = True) -> list[dict]:
    """
    Load paired vulnerable/fixed Python functions from the SafeCoder
    dataset (He et al., ICML 2024). SafeCoder ships two JSONL files
    of real-world commit-based fixes:

      - sec-desc      — adapted from prior SVEN work (4 CWEs)
      - sec-new-desc  — new in SafeCoder (9 CWEs)

    Each row contains `func_src_before` (vulnerable function) and
    `func_src_after` (the fix as it appeared in the public commit).
    These are *human-authored, production-grade* fixes — much stronger
    ground truth than synthetic LLM-generated patches.

    We filter rows to Python only (via file_name.endswith('.py')) and
    yield each pair as TWO entries:
      - vulnerable=1 with func_src_before
      - vulnerable=0 with func_src_after  (only if include_fixes=True)

    When `include_fixes=False` only the vulnerable side is emitted,
    which lets the detection bench run in "recall-only" mode against
    SafeCoder (a useful comparison if the user suspects a baseline is
    gaming precision on the after-fix samples).
    """
    if not SAFECODER_DIR.exists():
        return []
    out: list[dict] = []
    jsonl_files = [
        SAFECODER_DIR / "data_train_val" / "train" / "sec-desc.jsonl",
        SAFECODER_DIR / "data_train_val" / "val"   / "sec-desc.jsonl",
        SAFECODER_DIR / "data_train_val" / "train" / "sec-new-desc.jsonl",
        SAFECODER_DIR / "data_train_val" / "val"   / "sec-new-desc.jsonl",
    ]
    for jpath in jsonl_files:
        if not jpath.exists():
            continue
        split_id = f"{jpath.parent.name}/{jpath.stem}"  # train/sec-desc, etc.
        with jpath.open(encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fn = (row.get("file_name") or "").lower()
                # Filter Python only — the JSONL `lang` field is null;
                # rely on the actual file extension stored in `file_name`.
                if not fn.endswith(".py"):
                    continue
                cwe = normalize_cwe(row.get("vul_type") or "")
                if not cwe or cwe in PYTHON_INAPPLICABLE_CWES:
                    continue
                before = row.get("func_src_before") or ""
                after  = row.get("func_src_after") or ""
                if not before.strip():
                    continue
                source_prefix = f"SafeCoder/{split_id}/row{i}"
                out.append({
                    "cwe": cwe,
                    "category": cwe,
                    "code": before,
                    "vulnerable": 1,
                    "source": f"{source_prefix}#vuln",
                })
                if include_fixes and after.strip() and after.strip() != before.strip():
                    out.append({
                        "cwe": cwe,
                        "category": cwe,
                        "code": after,
                        "vulnerable": 0,
                        "source": f"{source_prefix}#fixed",
                    })
    return out


def load_promsec() -> list[dict]:
    """
    Load PromSec vulnerable Python samples (Nazzal et al., CCS 2024).

    PromSec uses a graph-GAN + LLM loop to iteratively rewrite
    Copilot-generated insecure code. For our purposes we use only the
    *input* corpus: two directories of vulnerable Python files.

      - Training_DS/ — ~500 files, CWE encoded in the filename
        (e.g. `experiments_dop_cwe-89_unsubscribe_..._copilot_0.py`)
      - Testing_DS/  — ~100 files (`test_file{0..99}.py`) with no CWE
        label in the filename.

    The Results_cfg_*/Fixed_codes/ outputs are intentionally NOT
    treated as ground truth: in spot checks the LLM "fixed" code
    strips all functionality and returns success stubs, so similarity
    against them would penalize honest fixes.

    For Testing_DS we set cwe='?' so the bench's CWE→OWASP mapping
    counts those samples as "uncovered" rather than wrong, mirroring
    how we handle CWEs absent from CWE_TO_OWASP elsewhere.
    """
    if not PROMSEC_DIR.exists():
        return []
    out: list[dict] = []

    training_dir = PROMSEC_DIR / "Training_DS"
    if training_dir.is_dir():
        for f in sorted(training_dir.glob("*.py")):
            cwe = normalize_cwe(f.name) or "?"
            if cwe in PYTHON_INAPPLICABLE_CWES:
                continue
            try:
                code = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            out.append({
                "cwe": cwe,
                "category": cwe,
                "code": code,
                "vulnerable": 1,
                "source": f"PromSec/Training_DS/{f.name}",
            })

    testing_dir = PROMSEC_DIR / "Testing_DS"
    if testing_dir.is_dir():
        for f in sorted(testing_dir.glob("*.py")):
            try:
                code = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # No CWE label in filename — try the file content first line
            # (some files declare `# CWE-XX` in a header comment); fall
            # back to '?' which is treated as uncovered.
            head = "\n".join(code.splitlines()[:5])
            cwe = normalize_cwe(head) or "?"
            if cwe in PYTHON_INAPPLICABLE_CWES:
                continue
            out.append({
                "cwe": cwe,
                "category": cwe,
                "code": code,
                "vulnerable": 1,
                "source": f"PromSec/Testing_DS/{f.name}",
            })

    return out


# ---------------------------------------------------------------------------
# Main bench.
# ---------------------------------------------------------------------------
def bench(entries: list[dict], rules, label: str) -> dict:
    """Run engine on every entry, compute per-CWE recall."""
    print(f"\n[{label}] {len(entries)} entries", flush=True)

    by_cwe = defaultdict(lambda: {"total": 0, "hit": 0, "miss_examples": []})
    total = len(entries)
    hit = 0
    t0 = time.perf_counter()

    for i, entry in enumerate(entries):
        cwe = entry["cwe"]
        expected_cats = set(CWE_TO_OWASP.get(cwe, []))
        if not expected_cats:
            # We don't have a CWE → OWASP mapping for this CWE — count
            # it as "uncovered by our taxonomy" so it doesn't pollute
            # recall numbers.
            by_cwe[cwe]["total"] += 1
            continue

        detected = detected_owasp_categories(entry["code"], rules)
        ok = bool(detected & expected_cats)

        by_cwe[cwe]["total"] += 1
        if ok:
            by_cwe[cwe]["hit"] += 1
            hit += 1
        else:
            if len(by_cwe[cwe]["miss_examples"]) < 3:
                by_cwe[cwe]["miss_examples"].append(entry["source"])

        if (i + 1) % 100 == 0:
            elapsed = time.perf_counter() - t0
            print(f"  ...{i+1}/{total} ({elapsed:.1f}s)", flush=True)

    elapsed = time.perf_counter() - t0
    overall_recall = hit / total if total else 0.0

    # Per-CWE summary (sorted by total desc)
    rows = []
    for cwe, d in sorted(by_cwe.items(), key=lambda x: -x[1]["total"]):
        rate = d["hit"] / d["total"] if d["total"] else 0.0
        rows.append({
            "cwe": cwe,
            "total": d["total"],
            "hit": d["hit"],
            "recall": round(rate, 3),
            "miss_examples": d["miss_examples"],
        })

    return {
        "label": label,
        "total": total,
        "hit": hit,
        "overall_recall": round(overall_recall, 3),
        "elapsed_s": round(elapsed, 2),
        "by_cwe": rows,
    }


def bench_pairs(entries: list[dict], rules, label: str) -> dict:
    """
    Benchmark on a labeled dataset where each entry has `vulnerable`
    in {0, 1} (PoisonPy-style). Computes the full confusion matrix
    plus precision / recall / F1, both globally and per-category.

    A detection counts as "engine flagged this entry" if scan() returns
    at least one match — we don't try to match on specific OWASP
    categories here because PoisonPy doesn't ship per-CWE labels.
    """
    print(f"\n[{label}] {len(entries)} entries", flush=True)
    t0 = time.perf_counter()

    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    )
    overall = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

    for i, e in enumerate(entries):
        cat = e.get("category", "?")
        is_vuln = bool(e.get("vulnerable"))
        flagged = bool(scan(e["code"], rules))

        if is_vuln and flagged:
            cell = "TP"
        elif is_vuln and not flagged:
            cell = "FN"
        elif not is_vuln and flagged:
            cell = "FP"
        else:
            cell = "TN"
        overall[cell] += 1
        by_cat[cat][cell] += 1

        if (i + 1) % 100 == 0:
            print(f"  ...{i+1}/{len(entries)}", flush=True)

    elapsed = time.perf_counter() - t0

    def metrics(d: dict[str, int]) -> dict:
        tp, fp, fn, tn = d["TP"], d["FP"], d["FN"], d["TN"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        return {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
            "accuracy":  round(accuracy, 3),
            "fpr":       round(fpr, 3),
        }

    return {
        "label": label,
        "total": len(entries),
        "elapsed_s": round(elapsed, 2),
        "overall": metrics(overall),
        "by_category": {cat: metrics(d) for cat, d in sorted(by_cat.items())},
    }


def write_reports(payload: dict, ts: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"run_{ts}.json"
    md_path = RESULTS_DIR / f"run_{ts}.md"

    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Markdown
    out = []
    out.append(f"# Redlyne dataset benchmark — {ts}")
    out.append("")
    out.append(f"- Engine rules loaded: **{payload['rules_loaded']}**")
    out.append(f"- Total entries scanned: **{payload['grand_total']}**")
    out.append(f"- Total wall-clock time: **{payload['total_elapsed_s']}s**")
    out.append("")

    for section in payload["sections"]:
        out.append(f"## {section['label']}")
        out.append("")
        # Pair-style report (PoisonPy): full confusion matrix
        if "overall" in section and "by_category" in section:
            o = section["overall"]
            out.append(f"- Entries: **{section['total']}**")
            out.append(f"- TP / FP / FN / TN: **{o['TP']} / {o['FP']} / {o['FN']} / {o['TN']}**")
            out.append(f"- Precision: **{o['precision']:.1%}** — when we flag, how often are we right")
            out.append(f"- Recall: **{o['recall']:.1%}** — of the truly vulnerable, how many we catch")
            out.append(f"- F1: **{o['f1']:.3f}**")
            out.append(f"- Accuracy: **{o['accuracy']:.1%}**")
            out.append(f"- False Positive Rate: **{o['fpr']:.1%}** — of the truly safe, how many we wrongly flag")
            out.append(f"- Time: {section['elapsed_s']}s")
            out.append("")
            out.append("### Per-category breakdown")
            out.append("")
            out.append("| Cat | TP | FP | FN | TN | Precision | Recall | F1 | FPR |")
            out.append("|---|---|---|---|---|---|---|---|---|")
            for cat, m in section["by_category"].items():
                out.append(
                    f"| {cat} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | "
                    f"{m['precision']:.1%} | {m['recall']:.1%} | {m['f1']:.3f} | {m['fpr']:.1%} |"
                )
            out.append("")
            continue

        # Recall-only report (SecurityEval / Copilot)
        out.append(f"- Entries: **{section['total']}**")
        out.append(f"- Hits: **{section['hit']}**")
        out.append(f"- Overall recall: **{section['overall_recall']:.1%}**")
        out.append(f"- Time: {section['elapsed_s']}s")
        out.append("")
        out.append("### Per-CWE breakdown")
        out.append("")
        out.append("| CWE | Total | Hit | Recall | Miss examples |")
        out.append("|---|---|---|---|---|")
        for row in section["by_cwe"]:
            misses = ", ".join(row["miss_examples"][:2]) if row["miss_examples"] else "—"
            out.append(
                f"| {row['cwe']} | {row['total']} | {row['hit']} | "
                f"{row['recall']:.1%} | {misses} |"
            )
        out.append("")

    md_path.write_text("\n".join(out), encoding="utf-8")
    return json_path, md_path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--securityeval", action="store_true",
                   help="Run only the SecurityEval dataset")
    p.add_argument("--copilot", action="store_true",
                   help="Run only the Copilot CWE Scenarios dataset")
    p.add_argument("--poisonpy", action="store_true",
                   help="Run only the PoisonPy paired clean/poisoned dataset")
    p.add_argument("--safecoder", action="store_true",
                   help="Run only the SafeCoder paired commit-fix dataset")
    p.add_argument("--promsec", action="store_true",
                   help="Run only the PromSec vulnerable-Python dataset")
    p.add_argument("--copilot-sample", type=int, default=5,
                   help="Cap N python files per copilot scenario dir "
                        "(default: 5; pass 0 for no cap = full dataset)")
    p.add_argument("--no-safecoder-fixes", action="store_true",
                   help="For SafeCoder, only count the vulnerable side "
                        "(skip the func_src_after clean samples). Useful "
                        "for recall-only comparison.")
    args = p.parse_args()

    any_filter = (args.securityeval or args.copilot or args.poisonpy
                  or args.safecoder or args.promsec)
    do_se = args.securityeval or not any_filter
    do_co = args.copilot or not any_filter
    do_pp = args.poisonpy or not any_filter
    do_sc = args.safecoder or not any_filter
    do_pm = args.promsec or not any_filter

    print("Loading rules...", flush=True)
    rules, errors = load_rules(verbose=False)
    if errors:
        print(f"  WARNING: {len(errors)} rule load errors (proceeding)")
    print(f"  loaded {len(rules)} rules")

    sections = []
    grand_total = 0
    total_elapsed = 0.0
    t_global = time.perf_counter()

    if do_se:
        entries = load_securityeval()
        if entries:
            section = bench(entries, rules, label="SecurityEval (insecure-code only)")
            sections.append(section)
            grand_total += section["total"]
            total_elapsed += section["elapsed_s"]
        else:
            print("  ! SecurityEval not found at", SECURITYEVAL_JSONL)

    if do_co:
        cap = args.copilot_sample if args.copilot_sample > 0 else None
        entries = load_copilot(sample_per_scenario=cap)
        if entries:
            cap_label = f"sampled ≤{cap}/scenario" if cap else "full dataset, no sampling"
            section = bench(entries, rules, label=f"Copilot CWE Scenarios ({cap_label})")
            sections.append(section)
            grand_total += section["total"]
            total_elapsed += section["elapsed_s"]
        else:
            print("  ! Copilot dataset not found at", COPILOT_DIR)

    if do_pp:
        entries = load_poisonpy()
        if entries:
            section = bench_pairs(entries, rules,
                                  label="PoisonPy (paired clean/poisoned, Cotroneo et al.)")
            sections.append(section)
            grand_total += section["total"]
            total_elapsed += section["elapsed_s"]
        else:
            print("  ! PoisonPy not found at", POISONPY_DIR)

    if do_sc:
        entries = load_safecoder(include_fixes=not args.no_safecoder_fixes)
        if entries:
            mode_label = ("paired vuln+fix, ICML 2024"
                          if not args.no_safecoder_fixes else "vuln-only")
            section = bench_pairs(entries, rules,
                                  label=f"SafeCoder ({mode_label}, He et al.)")
            sections.append(section)
            grand_total += section["total"]
            total_elapsed += section["elapsed_s"]
        else:
            print("  ! SafeCoder not found at", SAFECODER_DIR)

    if do_pm:
        entries = load_promsec()
        if entries:
            section = bench(entries, rules,
                            label="PromSec (Copilot-generated vulnerable Python, Nazzal et al.)")
            sections.append(section)
            grand_total += section["total"]
            total_elapsed += section["elapsed_s"]
        else:
            print("  ! PromSec not found at", PROMSEC_DIR)

    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "rules_loaded": len(rules),
        "rule_load_errors": len(errors),
        "grand_total": grand_total,
        "total_elapsed_s": round(time.perf_counter() - t_global, 2),
        "sections": sections,
    }

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path, md_path = write_reports(payload, ts)
    print()
    print(f"Wrote {json_path.relative_to(REPO_ROOT)}")
    print(f"Wrote {md_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
