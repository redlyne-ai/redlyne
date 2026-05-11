# Redlyne — Internal benchmark guide

This document is **internal**: not packaged with the VS Code extension and not
surfaced on the public site. It covers the three head-to-head harnesses that
produce the numbers we ship on the website, the public README, and the
LinkedIn posts.

For the engine regression / parity test suite, see `tests/README.md`.

| Script | What it measures | Tools compared | Typical runtime |
|---|---|---|---|
| `bench_dataset.py` | Redlyne **detection** alone across datasets | Redlyne only | 1–3 min |
| `bench_baselines.py` | **Detection** head-to-head | Redlyne, DeVAIC v2, DeVAIC v1, Bandit, Semgrep, Pylint | 5–10 min |
| `bench_remediation.py` | **Remediation** head-to-head | Redlyne, DeVAIC v2, Semgrep autofix, PatchitPy | 5 min (no PatchitPy) / ~40 min (full) |

All three write timestamped JSON + Markdown reports under `tests/reports/`.

---

## Prerequisites

```bash
# From the repo root
cd ~/Desktop/Redlyne

# Engine + baseline deps
python -m pip install -r requirements.txt
python -m pip install bandit semgrep pylint

# Optional: DeVAIC v1 (very slow, opt-in)
#   baselines/DeVAIC-v1/ must already contain the legacy bash entrypoint

# Optional: PatchitPy (remediation benchmark only)
chmod +x baselines/PatchitPy-main/extension_PatchitPy/launch_tool/*.sh
```

### Datasets

Expected layout under `dataset/`:

```
dataset/
├── PoisonPy/
│   ├── Unsafe samples with Safe implementation/
│   └── Additional TPI Samples/
├── SecurityEval-main/dataset.jsonl
├── copilot-cwe-scenarios-dataset/
└── CVEfixes_v1.0.8/Data/CVEfixes.db        # optional, private
```

CVEfixes is **private for now**. Redlyne's rule set doesn't yet cover most of
its CWEs (we're +0.01 F1 vs DeVAIC v2 there), so the numbers aren't publishable
until rule coverage is extended. Keep the DB locally; don't commit it.

If you need to rebuild the SQLite from the dump:

```bash
cd dataset/CVEfixes_v1.0.8/Data
gunzip CVEfixes_v1.0.8.sql.gz
sqlite3 CVEfixes.db < CVEfixes_v1.0.8.sql
```

---

## `bench_dataset.py` — Redlyne detection across datasets

Sanity-checks Redlyne in isolation. Use this to verify a rule change before
running the heavier baseline comparison.

```bash
python tests/bench_dataset.py
```

Output: `tests/reports/bench_dataset_<ts>.{json,md}` with per-dataset
precision / recall / F1 / accuracy and OWASP-level confusion.

---

## `bench_baselines.py` — Detection head-to-head

The headline detection benchmark. Reports **two** sets of numbers per tool:

- **Operational** — every sample counts, parse failures count as misses.
  This is what reaches end users — fair comparison.
- **On analyzed only** — only samples the tool actually parsed.
  Matches the metric definition in the baseline papers; favorable to AST-based
  tools.

Both are emitted so we can pick per channel (website / post / paper) without
re-running.

### Quick start

```bash
# Default: all tools, all public datasets (PoisonPy + SecurityEval + Copilot)
python tests/bench_baselines.py

# Subset of tools
python tests/bench_baselines.py --tools redlyne,devaic_v2,semgrep

# Subset of datasets
python tests/bench_baselines.py --datasets poisonpy

# Faster smoke test
python tests/bench_baselines.py --quick

# Include CVEfixes (private, ~500 samples by default)
python tests/bench_baselines.py --include-cvefixes --cvefixes-limit 500

# Include DeVAIC v1 (very slow bash subprocess per sample)
python tests/bench_baselines.py --tools redlyne,devaic_v1,devaic_v2
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--tools` | `bandit,semgrep,pylint,devaic_v2,redlyne` | Comma list. Valid IDs: `bandit`, `semgrep`, `pylint`, `devaic_v1`, `devaic_v2`, `redlyne` |
| `--datasets` | `poisonpy,securityeval,copilot` | Comma list of dataset IDs |
| `--include-cvefixes` | off | Opt-in for the private CVEfixes run |
| `--copilot-sample` | `5` | Samples per CWE scenario in Copilot |
| `--cvefixes-limit` | `500` | Cap on CVEfixes pairs loaded |
| `--quick` | off | Subsamples each dataset for fast iteration |

The report includes a **Coverage** column (`analyzed / total`). The ~17% you'll
see for Bandit / Pylint on PoisonPy is the AST-parse-failure cliff — they
can't read malformed AI output. That's the whole point of the operational
table.

---

## `bench_remediation.py` — Remediation head-to-head

Measures whether a tool can **fix** a vulnerable file, not just flag it.
PoisonPy is the only dataset wired in: it ships `code_clean` ground truth
paired to each vulnerable sample.

### Quick start

```bash
# Fast mode — skips PatchitPy bash subprocess, ~5 min
python tests/bench_remediation.py --no-patchitpy

# Full run — includes PatchitPy, ~40 min
python tests/bench_remediation.py

# Subset of tools
python tests/bench_remediation.py --tools redlyne,semgrep
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--tools` | `semgrep,patchitpy,devaic_v2,redlyne` | Comma list |
| `--no-patchitpy` | off | Skip the slow PatchitPy subprocess loop |

### Metrics reported per tool

| Column | Definition |
|---|---|
| **Applied** | Tool produced a non-identical patch |
| **Syntax-safe** | `ast.parse(patched)` succeeds |
| **Regression-free** | Patched code introduces **no new** Redlyne findings |
| **Cross-clean** | Redlyne rescan finds **zero** vulns in the patched file (strict) |
| **Similarity** | Normalized Levenshtein vs PoisonPy `code_clean` ground truth |
| **Latency** | Median ms per sample |

The headline claim we're testing: **"every patch Redlyne emits is verified
safe before it touches your buffer"** — only holds up if `cross-clean` lands
at or near 100%.

---

## Reports

All three harnesses write into `tests/reports/`:

```
tests/reports/
├── bench_dataset_2026-05-11T12-30-00.json
├── bench_dataset_2026-05-11T12-30-00.md
├── bench_baselines_2026-05-11T13-15-22.json
├── bench_baselines_2026-05-11T13-15-22.md
├── bench_remediation_2026-05-11T14-02-09.json
└── bench_remediation_2026-05-11T14-02-09.md
```

The `.md` files are what get copy-pasted into the public README, the website
benchmark component, and LinkedIn posts. The `.json` files are the source of
truth for downstream visualisations and for tracking trend across releases.

---

## Conventions when publishing numbers

1. **Always publish coverage alongside accuracy.** A 99% F1 on the 17% you
   could parse is not the same as a 99% F1 on the whole dataset. Skipping
   that distinction is what makes AST-only baselines look better than they
   are in practice.
2. **Use the operational table for the website and LinkedIn.** Use the
   on-analyzed table when responding to academic reviewers familiar with
   the baseline papers.
3. **Don't quote CVEfixes numbers externally** until the rule set is
   extended. Redlyne is only +0.01 F1 vs DeVAIC v2 there; we publish it
   once we've widened CWE coverage.
4. **Re-run after any engine, rule, or remediation-script change.** The
   harnesses are cheap; trusting stale numbers is expensive.
5. **Commit reports selectively.** Keep only the final report that backs
   a published number. Intermediate iterations go in `.gitignore` (see
   `tests/reports/.gitignore`).
