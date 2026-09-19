"""
scripts/generate_latex_tables.py — Generate all LaTeX table files for main.tex.

Reads:
  - results.csv                 → Table 1 (main static results)
  - results_adaptive.csv        → Table 2 (RQ4: static vs adaptive)
  - results_canary_ablation.csv → Table 3 (canary placement ablation)

Writes to research/tables/:
  - table_main_results.tex
  - table_rq4_adaptive.tex
  - table_canary_ablation.tex

Usage:
    python scripts/generate_latex_tables.py
"""

import sys
import csv
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.compute_statistics import wilson_ci, mcnemar_test

TABLES_DIR = Path("research") / "tables"
TABLES_DIR.mkdir(parents=True, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def ci_str(successes: int, n: int) -> str:
    """Return 'rate% [lo%, hi%]' formatted for LaTeX table cells."""
    if n == 0:
        return r"\textemdash"
    lo, hi = wilson_ci(successes, n)
    rate = successes / n * 100
    return rf"{rate:.1f}\% [{lo*100:.1f}\%\textendash{hi*100:.1f}\%]"


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        print(f"  WARNING: {path} not found — skipping this table.")
        return []
    return list(csv.DictReader(path.open(encoding="utf-8")))


# ── Table 1: Main Static Results ──────────────────────────────────────────────

def gen_table_main(rows: list[dict]) -> str:
    # Filter to Phase 1 benchmark runs (2026-09-10 date, single-suite runs)
    benchmark_rows = [
        r for r in rows
        if "+" not in r.get("Suite", "")
        and r.get("Model", "") in ("llama3", "gemma3:12b")
        and r.get("Timestamp", "").startswith("2026-09-10")
    ]

    # Deduplicate: keep latest run per (model, suite)
    latest: dict[tuple, dict] = {}
    for r in benchmark_rows:
        key = (r["Model"], r["Suite"])
        if key not in latest or r["Timestamp"] > latest[key]["Timestamp"]:
            latest[key] = r

    # Build table
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Attack Success Rate (ASR) and 95\% Wilson score confidence intervals",
        r"         for static benchmark evaluation across two models and three attack categories.}",
        r"\label{tab:main-results}",
        r"\setlength{\tabcolsep}{4pt}",
        r"\begin{tabular}{llrrrr}",
        r"\toprule",
        r"\textbf{Model} & \textbf{Suite} & \textbf{N} & \textbf{Complied} & "
        r"\textbf{ASR} & \textbf{95\% CI (Wilson)} \\",
        r"\midrule",
    ]

    suite_order = ["jailbreak", "injection", "exfiltration"]
    model_order = ["llama3", "gemma3:12b"]
    model_labels = {"llama3": r"Llama-3-8B", "gemma3:12b": r"Gemma-3-12B"}

    for model in model_order:
        for i, suite in enumerate(suite_order):
            r = latest.get((model, suite))
            if r is None:
                continue
            n         = int(r["Total"])
            complied  = int(r["Complied"])
            model_str = model_labels.get(model, model) if i == 0 else ""
            ci        = ci_str(complied, n)
            rate_pct  = f"{complied/n*100:.1f}" if n > 0 else r"\textemdash"
            lines.append(
                rf"{model_str} & \texttt{{{suite}}} & {n} & {complied} & "
                rf"{rate_pct}\% & {ci} \\"
            )
        lines.append(r"\midrule")

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines)


# ── Table 2: RQ4 Adaptive Results ────────────────────────────────────────────

def gen_table_rq4(rows: list[dict]) -> str:
    if not rows:
        return "% results_adaptive.csv not found — run run_adaptive_experiment.py first\n"

    # Group by model+suite
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r["model"], r["suite"])].append(r)

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Static vs.\ adaptive (PAIR) attack success rates.",
        r"         $p$-values from McNemar's test with continuity correction.",
        r"         Mean iterations conditioned on adaptive success.}",
        r"\label{tab:rq4-adaptive}",
        r"\setlength{\tabcolsep}{3pt}",
        r"\begin{tabular}{llccccr}",
        r"\toprule",
        r"\textbf{Model} & \textbf{Suite} & \textbf{ASR$_{\text{static}}$} & "
        r"\textbf{ASR$_{\text{adapt.}}$} & \textbf{McNemar $p$} & \textbf{Mean Iters} \\",
        r"\midrule",
    ]

    model_labels = {"llama3": r"Llama-3-8B", "gemma3:12b": r"Gemma-3-12B"}
    suite_order = ["jailbreak", "injection"]

    for model in ["llama3", "gemma3:12b"]:
        for suite in suite_order:
            group = groups.get((model, suite), [])
            if not group:
                continue

            n   = len(group)
            s_s = sum(int(r["succeeded_static"]) for r in group)
            s_a = sum(int(r["succeeded_adaptive"]) for r in group)

            b = sum(1 for r in group if not int(r["succeeded_static"]) and int(r["succeeded_adaptive"]))
            c = sum(1 for r in group if int(r["succeeded_static"]) and not int(r["succeeded_adaptive"]))
            _, p = mcnemar_test(b, c)

            successful = [r for r in group if int(r["succeeded_adaptive"])]
            mean_iters = (
                f"{sum(int(r['iterations_to_success']) for r in successful) / len(successful):.1f}"
                if successful else r"\textemdash"
            )

            p_str = rf"\textbf{{{p:.3f}}}*" if p < 0.05 else f"{p:.3f}"
            asr_s_str = ci_str(s_s, n)
            asr_a_str = ci_str(s_a, n)

            lines.append(
                rf"{model_labels.get(model, model)} & \texttt{{{suite}}} & "
                rf"{asr_s_str} & {asr_a_str} & {p_str} & {mean_iters} \\"
            )
        lines.append(r"\midrule")

    lines += [
        r"\multicolumn{6}{l}{\footnotesize * $p < 0.05$ (McNemar, continuity-corrected)} \\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines)


# ── Table 3: Canary Ablation ──────────────────────────────────────────────────

def gen_table_canary(rows: list[dict]) -> str:
    if not rows:
        return "% results_canary_ablation.csv not found — run run_canary_ablation.py first\n"

    # Index by (strategy, model)
    index: dict[tuple, dict] = {}
    for r in rows:
        index[(r["strategy"], r["model"])] = r

    strategies = ["inline", "prefix", "suffix", "xml", "comment", "header"]
    models     = ["llama3", "gemma3:12b"]
    model_labels = {"llama3": r"Llama-3-8B", "gemma3:12b": r"Gemma-3-12B"}

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Per-strategy canary placement leakage rates (95\% Wilson CI).",
        r"         Each cell: Complied/N, Rate [CI].}",
        r"\label{tab:canary-ablation}",
        r"\begin{tabular}{lcc}",
        r"\toprule",
        rf"\textbf{{Strategy}} & \textbf{{{model_labels['llama3']}}} & "
        rf"\textbf{{{model_labels['gemma3:12b']}}} \\",
        r"\midrule",
    ]

    for strategy in strategies:
        cells = []
        for model in models:
            r = index.get((strategy, model))
            if r is None:
                cells.append(r"\textemdash")
            else:
                leaked = int(r["leaked"])
                total  = int(r["total"])
                cells.append(
                    rf"{leaked}/{total} = " + ci_str(leaked, total)
                )
        lines.append(rf"\texttt{{{strategy}}} & {cells[0]} & {cells[1]} \\")

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\nGenerating LaTeX tables...\n")

    main_rows    = read_csv(Path("results.csv"))
    adaptive_rows = read_csv(Path("results_adaptive.csv"))
    canary_rows  = read_csv(Path("results_canary_ablation.csv"))

    tables = {
        "table_main_results.tex":  gen_table_main(main_rows),
        "table_rq4_adaptive.tex":  gen_table_rq4(adaptive_rows),
        "table_canary_ablation.tex": gen_table_canary(canary_rows),
    }

    for fname, content in tables.items():
        out_path = TABLES_DIR / fname
        out_path.write_text(content, encoding="utf-8")
        print(f"  [OK] {out_path}")

    print(f"\nAll tables written to {TABLES_DIR}/")
    print("Include in main.tex with: \\input{{tables/<filename>}}\n")


if __name__ == "__main__":
    main()
