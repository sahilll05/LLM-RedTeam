"""
scripts/generate_figures.py — Generate publication-quality figures for main.tex.

Generates:
  - research/figures/results_main.pdf   (bar chart with Wilson CI error bars)
  - research/figures/canary_heatmap.pdf (strategy x model heatmap)

Requires: matplotlib, numpy
Install:  pip install matplotlib numpy

Usage:
    python scripts/generate_figures.py
"""

import sys
import csv
from pathlib import Path

# Allow importing stats utils
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIGURES_DIR = Path("research") / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend for server-side rendering
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("WARNING: matplotlib/numpy not installed. Run: pip install matplotlib numpy")
    print("Generating placeholder .tex files instead.\n")

from scripts.compute_statistics import wilson_ci


def load_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return list(csv.DictReader(path.open(encoding="utf-8")))


def gen_results_bar_chart(rows: list[dict]) -> None:
    """
    Figure 4 (main results): Grouped bar chart with Wilson CI error bars.
    X-axis: Suite (jailbreak, injection, exfiltration)
    Groups: Llama-3-8B vs Gemma-3-12B
    Y-axis: ASR (%)
    Error bars: Wilson 95% CI
    """
    if not HAS_MPL:
        return

    # Filter to Phase-1 benchmark single-suite runs, deduplicated
    benchmark = {}
    for r in rows:
        if "+" in r.get("Suite", ""):
            continue
        if r.get("Model", "") not in ("llama3", "gemma3:12b"):
            continue
        if not r.get("Timestamp", "").startswith("2026-09-10"):
            continue
        key = (r["Model"], r["Suite"])
        if key not in benchmark or r["Timestamp"] > benchmark[key]["Timestamp"]:
            benchmark[key] = r

    suites  = ["jailbreak", "injection", "exfiltration"]
    models  = ["llama3", "gemma3:12b"]
    labels  = {"llama3": "Llama-3-8B", "gemma3:12b": "Gemma-3-12B"}
    colors  = {"llama3": "#2196F3", "gemma3:12b": "#FF5722"}

    x     = np.arange(len(suites))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7, 4.5))

    for i, model in enumerate(models):
        rates, lo_errs, hi_errs = [], [], []
        for suite in suites:
            r = benchmark.get((model, suite))
            if r:
                n = int(r["Total"])
                c = int(r["Complied"])
                rate = c / n * 100 if n > 0 else 0
                lo, hi = wilson_ci(c, n)
                rates.append(rate)
                lo_errs.append(rate - lo * 100)
                hi_errs.append(hi * 100 - rate)
            else:
                rates.append(0)
                lo_errs.append(0)
                hi_errs.append(0)

        offset = (i - 0.5) * width
        bars = ax.bar(
            x + offset, rates, width,
            label=labels[model],
            color=colors[model],
            alpha=0.85,
            zorder=3,
        )
        ax.errorbar(
            x + offset, rates,
            yerr=[lo_errs, hi_errs],
            fmt="none",
            color="black",
            capsize=4,
            linewidth=1.2,
            zorder=4,
        )

    ax.set_xlabel("Attack Suite", fontsize=12)
    ax.set_ylabel("Attack Success Rate (%)", fontsize=12)
    ax.set_title("VAJRA Static Benchmark — ASR with 95% Wilson CI", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels([s.capitalize() for s in suites], fontsize=11)
    ax.set_ylim(0, 105)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10)

    plt.tight_layout()
    out = FIGURES_DIR / "results_main.pdf"
    plt.savefig(out, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"  [OK] {out}")


def gen_canary_heatmap(canary_rows: list[dict]) -> None:
    """
    Figure for canary ablation: heatmap of strategy x model leakage rates.
    """
    if not HAS_MPL or not canary_rows:
        return

    strategies = ["inline", "prefix", "suffix", "xml", "comment", "header"]
    models     = ["llama3", "gemma3:12b"]
    labels     = {"llama3": "Llama-3-8B", "gemma3:12b": "Gemma-3-12B"}

    # Build matrix
    index = {}
    for r in canary_rows:
        index[(r["strategy"], r["model"])] = float(r.get("rate_pct", 0))

    matrix = np.array([
        [index.get((s, m), 0.0) for m in models]
        for s in strategies
    ])

    fig, ax = plt.subplots(figsize=(5, 5))
    im = ax.imshow(matrix, cmap="RdYlGn_r", vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([labels[m] for m in models], fontsize=10)
    ax.set_yticks(range(len(strategies)))
    ax.set_yticklabels(strategies, fontsize=10, fontfamily="monospace")

    # Annotate cells
    for i in range(len(strategies)):
        for j in range(len(models)):
            val = matrix[i, j]
            color = "white" if val > 60 else "black"
            ax.text(j, i, f"{val:.0f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color=color)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Leakage Rate (%)", fontsize=10)
    ax.set_title("Canary Placement Strategy Leakage Rates", fontsize=12, fontweight="bold")

    plt.tight_layout()
    out = FIGURES_DIR / "canary_heatmap.pdf"
    plt.savefig(out, bbox_inches="tight", dpi=300)
    plt.close()
    print(f"  [OK] {out}")


def main() -> None:
    print("\nGenerating figures...\n")

    main_rows   = load_csv(Path("results.csv"))
    canary_rows = load_csv(Path("results_canary_ablation.csv"))

    gen_results_bar_chart(main_rows)
    gen_canary_heatmap(canary_rows)

    if not HAS_MPL:
        print("Install matplotlib to generate PDF figures:")
        print("  pip install matplotlib numpy")
    else:
        print(f"\nFigures written to {FIGURES_DIR}/")


if __name__ == "__main__":
    main()
