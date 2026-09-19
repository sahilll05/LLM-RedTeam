"""
scripts/compute_statistics.py — Research-grade statistical utilities for VAJRA.

Functions
---------
wilson_ci(successes, n, z=1.96)
    Wilson score 95% confidence interval for a proportion.
    Standard for small-N binomial rates in ML/security papers.

mcnemar_test(b, c)
    McNemar's chi-squared test for paired binary outcomes.
    Used to compare static vs adaptive attack success (RQ4).

cohens_kappa(y1, y2)
    Cohen's kappa for inter-rater agreement.
    Used for judge model sensitivity ablation (RQ5).

bootstrap_ci(data, stat_fn, n_bootstrap=10000, alpha=0.05, seed=42)
    Non-parametric bootstrapped confidence interval.
    Used when parametric assumptions are questionable.

format_pct_ci(successes, n)
    Human-readable "{rate:.1f}% [{lo:.1f}%, {hi:.1f}%]" string for LaTeX.
"""

from __future__ import annotations
import math
import random
from typing import Callable


# ── Wilson Score Interval ────────────────────────────────────────────────────

def wilson_ci(
    successes: int,
    n: int,
    z: float = 1.96,
) -> tuple[float, float]:
    """
    Wilson score 95% confidence interval for a proportion p = successes/n.

    Preferred over normal approximation for small n or extreme proportions
    (near 0 or 1), which is typical in security evaluation experiments.

    Parameters
    ----------
    successes : int  Number of positive outcomes.
    n         : int  Total trials.
    z         : float  z-score for desired confidence level (default 1.96 = 95%).

    Returns
    -------
    (lower, upper) as fractions in [0, 1].
    """
    if n == 0:
        return (0.0, 1.0)

    p_hat = successes / n
    z2 = z * z

    denominator = 1 + z2 / n
    centre = (p_hat + z2 / (2 * n)) / denominator
    margin = (z / denominator) * math.sqrt(
        p_hat * (1 - p_hat) / n + z2 / (4 * n * n)
    )

    lower = max(0.0, centre - margin)
    upper = min(1.0, centre + margin)
    return lower, upper


def format_pct_ci(successes: int, n: int, z: float = 1.96) -> str:
    """
    Return a formatted string: 'rate% [lo%, hi%]' suitable for LaTeX tables.
    Rates are multiplied by 100 for percentage display.
    """
    if n == 0:
        return "N/A"
    lo, hi = wilson_ci(successes, n, z)
    rate = (successes / n) * 100
    return f"{rate:.1f}% [{lo*100:.1f}\\%, {hi*100:.1f}\\%]"


# ── McNemar's Test ────────────────────────────────────────────────────────────

def mcnemar_test(b: int, c: int, continuity_correction: bool = True) -> tuple[float, float]:
    """
    McNemar's test for paired binary data.

    Used to test if the proportion of successes differs significantly
    between two conditions (e.g., static vs adaptive attacks on the
    same set of payloads). This is the appropriate test when the same
    payload is tested under both conditions.

    Contingency table (for reference):
        +----------------------------+
        |         Adaptive           |
        |         Fail  |  Succeed   |
    Static Fail  |  a    |    b      |
    Static Succ  |  c    |    d      |
        +----------------------------+

    Parameters
    ----------
    b : int  Discordant pairs: static failed, adaptive succeeded.
    c : int  Discordant pairs: static succeeded, adaptive failed.
    continuity_correction : bool
        Apply Edwards' continuity correction (recommended for b+c < 25).

    Returns
    -------
    (chi2_statistic, p_value)  — p < 0.05 indicates significant difference.
    """
    import math

    if b + c == 0:
        return (0.0, 1.0)

    if continuity_correction:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c)
    else:
        chi2 = (b - c) ** 2 / (b + c)

    # p-value from chi-squared distribution with 1 degree of freedom
    # Using the regularized incomplete gamma function approximation
    # (avoid scipy dependency — use math module's lgamma)
    p = _chi2_sf(chi2, df=1)
    return chi2, p


def _chi2_sf(x: float, df: int) -> float:
    """
    Survival function (1 - CDF) for chi-squared distribution.
    Uses regularized incomplete gamma: P(chi2 > x) = Q(df/2, x/2).
    Pure Python implementation to avoid scipy dependency.
    """
    if x <= 0:
        return 1.0
    # For df=1: P(X > x) = erfc(sqrt(x/2))
    if df == 1:
        return math.erfc(math.sqrt(x / 2))
    # General: use upper incomplete gamma / gamma
    # Q(a, x) = 1 - gamma_inc_lower(a, x) / gamma(a)
    a = df / 2.0
    return _upper_regularized_gamma(a, x / 2.0)


def _upper_regularized_gamma(a: float, x: float, max_iter: int = 200) -> float:
    """
    Upper regularized incomplete gamma function Q(a, x).
    Uses continued fraction representation for x > a + 1, series for x <= a + 1.
    """
    if x < 0:
        return 1.0
    if x == 0:
        return 1.0

    log_gamma_a = math.lgamma(a)

    if x <= a + 1:
        # Series expansion for lower gamma, then Q = 1 - P
        term = 1.0 / a
        s = term
        for n in range(1, max_iter):
            term *= x / (a + n)
            s += term
            if abs(term) < 1e-12 * abs(s):
                break
        p = math.exp(-x + a * math.log(x) - log_gamma_a) * s
        return max(0.0, min(1.0, 1.0 - p))
    else:
        # Continued fraction for upper gamma
        f = 1.0
        c = 1.0 / 1e-30
        d = 1.0 / (x - a + 1)
        h = d
        for n in range(1, max_iter):
            an = -n * (n - a)
            bn = x - a + 2 * n + 1
            d = 1.0 / (an * d + bn)
            c = bn + an / c
            delta = c * d
            h *= delta
            if abs(delta - 1.0) < 1e-12:
                break
        return max(0.0, min(1.0, math.exp(-x + a * math.log(x) - log_gamma_a) * h))


# ── Cohen's Kappa ─────────────────────────────────────────────────────────────

def cohens_kappa(y1: list, y2: list) -> float:
    """
    Cohen's kappa: inter-rater agreement beyond chance.

    Kappa interpretation (Landis & Koch 1977):
      < 0     : No agreement
      0–0.20  : Slight
      0.21–0.40 : Fair
      0.41–0.60 : Moderate
      0.61–0.80 : Substantial
      0.81–1.0  : Almost perfect

    Parameters
    ----------
    y1, y2 : list  Parallel lists of categorical labels from two raters/judges.

    Returns
    -------
    kappa : float in [-1, 1].
    """
    assert len(y1) == len(y2), "Label lists must be the same length"
    n = len(y1)
    if n == 0:
        return 0.0

    categories = list(set(y1) | set(y2))
    # Observed agreement
    p_o = sum(a == b for a, b in zip(y1, y2)) / n

    # Expected agreement by chance
    p_e = 0.0
    for cat in categories:
        p1 = sum(a == cat for a in y1) / n
        p2 = sum(b == cat for b in y2) / n
        p_e += p1 * p2

    if p_e >= 1.0:
        return 1.0

    return (p_o - p_e) / (1.0 - p_e)


# ── Bootstrap CI ─────────────────────────────────────────────────────────────

def bootstrap_ci(
    data: list,
    stat_fn: Callable[[list], float],
    n_bootstrap: int = 10_000,
    alpha: float = 0.05,
    seed: int = 42,
) -> tuple[float, float, float]:
    """
    Non-parametric bootstrap confidence interval.

    Parameters
    ----------
    data        : list  Observed data points (e.g., list of 0/1 outcomes).
    stat_fn     : callable  Function mapping a sample to a scalar statistic.
    n_bootstrap : int  Number of bootstrap resamples.
    alpha       : float  Significance level (default 0.05 → 95% CI).
    seed        : int  Random seed for reproducibility.

    Returns
    -------
    (point_estimate, lower_bound, upper_bound)
    """
    rng = random.Random(seed)
    n = len(data)
    point = stat_fn(data)

    bootstrap_stats = []
    for _ in range(n_bootstrap):
        sample = [rng.choice(data) for _ in range(n)]
        bootstrap_stats.append(stat_fn(sample))

    bootstrap_stats.sort()
    lo_idx = int((alpha / 2) * n_bootstrap)
    hi_idx = int((1 - alpha / 2) * n_bootstrap) - 1

    return (
        point,
        bootstrap_stats[lo_idx],
        bootstrap_stats[hi_idx],
    )


# ── Convenience: Summarize a binary results list ──────────────────────────────

def summarize_binary(
    results: list[bool],
    label: str = "",
) -> dict:
    """
    Compute all standard statistics for a list of binary outcomes.

    Parameters
    ----------
    results : list[bool]  True = success/complied, False = refused.
    label   : str  Optional label for display.

    Returns
    -------
    dict with keys: n, successes, rate, wilson_lo, wilson_hi,
                    bootstrap_lo, bootstrap_hi
    """
    n = len(results)
    successes = sum(results)
    rate = successes / n if n > 0 else 0.0
    w_lo, w_hi = wilson_ci(successes, n)
    b_point, b_lo, b_hi = bootstrap_ci(
        results,
        lambda s: sum(s) / len(s) if s else 0.0,
    )

    return {
        "label":         label,
        "n":             n,
        "successes":     successes,
        "rate":          rate,
        "rate_pct":      round(rate * 100, 2),
        "wilson_lo":     round(w_lo * 100, 2),
        "wilson_hi":     round(w_hi * 100, 2),
        "bootstrap_lo":  round(b_lo * 100, 2),
        "bootstrap_hi":  round(b_hi * 100, 2),
    }


# ── CLI: print stats for the current results.csv ─────────────────────────────

if __name__ == "__main__":
    import csv
    import sys
    from pathlib import Path

    csv_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results.csv")
    if not csv_path.exists():
        print(f"File not found: {csv_path}")
        sys.exit(1)

    rows = list(csv.DictReader(csv_path.open()))
    print(f"\n{'='*70}")
    print(f"  Statistical Summary — {csv_path.name}")
    print(f"{'='*70}")

    # Group by model + suite
    from collections import defaultdict
    groups: dict[tuple, list] = defaultdict(list)
    for row in rows:
        key = (row.get("Model", "?"), row.get("Suite", "?"))
        groups[key].append(row)

    for (model, suite), group in sorted(groups.items()):
        # Use the latest run per group
        latest = sorted(group, key=lambda r: r.get("Timestamp", ""))[-1]
        total   = int(latest.get("Total", 0))
        complied = int(latest.get("Complied", 0))
        if total == 0:
            continue

        lo, hi = wilson_ci(complied, total)
        rate_pct = complied / total * 100
        print(
            f"  {model:<20} {suite:<30} "
            f"{complied}/{total} = {rate_pct:5.1f}% "
            f"[95% CI: {lo*100:.1f}%–{hi*100:.1f}%]"
        )

    print(f"{'='*70}\n")
