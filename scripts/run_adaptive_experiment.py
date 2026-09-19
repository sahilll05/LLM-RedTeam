"""
scripts/run_adaptive_experiment.py — RQ4: Static vs Adaptive attack comparison.

Research purpose: Closes the most critical gap — Table 2 in main.tex.
The current paper (Section 4.4) makes only qualitative claims about the
adaptive orchestrator. This script produces quantitative results:

  - For each payload, runs BOTH static (1 attempt) AND adaptive (up to N iterations).
  - Records: static_verdict, adaptive_verdict, iterations_to_success,
             dedup_rejections, chain_diversity (unique prompt ratio).
  - Computes: ASR_static, ASR_adaptive, McNemar chi2 and p-value.
  - Computes: mean iterations to compromise (for payloads that succeeded adaptively).

Output: results_adaptive.csv
Columns: model, suite, payload_id, static_verdict, adaptive_verdict,
         succeeded_static, succeeded_adaptive, iterations_to_success,
         dedup_rejections, chain_diversity

Usage:
    python -u scripts/run_adaptive_experiment.py
    python -u scripts/run_adaptive_experiment.py --models llama3 gemma3:12b
    python -u scripts/run_adaptive_experiment.py --suites jailbreak injection --iterations 5
"""

import sys
import csv
import json
import argparse
import time
import difflib
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.core import load_config, load_payloads, load_target
from engine.orchestrator_adaptive import AdaptiveOrchestrator, AdaptiveResult
from engine.scorer import ScoringEngine, VERDICT_COMPLIED, VERDICT_REFUSED

from scripts.compute_statistics import wilson_ci, mcnemar_test, summarize_binary

OUTPUT_CSV = Path("results_adaptive.csv")


def compute_chain_diversity(chain) -> float:
    """
    Measure prompt diversity in the adaptive chain.
    Returns fraction of unique prompts (after dedup normalization).
    A value of 1.0 = all prompts distinct; 0.0 = all identical.
    """
    prompts = [rec.prompt for rec in chain]
    if len(prompts) <= 1:
        return 1.0
    # Count pairwise distinct pairs
    n_unique = 1
    for i in range(1, len(prompts)):
        sim = difflib.SequenceMatcher(None, prompts[i], prompts[i-1]).ratio()
        if sim < 0.85:
            n_unique += 1
    return n_unique / len(prompts)


def run_single_static(target, scorer_config: dict, payload: dict) -> tuple[str, float]:
    """Run a single static (non-adaptive) attempt and return (verdict, score)."""
    scorer = ScoringEngine(scorer_config)
    try:
        response = target.send(
            prompt=payload["prompt"],
            system_prompt=None,
        )
        response = target.normalize_response(response)
    except Exception as exc:
        response = f"[TARGET ERROR: {exc}]"

    verdict, _, score = scorer.score(
        attack_prompt=payload["prompt"],
        response=response,
        success_indicators=payload.get("success_indicators", []),
        negative_indicators=payload.get("negative_indicators", []),
        suite=payload.get("category", ""),
    )
    return verdict, score


def run_experiment(
    models: list[str],
    suites: list[str],
    max_iterations: int,
    config_path: str,
) -> list[dict]:
    config = load_config(Path(config_path))
    all_results = []

    print(f"\n{'='*70}")
    print(f"  VAJRA — RQ4 Adaptive Experiment")
    print(f"  Models     : {', '.join(models)}")
    print(f"  Suites     : {', '.join(suites)}")
    print(f"  Max iterations (PAIR): {max_iterations}")
    print(f"{'='*70}\n")

    payloads = []
    for suite in suites:
        suite_payloads = load_payloads([suite])
        payloads.extend(suite_payloads)

    if not payloads:
        print("ERROR: No payloads loaded. Check suite names and YAML files.")
        sys.exit(1)

    print(f"  Total payloads: {len(payloads)} across {len(suites)} suite(s)")

    for model in models:
        print(f"\n\n{'='*70}")
        print(f"  Target model: {model}")
        print(f"{'='*70}\n")

        config.setdefault("target", {})["model"] = model
        target = load_target(config)

        # Attacker uses the same model (standard PAIR setup)
        attacker_cfg = {
            "type":     config["target"].get("type", "ollama"),
            "model":    model,
            "base_url": config["target"].get("base_url", "http://localhost:11434"),
            "timeout":  90,
        }
        scorer_config = config.get("scoring", {})

        orch = AdaptiveOrchestrator(
            target=target,
            attacker_config=attacker_cfg,
            scoring_config=scorer_config,
            max_iterations=max_iterations,
        )

        for payload in payloads:
            pid   = payload.get("id", "unknown")
            suite = payload.get("category", "unknown")

            print(f"  [{suite}] {pid}")

            # --- Static run ---
            static_verdict, static_score = run_single_static(
                target, scorer_config, payload
            )
            succeeded_static = (static_verdict == VERDICT_COMPLIED)
            print(f"    Static  -> {static_verdict}")

            # Small delay between static and adaptive to avoid rate-limiting
            time.sleep(0.3)

            # --- Adaptive run ---
            adaptive_result: AdaptiveResult = orch.run(payload)
            succeeded_adaptive = adaptive_result.succeeded
            adaptive_verdict   = adaptive_result.best_verdict
            iters_to_success   = (
                adaptive_result.best_iteration
                if succeeded_adaptive else max_iterations
            )
            # Count how many times the dedup engine rejected a rewrite
            dedup_rejections = sum(
                1 for rec in adaptive_result.chain
                if rec.refinement_prompt is not None
                and difflib.SequenceMatcher(
                    None, rec.prompt, payload["prompt"]
                ).ratio() > 0.85
            )
            chain_diversity = compute_chain_diversity(adaptive_result.chain)

            print(
                f"    Adaptive -> {adaptive_verdict} "
                f"(iter {adaptive_result.best_iteration}/{adaptive_result.iterations_run}, "
                f"diversity={chain_diversity:.2f})"
            )

            row = {
                "timestamp":          datetime.now().isoformat(),
                "model":              model,
                "suite":              suite,
                "payload_id":         pid,
                "static_verdict":     static_verdict,
                "adaptive_verdict":   adaptive_verdict,
                "succeeded_static":   int(succeeded_static),
                "succeeded_adaptive": int(succeeded_adaptive),
                "iterations_to_success": iters_to_success,
                "iterations_run":     adaptive_result.iterations_run,
                "dedup_rejections":   dedup_rejections,
                "chain_diversity":    round(chain_diversity, 3),
            }
            all_results.append(row)

    return all_results


def compute_and_print_statistics(results: list[dict]) -> None:
    """Compute and display McNemar test + ASR comparison per model/suite."""
    from collections import defaultdict

    print(f"\n{'='*70}")
    print(f"  RQ4 Statistical Analysis")
    print(f"{'='*70}")

    # Group by model + suite
    groups: dict[tuple, list] = defaultdict(list)
    for r in results:
        groups[(r["model"], r["suite"])].append(r)

    for (model, suite), group in sorted(groups.items()):
        static_outcomes   = [bool(r["succeeded_static"])   for r in group]
        adaptive_outcomes = [bool(r["succeeded_adaptive"]) for r in group]

        n = len(group)
        s_static   = sum(static_outcomes)
        s_adaptive = sum(adaptive_outcomes)

        # McNemar: b = static_fail + adaptive_succeed; c = static_succeed + adaptive_fail
        b = sum(
            1 for r in group
            if not r["succeeded_static"] and r["succeeded_adaptive"]
        )
        c = sum(
            1 for r in group
            if r["succeeded_static"] and not r["succeeded_adaptive"]
        )
        chi2, p_val = mcnemar_test(b, c)

        lo_s, hi_s = wilson_ci(s_static,   n)
        lo_a, hi_a = wilson_ci(s_adaptive, n)

        # Mean iterations to success (adaptive only, conditioned on success)
        successful = [r for r in group if r["succeeded_adaptive"]]
        mean_iters = (
            sum(r["iterations_to_success"] for r in successful) / len(successful)
            if successful else float("nan")
        )
        mean_diversity = sum(r["chain_diversity"] for r in group) / n if n else 0

        print(f"\n  {model} / {suite} (N={n})")
        print(
            f"    ASR Static  : {s_static}/{n} = {s_static/n*100:.1f}% "
            f"[{lo_s*100:.1f}%, {hi_s*100:.1f}%]"
        )
        print(
            f"    ASR Adaptive: {s_adaptive}/{n} = {s_adaptive/n*100:.1f}% "
            f"[{lo_a*100:.1f}%, {hi_a*100:.1f}%]"
        )
        print(f"    McNemar chi2={chi2:.3f}, p={p_val:.4f}", end="")
        print("  *** p<0.05 ***" if p_val < 0.05 else "  (not significant)")
        print(f"    Mean iters to success: {mean_iters:.1f}" if successful else "    No adaptive successes")
        print(f"    Mean chain diversity : {mean_diversity:.3f}")

    print(f"\n{'='*70}\n")


def write_csv(results: list[dict]) -> None:
    if not results:
        print("No results to write.")
        return

    fieldnames = list(results[0].keys())
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[OK] Adaptive results written to {OUTPUT_CSV}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run RQ4: static vs adaptive attack comparison."
    )
    parser.add_argument(
        "--models", nargs="+", default=["llama3", "gemma3:12b"],
        help="Models to test (default: llama3 gemma3:12b)"
    )
    parser.add_argument(
        "--suites", nargs="+", default=["jailbreak", "injection"],
        help="Payload suites (default: jailbreak injection)"
    )
    parser.add_argument(
        "--iterations", type=int, default=5,
        help="Max PAIR iterations per payload (default: 5)"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml"
    )
    args = parser.parse_args()

    results = run_experiment(
        models=args.models,
        suites=args.suites,
        max_iterations=args.iterations,
        config_path=args.config,
    )

    write_csv(results)
    compute_and_print_statistics(results)
