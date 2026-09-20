"""
scripts/run_adaptive_experiment.py — RQ4: Static vs Adaptive attack comparison.

Research purpose: Table 2 in main.tex — quantitative static vs. PAIR adaptive ASR.

PAUSE/RESUME SUPPORT:
    Each completed payload is immediately written to:
        - results_adaptive.csv        (append mode — safe to read while running)
        - results_adaptive_checkpoint.json  (tracks which (model, suite, payload_id)
                                             combos are done)

    To PAUSE: press Ctrl+C at any time — progress up to the current payload is saved.
    To RESUME: simply re-run the same command — completed payloads are skipped.
    To RESTART from scratch: delete results_adaptive_checkpoint.json and results_adaptive.csv

Usage:
    # First run (or resume after pause):
    python -u scripts/run_adaptive_experiment.py

    # Custom models/suites:
    python -u scripts/run_adaptive_experiment.py --models llama3 gemma3:12b --suites jailbreak injection --iterations 5

    # Force full restart (ignore checkpoint):
    python -u scripts/run_adaptive_experiment.py --no-resume
"""

import sys
import csv
import json
import argparse
import signal
import time
import difflib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.core import load_config, load_payloads, load_target
from engine.orchestrator_adaptive import AdaptiveOrchestrator, AdaptiveResult
from engine.scorer import ScoringEngine, VERDICT_COMPLIED, VERDICT_REFUSED
from scripts.compute_statistics import wilson_ci, mcnemar_test

# ── File paths ────────────────────────────────────────────────────────────────
OUTPUT_CSV        = Path("results_adaptive.csv")
CHECKPOINT_FILE   = Path("results_adaptive_checkpoint.json")

# CSV columns (order matters — must stay consistent across resume runs)
FIELDNAMES = [
    "timestamp", "model", "suite", "payload_id",
    "static_verdict", "adaptive_verdict",
    "succeeded_static", "succeeded_adaptive",
    "iterations_to_success", "iterations_run",
    "dedup_rejections", "chain_diversity",
]

# ── Global flag for graceful shutdown ─────────────────────────────────────────
_shutdown_requested = False

def _handle_sigint(sig, frame):
    global _shutdown_requested
    print("\n\n[PAUSE] Ctrl+C received — finishing current payload then saving checkpoint...")
    _shutdown_requested = True

signal.signal(signal.SIGINT, _handle_sigint)


# ── Checkpoint helpers ────────────────────────────────────────────────────────

def load_checkpoint() -> set:
    """Return a set of (model, suite, payload_id) tuples already completed."""
    if not CHECKPOINT_FILE.exists():
        return set()
    try:
        data = json.loads(CHECKPOINT_FILE.read_text(encoding="utf-8"))
        done = set(tuple(entry) for entry in data.get("completed", []))
        print(f"  [RESUME] Checkpoint loaded — {len(done)} payload(s) already completed.")
        return done
    except Exception as e:
        print(f"  [WARN] Could not load checkpoint ({e}) — starting fresh.")
        return set()


def save_checkpoint(completed: set) -> None:
    """Persist the completed set to disk."""
    data = {"completed": [list(t) for t in sorted(completed)],
            "updated_at": datetime.now().isoformat()}
    CHECKPOINT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def append_row_to_csv(row: dict) -> None:
    """Append a single result row immediately — safe across restarts."""
    file_exists = OUTPUT_CSV.exists()
    with OUTPUT_CSV.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ── Experiment helpers ────────────────────────────────────────────────────────

def compute_chain_diversity(chain) -> float:
    prompts = [rec.prompt for rec in chain]
    if len(prompts) <= 1:
        return 1.0
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
        response = target.send(prompt=payload["prompt"], system_prompt=None)
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


# ── Main experiment loop ──────────────────────────────────────────────────────

def run_experiment(
    models: list[str],
    suites: list[str],
    max_iterations: int,
    config_path: str,
    resume: bool = True,
) -> None:
    """
    Run the full adaptive experiment with checkpoint support.
    Results are written incrementally — safe to pause/resume.
    """
    global _shutdown_requested

    config   = load_config(Path(config_path))
    completed = load_checkpoint() if resume else set()

    # Load payloads
    payloads = []
    for suite in suites:
        suite_payloads = load_payloads([suite])
        payloads.extend(suite_payloads)

    if not payloads:
        print("ERROR: No payloads loaded. Check suite names and YAML files.")
        sys.exit(1)

    total_jobs = len(models) * len(payloads)
    done_jobs  = sum(
        1 for m in models for p in payloads
        if (m, p.get("category",""), p.get("id","")) in completed
    )

    print(f"\n{'='*70}")
    print(f"  VAJRA -- RQ4 Adaptive Experiment (Resumable)")
    print(f"  Models          : {', '.join(models)}")
    print(f"  Suites          : {', '.join(suites)}")
    print(f"  Max PAIR iters  : {max_iterations}")
    print(f"  Total payloads  : {len(payloads)} x {len(models)} models = {total_jobs} jobs")
    print(f"  Already done    : {done_jobs} / {total_jobs}")
    print(f"  Remaining       : {total_jobs - done_jobs}")
    print(f"  Output CSV      : {OUTPUT_CSV}")
    print(f"  Checkpoint      : {CHECKPOINT_FILE}")
    print(f"{'='*70}")
    print(f"  >> Press Ctrl+C at any time to pause safely <<")
    print()

    for model in models:
        if _shutdown_requested:
            break

        print(f"\n{'='*70}")
        print(f"  Target model: {model}")
        print(f"{'='*70}\n")

        config.setdefault("target", {})["model"] = model
        target = load_target(config)

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

        for idx, payload in enumerate(payloads, 1):
            if _shutdown_requested:
                break

            pid   = payload.get("id", f"payload_{idx}")
            suite = payload.get("category", "unknown")
            job_key = (model, suite, pid)

            # Skip if already completed (checkpoint)
            if job_key in completed:
                print(f"  [SKIP] {model} / {suite} / {pid} (already in checkpoint)")
                continue

            done_jobs += 1
            pct = done_jobs / total_jobs * 100
            print(f"  [{done_jobs:02d}/{total_jobs}] ({pct:.0f}%) [{suite}] {pid}")

            # --- Static run ---
            try:
                static_verdict, _ = run_single_static(target, scorer_config, payload)
            except Exception as exc:
                static_verdict = VERDICT_REFUSED
                print(f"    Static  -> ERROR: {exc}")
            succeeded_static = (static_verdict == VERDICT_COMPLIED)
            print(f"    Static  -> {static_verdict}")

            time.sleep(0.2)

            # --- Adaptive run ---
            try:
                adaptive_result: AdaptiveResult = orch.run(payload)
            except Exception as exc:
                print(f"    Adaptive -> ERROR: {exc}")
                # Count as non-success so we don't lose the row
                adaptive_result = type("R", (), {
                    "succeeded": False,
                    "best_verdict": VERDICT_REFUSED,
                    "best_iteration": max_iterations,
                    "iterations_run": max_iterations,
                    "chain": [],
                })()

            succeeded_adaptive = adaptive_result.succeeded
            adaptive_verdict   = adaptive_result.best_verdict
            iters_to_success   = (
                adaptive_result.best_iteration if succeeded_adaptive else max_iterations
            )
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

            # --- Write immediately (survive restarts) ---
            row = {
                "timestamp":             datetime.now().isoformat(),
                "model":                 model,
                "suite":                 suite,
                "payload_id":            pid,
                "static_verdict":        static_verdict,
                "adaptive_verdict":      adaptive_verdict,
                "succeeded_static":      int(succeeded_static),
                "succeeded_adaptive":    int(succeeded_adaptive),
                "iterations_to_success": iters_to_success,
                "iterations_run":        adaptive_result.iterations_run,
                "dedup_rejections":      dedup_rejections,
                "chain_diversity":       round(chain_diversity, 3),
            }
            append_row_to_csv(row)
            completed.add(job_key)
            save_checkpoint(completed)

    # ── Done (or paused) ─────────────────────────────────────────────────────
    remaining = total_jobs - len([
        k for m in models for p in payloads
        if (k := (m, p.get("category",""), p.get("id",""))) in completed
    ])

    if _shutdown_requested:
        print(f"\n[PAUSED] Progress saved. {remaining} job(s) remaining.")
        print(f"  Resume by re-running the same command.")
        print(f"  Checkpoint: {CHECKPOINT_FILE}")
    else:
        print(f"\n[DONE] All {total_jobs} jobs completed.")
        CHECKPOINT_FILE.unlink(missing_ok=True)  # Clean up checkpoint on full completion
        print(f"  Results: {OUTPUT_CSV}")


# ── Statistics printer ────────────────────────────────────────────────────────

def compute_and_print_statistics() -> None:
    if not OUTPUT_CSV.exists():
        print("No results CSV found — cannot compute statistics.")
        return

    rows = list(csv.DictReader(OUTPUT_CSV.open(encoding="utf-8")))
    if not rows:
        return

    print(f"\n{'='*70}")
    print(f"  RQ4 Statistical Analysis (from {OUTPUT_CSV})")
    print(f"{'='*70}")

    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        groups[(r["model"], r["suite"])].append(r)

    for (model, suite), group in sorted(groups.items()):
        n         = len(group)
        s_static  = sum(int(r["succeeded_static"])   for r in group)
        s_adaptive= sum(int(r["succeeded_adaptive"]) for r in group)

        b = sum(1 for r in group if not int(r["succeeded_static"]) and int(r["succeeded_adaptive"]))
        c = sum(1 for r in group if int(r["succeeded_static"]) and not int(r["succeeded_adaptive"]))
        chi2, p_val = mcnemar_test(b, c)

        lo_s, hi_s = wilson_ci(s_static,   n)
        lo_a, hi_a = wilson_ci(s_adaptive, n)

        successful = [r for r in group if int(r["succeeded_adaptive"])]
        mean_iters = (
            sum(int(r["iterations_to_success"]) for r in successful) / len(successful)
            if successful else float("nan")
        )
        mean_diversity = sum(float(r["chain_diversity"]) for r in group) / n

        print(f"\n  {model} / {suite}  (N={n})")
        print(f"    ASR Static  : {s_static}/{n} = {s_static/n*100:.1f}% [{lo_s*100:.1f}%, {hi_s*100:.1f}%]")
        print(f"    ASR Adaptive: {s_adaptive}/{n} = {s_adaptive/n*100:.1f}% [{lo_a*100:.1f}%, {hi_a*100:.1f}%]")
        sig = "  *** p<0.05 ***" if p_val < 0.05 else "  (not significant)"
        print(f"    McNemar chi2={chi2:.3f}, p={p_val:.4f}{sig}")
        if successful:
            print(f"    Mean iters to success : {mean_iters:.1f}")
        else:
            print(f"    Mean iters to success : N/A (no adaptive successes)")
        print(f"    Mean chain diversity  : {mean_diversity:.3f}")

    print(f"\n{'='*70}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run RQ4 adaptive experiment (resumable via checkpoint)."
    )
    parser.add_argument("--models",     nargs="+", default=["llama3", "gemma3:12b"])
    parser.add_argument("--suites",     nargs="+", default=["jailbreak", "injection"])
    parser.add_argument("--iterations", type=int,  default=5)
    parser.add_argument("--config",     default="config.yaml")
    parser.add_argument(
        "--no-resume", action="store_true",
        help="Ignore checkpoint and restart from scratch"
    )
    parser.add_argument(
        "--stats-only", action="store_true",
        help="Just print statistics from existing CSV without running any experiments"
    )
    args = parser.parse_args()

    if args.stats_only:
        compute_and_print_statistics()
        sys.exit(0)

    if args.no_resume:
        OUTPUT_CSV.unlink(missing_ok=True)
        CHECKPOINT_FILE.unlink(missing_ok=True)
        print("[INFO] Cleared checkpoint and CSV — starting fresh.")

    run_experiment(
        models=args.models,
        suites=args.suites,
        max_iterations=args.iterations,
        config_path=args.config,
        resume=not args.no_resume,
    )

    compute_and_print_statistics()
