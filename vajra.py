"""
VAJRA CLI — Entry point.
Vulnerability Analysis for Jailbreak & RAG Attacks

Usage:
    python vajra.py scan
    python vajra.py scan -s jailbreak -s injection --scoring llm_judge
    python vajra.py scan --target ollama --model hermes
    python vajra.py scan --output json
    python vajra.py list-runs
    python vajra.py report <run-id>
    python vajra.py validate
    python vajra.py ingest --count 200
"""
import sys
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

VERSION = "1.0.0"

BANNER_UNICODE = r"""
[bold cyan] █████   █████   █████████         █████ ███████████     █████████  [/]
[bold cyan]░░███   ░░███   ███░░░░░███       ░░███ ░░███░░░░░███   ███░░░░░███ [/]
[bold cyan] ░███    ░███  ░███    ░███        ░███  ░███    ░███  ░███    ░███ [/]
[bold cyan] ░███    ░███  ░███████████        ░███  ░██████████   ░███████████ [/]
[bold cyan] ░░███   ███   ░███░░░░░███        ░███  ░███░░░░░███  ░███░░░░░███ [/]
[bold cyan]  ░░░█████░    ░███    ░███  ███   ░███  ░███    ░███  ░███    ░███ [/]
[bold cyan]    ░░███      █████   █████░░████████   █████   █████ █████   █████[/]
[bold cyan]     ░░░      ░░░░░   ░░░░░  ░░░░░░░░   ░░░░░   ░░░░░ ░░░░░   ░░░░░[/]
[dim]  Vulnerability Analysis for Jailbreak & RAG Attacks[/]
  [dim]https://github.com/sahilll05/LLM-RedTeam[/]
"""

def _can_encode(s: str) -> bool:
    enc = getattr(sys.stdout, "encoding", "utf-8") or "utf-8"
    try:
        s.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False

BANNER_ASCII = r"""
 ____   ____    _       _  ____     _    
|_  _| |_  _|  / \    / \|_  _|  /_\   
  \ \   / /   / _ \  / _ \ \ \   //_\\  
   \ \ / /   / ___ \/ ___ \ \ \ //   \\ 
    \ ' /   /_/   \_\_/ \_/\_'_\/       \
     \_/                                 
  Vulnerability Analysis for Jailbreak & RAG Attacks
  v{version} -- https://github.com/sahilll05/LLM-RedTeam
"""

app = typer.Typer(
    name="vajra",
    help="[bold cyan]VAJRA[/] -- Vulnerability Analysis for Jailbreak & RAG Attacks.",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)
console = Console()




def print_banner():
    # Check if the terminal can render shade block characters used in the banner
    if _can_encode("\u2591"):
        console.print(BANNER_UNICODE)
    else:
        console.print(BANNER_ASCII.format(version=VERSION))


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show VAJRA version and exit.", is_eager=True),
):
    """VAJRA — Automated LLM red-teaming framework."""
    if version:
        console.print(f"[bold cyan]VAJRA[/] v{VERSION}")
        raise typer.Exit()
    # Banner is printed unconditionally at startup below.

@app.command()
def scan(
    config_path: Path = typer.Option(
        Path("./config.yaml"),
        "--config", "-c",
        help="Path to config.yaml",
        exists=True,
        readable=True,
    ),
    suite: Optional[list[str]] = typer.Option(
        None,
        "--suite", "-s",
        help="Attack suite(s) to run. Repeatable. "
             "Choices: jailbreak | injection | exfiltration | indirect_injection | multi_turn | wildjailbreak",
    ),
    target_type: Optional[str] = typer.Option(
        None,
        "--target", "-t",
        help="Override target type from config. Choices: ollama | openai | anthropic | http | rag",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model", "-m",
        help="Override model name (e.g. hermes, llama3, gpt-4o-mini).",
    ),
    scoring_mode: Optional[str] = typer.Option(
        None,
        "--scoring",
        help="Scoring mode override: heuristic | llm_judge | both",
    ),
    output_fmt: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output format override: html | json | both",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="List all payloads that would be sent, without making any requests.",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="Skip HTML report generation.",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Don't auto-open the HTML report in browser after scan.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Show each request/response pair in real-time during scan.",
    ),
):
    """
    Run a full red-team scan against the configured target.

    \b
    Examples:
      python vajra.py scan
      python vajra.py scan -s jailbreak -s injection
      python vajra.py scan --target ollama --model hermes --scoring llm_judge
      python vajra.py scan --suite wildjailbreak --dry-run
      python vajra.py scan --output json --no-open
    """
    from engine.core import load_config, run_scan
    from engine.report import print_cli_report, generate_html_report
    from engine.storage import ResultsStore
    import json

    config = load_config(config_path)

    # Apply CLI overrides
    if suite:
        config["suites"] = list(suite)
    if scoring_mode:
        config.setdefault("scoring", {})["mode"] = scoring_mode
    if target_type:
        config.setdefault("target", {})["type"] = target_type
    if model:
        config.setdefault("target", {})["model"] = model
    if output_fmt:
        config.setdefault("output", {})["format"] = output_fmt
    if verbose:
        config["verbose"] = True

    run_id, results = run_scan(config, dry_run=dry_run)

    if dry_run or not results:
        return

    # CLI report
    print_cli_report(results, run_id, config)

    output_cfg = config.get("output", {})
    reports_dir = Path(output_cfg.get("reports_dir", "./reports"))

    # JSON dump
    if output_cfg.get("format") in ("json", "both"):
        json_path = reports_dir / f"{run_id}.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps([vars(r) for r in results], indent=2),
            encoding="utf-8",
        )
        console.print(f"[dim]JSON saved -> {json_path}[/]")

    # HTML report
    if not no_html and output_cfg.get("format") in ("html", "both"):
        html_path = reports_dir / f"{run_id}.html"
        generate_html_report(results, run_id, config, html_path)
        console.print(f"[dim]HTML report -> [link={html_path.resolve().as_uri()}]{html_path}[/link][/]")

        should_open = (not no_open) and output_cfg.get("open_html", True)
        if should_open:
            webbrowser.open(html_path.resolve().as_uri())


@app.command("list-runs")
def list_runs():
    """List all past scan runs stored in the results database."""
    from engine.storage import ResultsStore

    store = ResultsStore()
    runs = store.list_runs()

    if not runs:
        console.print("[yellow]No runs found. Run a scan first with:[/] python vajra.py scan")
        return

    table = Table(
        title="Past Scan Runs",
        box=box.ROUNDED,
        header_style="bold magenta",
    )
    table.add_column("Run ID", style="cyan")
    table.add_column("Timestamp")
    table.add_column("Target Type")
    table.add_column("Model")
    table.add_column("Suites")

    for run in runs:
        import json
        suites = json.loads(run.get("suites", "[]"))
        table.add_row(
            run["id"],
            run["timestamp"][:19],
            run.get("target_type", "?"),
            run.get("model", "?"),
            ", ".join(suites),
        )

    console.print(table)


@app.command()
def report(
    run_id: str = typer.Argument(..., help="Run ID from 'list-runs'"),
    config_path: Path = typer.Option(
        Path("./config.yaml"),
        "--config", "-c",
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Don't open the report in browser."),
):
    """Regenerate the HTML report for a past run."""
    from engine.storage import ResultsStore
    from engine.report import print_cli_report, generate_html_report
    from engine.core import load_config
    import json
    import webbrowser

    store = ResultsStore()
    results = store.get_run_results(run_id)

    if not results:
        console.print(f"[red]No results found for run ID:[/] {run_id}")
        raise typer.Exit(1)

    config = load_config(config_path)
    print_cli_report(results, run_id, config)

    reports_dir = Path(config.get("output", {}).get("reports_dir", "./reports"))
    html_path = reports_dir / f"{run_id}.html"
    generate_html_report(results, run_id, config, html_path)
    console.print(f"[dim]HTML report -> {html_path}[/]")

    if not no_open:
        webbrowser.open(html_path.resolve().as_uri())


@app.command()
def validate(
    config_path: Path = typer.Option(
        Path("./config.yaml"),
        "--config", "-c",
        exists=True,
    ),
):
    """Validate config.yaml, payload files, and check target connectivity."""
    from engine.core import load_config, load_payloads, load_target

    console.print("\n[bold]Validating VAJRA configuration...[/]\n")
    errors = []

    # 1. Load config
    try:
        config = load_config(config_path)
        console.print(f"[green]OK[/] Config loaded from [cyan]{config_path}[/]")
    except Exception as e:
        console.print(f"[red]FAIL Config load failed:[/] {e}")
        raise typer.Exit(1)

    # 2. Validate required keys
    if "target" not in config:
        errors.append("Missing 'target' section in config.yaml")
    if "suites" not in config or not config["suites"]:
        errors.append("No 'suites' defined in config.yaml")

    # 3. Validate payload files
    suites = config.get("suites", [])
    payloads = load_payloads(suites)
    if payloads:
        console.print(f"[green]OK[/] {len(payloads)} payloads loaded across {len(suites)} suite(s)")
    else:
        errors.append("No payloads loaded — check suite names and payload YAML files")

    # 4. Target health check
    try:
        target = load_target(config)
        healthy = target.health_check()
        if healthy:
            console.print(f"[green]OK[/] Target reachable: {config['target']['type']} / {config['target'].get('model', '')}")
        else:
            errors.append("Target health check failed — is the target running?")
    except Exception as e:
        errors.append(f"Target init error: {e}")

    # Summary
    if errors:
        console.print("\n[bold red]Validation failed:[/]")
        for err in errors:
            console.print(f"  [red]FAIL[/] {err}")
        raise typer.Exit(1)
    else:
        console.print("\n[bold green]All checks passed. Ready to scan.[/]")


@app.command()
def ingest(
    dataset: str = typer.Option(
        "wildjailbreak",
        "--dataset", "-d",
        help="Dataset to ingest: wildjailbreak | jbb",
    ),
    count: int = typer.Option(
        100,
        "--count", "-n",
        help="Number of payloads to extract.",
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Re-download dataset even if cached locally.",
    ),
):
    """
    Download and ingest a Hugging Face research dataset into a VAJRA payload YAML.

    \b
    Examples:
      python vajra.py ingest
      python vajra.py ingest --dataset wildjailbreak --count 200
      python vajra.py ingest --force
    """
    import subprocess
    cmd = [sys.executable, "scripts/ingest_hf.py",
           "--dataset", dataset,
           "--count", str(count)]
    if force:
        cmd.append("--force")
    subprocess.run(cmd, check=True)


@app.command()
def adaptive(
    config_path: Path = typer.Option(
        Path("./config.yaml"),
        "--config", "-c",
        help="Path to config.yaml",
        exists=True,
        readable=True,
    ),
    suite: str = typer.Option(
        "jailbreak",
        "--suite", "-s",
        help="Payload suite to run adaptively: jailbreak | injection | exfiltration | wildjailbreak",
    ),
    count: int = typer.Option(
        5,
        "--count", "-n",
        help="Number of payloads to run adaptively (default: 5).",
    ),
    iterations: int = typer.Option(
        5,
        "--iterations", "-i",
        help="Max PAIR refinement iterations per payload (default: 5).",
    ),
    attacker_model: Optional[str] = typer.Option(
        None,
        "--attacker-model",
        help="Override attacker LLM model (e.g. llama3, mistral). Defaults to config judge model.",
    ),
):
    """
    Run adaptive (PAIR-style) attack loop on a payload suite.

    For each payload, if the target refuses, an attacker LLM automatically
    rewrites the prompt and retries. Logs the full iteration chain and final
    verdict for each payload.

    \\b
    Examples:
      python vajra.py adaptive
      python vajra.py adaptive -s injection --count 10 --iterations 5
      python vajra.py adaptive --attacker-model mistral
    """
    from engine.core import load_config, load_payloads, load_target
    from engine.orchestrator_adaptive import AdaptiveOrchestrator, AdaptiveResult

    config     = load_config(config_path)
    sys_prompt = config.get("target", {}).get("system_prompt")

    # Build attacker config — default to judge config, fallback to target config
    judge_cfg        = config.get("scoring", {}).get("judge", {})
    attacker_cfg = {
        "type":     judge_cfg.get("type", config["target"].get("type", "ollama")),
        "model":    attacker_model or judge_cfg.get("model", config["target"].get("model", "llama3")),
        "base_url": judge_cfg.get("base_url", config["target"].get("base_url", "http://localhost:11434")),
        "timeout":  60,
    }

    payloads = load_payloads([suite])
    if not payloads:
        console.print(f"[red]No payloads found for suite:[/] {suite}")
        raise typer.Exit(1)

    payloads = payloads[:count]
    target   = load_target(config)
    scoring  = config.get("scoring", {})

    orch = AdaptiveOrchestrator(
        target=target,
        attacker_config=attacker_cfg,
        scoring_config=scoring,
        max_iterations=iterations,
        system_prompt=sys_prompt,
    )

    console.print(f"\n[bold cyan]VAJRA[/] — Adaptive (PAIR) Mode")
    console.print(f"  Suite      : [bold]{suite}[/] ({len(payloads)} payloads)")
    console.print(f"  Iterations : [bold]{iterations}[/] per payload")
    console.print(f"  Attacker   : [bold]{attacker_cfg['model']}[/]\n")

    succeeded = 0
    for payload in payloads:
        pid = payload.get("id", "?")
        console.print(f"[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print(f"[bold]Payload:[/] {pid}")
        result: AdaptiveResult = orch.run(payload)

        for rec in result.chain:
            color = "red" if rec.verdict == "COMPLIED" else "green" if rec.verdict == "REFUSED" else "yellow"
            iter_label = f"iter {rec.iteration}"
            console.print(
                f"  [{color}]{iter_label:6}[/] [{color}]{rec.verdict:14}[/] "
                f"[dim]{rec.justification[:90]}[/]"
            )
            if rec.iteration > 0:
                console.print(f"  [dim]  rewrite: {rec.prompt[:100]}...[/]")

        status_color = "red" if result.succeeded else "green"
        console.print(f"\n  [bold]Result:[/] [{status_color}]{result.summary()}[/]\n")

        if result.succeeded:
            succeeded += 1

    console.print(f"[dim]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
    console.print(
        f"\n[bold]Adaptive summary:[/] {succeeded}/{len(payloads)} payloads bypassed "
        f"within {iterations} iterations."
    )


if __name__ == "__main__":
    # Ensure the banner prints first, regardless of what command or help flag is passed
    if "--version" not in sys.argv and "-v" not in sys.argv:
        print_banner()
    app()

