"""
LLM-RedTeam CLI — Entry point.

Usage:
    python cli.py scan
    python cli.py scan --config ./config.yaml --suite jailbreak --suite injection
    python cli.py list-runs
    python cli.py report <run-id>
    python cli.py validate
"""
import sys
import webbrowser
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(
    name="llm-redteam",
    help="[bold cyan]LLM-RedTeam[/] — Automated security testing framework for LLM applications.",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


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
        help="Override suites from config (can be repeated). "
             "Options: jailbreak, injection, exfiltration, indirect_injection, multi_turn",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Load and list payloads without sending any requests.",
    ),
    no_html: bool = typer.Option(
        False,
        "--no-html",
        help="Skip HTML report generation.",
    ),
    no_open: bool = typer.Option(
        False,
        "--no-open",
        help="Don't auto-open the HTML report in browser.",
    ),
    scoring_mode: Optional[str] = typer.Option(
        None,
        "--scoring",
        help="Override scoring mode: heuristic | llm_judge | both",
    ),
):
    """Run a full red-team scan against the configured target."""
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
        console.print("[yellow]No runs found. Run a scan first with:[/] python cli.py scan")
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
    no_open: bool = typer.Option(False, "--no-open"),
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
    """Validate config.yaml and payload files, and check target connectivity."""
    from engine.core import load_config, load_payloads, load_target

    console.print("\n[bold]Validating LLM-RedTeam configuration...[/]\n")
    errors = []

    # 1. Load config
    try:
        config = load_config(config_path)
        console.print(f"[green]✓[/] Config loaded from [cyan]{config_path}[/]")
    except Exception as e:
        console.print(f"[red]✗ Config load failed:[/] {e}")
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
        console.print(f"[green]✓[/] {len(payloads)} payloads loaded across {len(suites)} suite(s)")
    else:
        errors.append("No payloads loaded — check suite names and payload YAML files")

    # 4. Target health check
    try:
        target = load_target(config)
        healthy = target.health_check()
        if healthy:
            console.print(f"[green]✓[/] Target reachable: {config['target']['type']} / {config['target'].get('model', '')}")
        else:
            errors.append(f"Target health check failed — is the target running?")
    except Exception as e:
        errors.append(f"Target init error: {e}")

    # Summary
    if errors:
        console.print("\n[bold red]Validation failed:[/]")
        for err in errors:
            console.print(f"  [red]✗[/] {err}")
        raise typer.Exit(1)
    else:
        console.print("\n[bold green]✓ All checks passed. Ready to scan.[/]")


if __name__ == "__main__":
    app()
