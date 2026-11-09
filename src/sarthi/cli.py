from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from sarthi.mcp.server import run_server

app = typer.Typer(
    name="sarthi",
    help="Production engineering standards for AI coding agents.",
    no_args_is_help=True,
)
install_app = typer.Typer(name="install", help="Install client integrations.")
uninstall_app = typer.Typer(name="uninstall", help="Uninstall client integrations.")
app.add_typer(install_app)
app.add_typer(uninstall_app)

console = Console()


def version_callback(value: bool) -> None:
    if value:
        from sarthi import __version__

        console.print(f"[bold cyan]sarthi[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show Sarthi version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Production engineering standards for AI coding agents."""


@app.command()
def init(
    path: str = typer.Argument(".", help="Path to project root."),
    force: bool = typer.Option(False, "--force", "-f", help="Force refresh even if fingerprint is unchanged."),
) -> None:
    """Detect stack, scaffold .sarthi/project.yaml, and generate cached context."""
    from sarthi.core.config import ConfigLoader
    from sarthi.core.context import ContextBuilder

    root_path = Path(path).resolve()
    console.print(f"[bold cyan]Initializing Sarthi in:[/bold cyan] {root_path}")

    builder = ContextBuilder(root_path)
    profile, config, version, refreshed = builder.build_context(force=force)

    # Ensure config file exists
    loader = ConfigLoader(root_path)
    if not loader.exists():
        cfg = loader.create_default(
            project_name=root_path.name,
            profile=profile.suggested_profile,
        )
        saved = loader.save(cfg)
        console.print(f"[green]Created config file:[/green] {saved.relative_to(root_path)}")

    console.print(f"[bold green]Initialized context v{version}![/bold green] (Refreshed: {refreshed})")
    console.print(f"Detected Languages: {', '.join(profile.languages) or 'None'}")
    console.print(f"Package Managers: {', '.join(profile.package_managers) or 'None'}")
    console.print(f"Test Frameworks: {', '.join(profile.test_frameworks) or 'None'}")
    console.print(f"Detected Layers: {', '.join(profile.layer_names()) or 'None'}")
    console.print(f"Suggested Profile: [bold]{profile.suggested_profile or 'None'}[/bold]")


@app.command()
def context(
    path: str = typer.Argument(".", help="Path to project root."),
) -> None:
    """Print the human-readable project context."""
    from sarthi.core.context import ContextBuilder

    root_path = Path(path).resolve()
    builder = ContextBuilder(root_path)
    profile, config, version, _ = builder.build_context(force=False)

    context_file = root_path / ".sarthi" / "cache" / "context.md"
    if context_file.is_file():
        console.print(context_file.read_text(encoding="utf-8"))
    else:
        console.print(f"# Project Context (v{version})\nLanguages: {', '.join(profile.languages)}")


@app.command()
def standards(
    path: str = typer.Argument(".", help="Path to project root."),
    task: str = typer.Option(..., "--task", "-t", help="Description of task to retrieve standards for."),
    task_type: str = typer.Option("feature", "--type", help="Task type (feature, bugfix, refactor, new-project)."),
    layers: Optional[str] = typer.Option(None, "--layers", "-l", help="Comma-separated layer overrides."),
    max_rules: int = typer.Option(15, "--max-rules", "-m", help="Maximum rules to return."),
) -> None:
    """Display the ranked, budgeted standards an agent would receive for a task."""
    from sarthi.core.context import ContextBuilder
    from sarthi.core.rules import RuleLoader, RuleSelector

    root_path = Path(path).resolve()
    builder = ContextBuilder(root_path)
    profile, config, _, _ = builder.build_context(force=False)

    layer_list = [lyr.strip() for lyr in layers.split(",")] if layers else None
    loader = RuleLoader()
    all_rules = loader.load_all_rules()
    selector = RuleSelector(all_rules, loader.load_profiles())

    active_layers = selector.resolve_active_layers(
        detected_layers=profile.layer_names(),
        config=config,
        explicit_layers=layer_list,
    )

    selected_rules, truncated, hint = selector.select_rules(
        active_layers=active_layers,
        task=task,
        task_type=task_type,
        config=config,
        max_rules=max_rules,
    )

    console.print(f"\n[bold]Task:[/bold] {task} ([cyan]{task_type}[/cyan])")
    console.print(f"[bold]Active Layers:[/bold] {', '.join(active_layers)}")
    console.print(f"[bold]Standards Returned:[/bold] {len(selected_rules)} (Truncated: {truncated})\n")

    table = Table(show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("ID", width=15)
    table.add_column("Layer", width=14)
    table.add_column("Rule Title & Statement")

    for r in selected_rules:
        sev_color = "red" if r.severity.value in ("critical", "high") else "yellow"
        body = f"[bold]{r.title}[/bold]\n{r.rule.strip()}"
        table.add_row(f"[{sev_color}]{r.severity.value.upper()}[/{sev_color}]", r.id, r.layer, body)

    console.print(table)

    # Query and display Unified ECC Knowledge & Skills
    from sarthi.core.resources.models import ResourceType
    from sarthi.core.resources.selector import UnifiedResourceSelector

    unified_selector = UnifiedResourceSelector()
    unified_res, trace, conflict_report = unified_selector.select_resources(
        active_layers=active_layers,
        task=task,
        task_type=task_type,
        config=config,
        max_tokens=3000,
    )
    ecc_skills = [r for r in unified_res if r.type == ResourceType.SKILL]
    if ecc_skills:
        console.print(f"[bold cyan]Upstream ECC Procedural Skills Available:[/bold cyan] {len(ecc_skills)}\n")
        skill_table = Table(show_lines=True)
        skill_table.add_column("Tier", width=8)
        skill_table.add_column("ID", width=32)
        skill_table.add_column("Skill Name & Description")
        for s in ecc_skills:
            skill_table.add_row("Tier 6", s.id, f"[bold]{s.name}[/bold]\n{s.description}")
        console.print(skill_table)

    if hint:
        console.print(f"[dim]{hint}[/dim]\n")


@app.command()
def verify(
    path: str = typer.Argument(".", help="Path to project root."),
    all_files: bool = typer.Option(False, "--all", "-a", help="Verify all files instead of just changed files."),
    timeout: float = typer.Option(60.0, "--timeout", help="Wall-clock budget in seconds."),
    as_json: bool = typer.Option(False, "--json", help="Output report as structured JSON."),
) -> None:
    """Execute the deterministic verification loop and output findings."""
    from sarthi.core.verify.reporter import Reporter
    from sarthi.core.verify.verifier import Verifier

    root_path = Path(path).resolve()
    scope = "all" if all_files else "changed"

    verifier = Verifier(root_path)
    report = verifier.verify(scope=scope, timeout=timeout)

    if as_json:
        console.print(json.dumps(report.model_dump(mode="json"), indent=2))
    else:
        reporter = Reporter(console)
        reporter.print_report(report)

    if report.status == "failed":
        sys.exit(1)


@install_app.command(name="antigravity")
def install_antigravity(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing configuration."),
    no_scaffold: bool = typer.Option(False, "--no-scaffold", help="Do not create project.yaml in current directory."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing files to disk."),
) -> None:
    """One-time setup for Google Antigravity (MCP server + global Core Contract)."""
    from sarthi.adapters.antigravity.adapter import AntigravityAdapter
    from sarthi.adapters.base import InstallOpts

    adapter = AntigravityAdapter()
    opts = InstallOpts(
        workspace_root=Path.cwd(),
        force=force,
        with_scaffold=not no_scaffold,
        dry_run=dry_run,
    )
    res = adapter.install(opts)
    if res.success:
        console.print(f"[bold green]Success:[/bold green] {res.message}")
    else:
        console.print(f"[bold red]Failed:[/bold red] {res.message}")
        sys.exit(1)


@uninstall_app.command(name="antigravity")
def uninstall_antigravity() -> None:
    """Revert changes installed for Google Antigravity."""
    from sarthi.adapters.antigravity.adapter import AntigravityAdapter

    adapter = AntigravityAdapter()
    res = adapter.uninstall()
    if res.success:
        console.print(f"[bold green]Success:[/bold green] {res.message}")
    else:
        console.print(f"[bold red]Failed:[/bold red] {res.message}")
        sys.exit(1)


@app.command()
def doctor() -> None:
    """Diagnose environment, installed tools, and client configuration."""
    from sarthi.adapters.antigravity.adapter import AntigravityAdapter

    console.print("[bold cyan]Running Sarthi Environment Diagnostics...[/bold cyan]\n")

    adapter = AntigravityAdapter()
    checks = adapter.doctor()

    table = Table(show_lines=True)
    table.add_column("Status", width=8)
    table.add_column("Check", width=30)
    table.add_column("Details")

    all_passed = True
    for c in checks:
        if c.passed:
            status = "[bold green]PASS[/bold green]"
            msg = c.message
        else:
            status = "[bold yellow]WARN[/bold yellow]"
            msg = f"{c.message}\n[dim]Hint: {c.hint}[/dim]" if c.hint else c.message
            all_passed = False
        table.add_row(status, c.name, msg)

    console.print(table)
    if all_passed:
        console.print("\n[bold green]All core diagnostics passed cleanly![/bold green]")
    else:
        console.print("\n[yellow]Some optional tools or client configurations can be improved (see hints above).[/yellow]")


@app.command(name="lint-standards")
def lint_standards(
    summary: bool = typer.Option(False, "--summary", "-s", help="Print layer rules and machine verifiers summary table."),
) -> None:
    """Validate standards library against schema, uniqueness, and references."""
    from sarthi.core.standards_linter import StandardsLinter

    console.print("[bold cyan]Linting Sarthi Standards Library...[/bold cyan]")
    linter = StandardsLinter()
    errors = linter.lint()

    if errors:
        console.print(f"\n[bold red]Found {len(errors)} standards error(s):[/bold red]")
        for err in errors:
            console.print(f"  [red]x[/red] {err}")
        sys.exit(1)
    else:
        console.print("[bold green]All standards, profiles, and verifiers passed schema validation![/bold green]")

    if summary:
        console.print(f"\n{linter.generate_summary_table()}\n")


def _is_interactive_tty() -> bool:
    """Returns True if standard input is attached to an interactive terminal."""
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


@app.command()
def approve(
    path: str = typer.Argument(".", help="Path to project root."),
) -> None:
    """Approve test commands (custom or default) for project execution."""
    if not _is_interactive_tty():
        console.print(
            "[bold red]Error:[/bold red] `sarthi approve` requires an interactive terminal (TTY).\n"
            "Non-interactive input and piped stdin are refused to prevent automated agent self-approval."
        )
        raise typer.Exit(code=1)

    root_path = Path(path).resolve()
    from sarthi.core.config import ConfigLoader
    from sarthi.core.models import ProjectConfig, RunContext
    from sarthi.core.verify.runners.tests import TestRunner
    from sarthi.core.verify.trust import CommandTrustError, CommandTrustManager

    loader = ConfigLoader(root_path)
    config = loader.load() if loader.exists() else ProjectConfig()

    trust_mgr = CommandTrustManager()

    if config.verify.commands:
        commands_to_approve = dict(config.verify.commands)
    else:
        ctx = RunContext(project_root=root_path, config=config)
        detected = TestRunner(trust_mgr)._detect_default_command(ctx)
        if detected:
            commands_to_approve = {"test": " ".join(detected)}
        else:
            commands_to_approve = {"test": "pytest -q"}

    console.print(f"[bold cyan]Project:[/bold cyan] {root_path}")
    console.print("[bold cyan]Commands to approve:[/bold cyan]")
    for k, v in commands_to_approve.items():
        console.print(f"  [cyan]{k}[/cyan]: {v}")
    console.print(
        "[dim yellow]Notice: Approval covers this command set, not repository contents. "
        "Allowlisted test tools execute repository code by design.[/dim yellow]"
    )

    confirmed = typer.confirm("Do you approve executing these commands on your machine?", default=False)
    if not confirmed:
        console.print("[yellow]Approval cancelled by user.[/yellow]")
        raise typer.Exit(code=1)

    try:
        cmd_hash = trust_mgr.approve(root_path, commands_to_approve)
        console.print(f"[bold green]Successfully approved test command(s) for:[/bold green] {root_path}")
        console.print(f"[dim]Approval hash: {cmd_hash[:16]}...[/dim]")
        for k, v in commands_to_approve.items():
            console.print(f"  [cyan]{k}[/cyan]: {v}")
    except CommandTrustError as e:
        console.print(f"[bold red]Cannot approve commands:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command(name="revoke-approval")
def revoke_approval(
    path: str = typer.Argument(".", help="Path to project root."),
) -> None:
    """Revoke approval for custom verify commands in a project."""
    from sarthi.core.verify.trust import CommandTrustManager

    root_path = Path(path).resolve()
    trust_mgr = CommandTrustManager()
    if trust_mgr.revoke(root_path):
        console.print(f"[green]Revoked approval for:[/green] {root_path}")
    else:
        console.print(f"[yellow]No existing approval found for:[/yellow] {root_path}")


@app.command()
def serve() -> None:
    """Start the Sarthi MCP server over stdio."""
    run_server()


@app.command(name="eval")
def run_eval(
    scenario: str = typer.Option("FASTAPI-RATELIMIT-01", "--scenario", "-s", help="Benchmark scenario ID."),
    provider: str = typer.Option("mock", "--provider", "-p", help="Provider adapter: mock, anthropic, gemini, openai."),
    model: str = typer.Option("", "--model", "-m", help="Model name identifier."),
    cost_cap: float = typer.Option(0.50, "--cost-cap", help="Cost cap in USD."),
    output_dir: str = typer.Option("eval_results", "--output-dir", "-o", help="Output directory for reports."),
) -> None:
    """Run Layer 4 Live AI coding agent comparative evaluation."""
    from sarthi.eval.config import LiveEvalConfig
    from sarthi.eval.runner import LiveAIEvaluationRunner

    cfg = LiveEvalConfig(
        enabled=True,
        provider=provider,
        model_name=model or ("mock-model" if provider == "mock" else ""),
        cost_cap_usd=cost_cap,
        output_dir=Path(output_dir),
    )

    runner = LiveAIEvaluationRunner(config=cfg)
    console.print(f"[bold cyan]Starting Layer 4 Evaluation:[/bold cyan] scenario=[yellow]{scenario}[/yellow], provider=[green]{provider}[/green]")

    result = runner.run_live_scenario(scenario=scenario)
    if result.get("status") == "skipped":
        console.print(f"[bold red]Evaluation skipped:[/bold red] {result.get('reason')}")
        raise typer.Exit(code=1)

    console.print("[bold green]Evaluation Completed![/bold green]")
    console.print(f"  Findings Reduction: [bold cyan]{result.get('findings_reduction', 0):+d}[/bold cyan]")
    console.print(f"  Sarthi Passed Cleanly: {'[green]YES[/green]' if result.get('sarthi_passed_cleanly') else '[red]NO[/red]'}")
    console.print(f"  Baseline Passed Cleanly: {'[green]YES[/green]' if result.get('baseline_passed_cleanly') else '[red]NO[/red]'}")
    console.print(f"  Markdown Report: {result.get('markdown_report_path')}")
    console.print(f"  JSON Report: {result.get('json_report_path')}")


if __name__ == "__main__":
    app()
