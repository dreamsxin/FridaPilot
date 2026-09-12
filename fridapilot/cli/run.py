"""fp run - AI Agent powered natural language task execution."""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def run_cmd(
    goal: str = typer.Argument(..., help="Natural language task description."),
    target: str = typer.Option("", "--target", "-t", help="Target process/package name."),
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
    output: str = typer.Option("", "--output", "-o", help="Save report to file."),
    max_retries: int = typer.Option(3, "--retries", help="Max retry rounds on failure."),
    report_format: str = typer.Option("md", "--format", "-f", help="Report format: md, json."),
) -> None:
    """AI Agent: plan, execute, observe, fix, report - all from natural language."""
    try:
        import litellm  # noqa: F401
    except ImportError:
        console.print("[red]Error: LLM support requires 'litellm'. Install with:[/red]")
        console.print("  pip install fridapilot[agent]")
        raise typer.Exit(1)

    asyncio.run(_run_agent(goal, target, device, host, output, max_retries, report_format))


async def _run_agent(
    goal: str,
    target: str,
    device: str,
    host: str,
    output: str,
    max_retries: int,
    report_format: str,
) -> None:
    """Async agent execution loop."""
    from fridapilot.agent.planner import create_plan
    from fridapilot.agent.executor import execute_plan
    from fridapilot.agent.reflector import reflect_and_fix
    from fridapilot.agent.reporter import generate_report, save_report

    console.print(Panel(f"[bold]{goal}[/bold]", title="FridaPilot Agent", subtitle=f"target={target} device={device}"))

    # Phase 1: Plan
    console.print("\n[bold cyan]Phase 1: Planning...[/bold cyan]")
    plan = await create_plan(goal, target, device)

    step_table = Table(title="Execution Plan")
    step_table.add_column("#", style="cyan", width=4)
    step_table.add_column("Tool", style="green")
    step_table.add_column("Description")
    step_table.add_column("Depends", style="dim")
    for step in plan.steps:
        step_table.add_row(
            str(step.id), step.tool, step.description,
            ",".join(str(d) for d in step.depends_on) or "-",
        )
    console.print(step_table)

    # Phase 2: Execute + Reflect loop
    for attempt in range(1, max_retries + 1):
        console.print(f"\n[bold cyan]Phase 2: Executing (attempt {attempt}/{max_retries})...[/bold cyan]")

        ctx, results = execute_plan(plan)

        # Print step results
        for r in results:
            status = "[green]OK[/green]" if r.success else "[red]FAIL[/red]"
            console.print(f"  Step {r.step_id} ({r.tool}): {status} ({r.duration:.2f}s)")
            if not r.success:
                console.print(f"    Error: {r.error}")

        # Phase 3: Reflect
        console.print(f"\n[bold cyan]Phase 3: Reflecting...[/bold cyan]")
        diag = await reflect_and_fix(plan, results, ctx, max_retries=max_retries)

        if diag.success:
            console.print("[green bold]Goal achieved![/green bold]")
            break

        # Show diagnosis
        for suggestion in diag.suggestions:
            console.print(f"  [yellow]{suggestion}[/yellow]")

        if diag.fix_plan and attempt < max_retries:
            console.print("[yellow]Applying fix plan...[/yellow]")
            plan = diag.fix_plan
        else:
            console.print(f"[red]Failed after {attempt} attempts.[/red]")
            break
    else:
        console.print(f"[red]Max retries ({max_retries}) reached.[/red]")

    # Phase 4: Report
    console.print(f"\n[bold cyan]Phase 4: Generating report...[/bold cyan]")
    report = generate_report(plan, results, ctx, format=report_format)

    if output:
        save_report(report, output)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(report)
