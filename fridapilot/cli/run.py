"""fp run - AI Agent powered natural language task execution."""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Available analysis modes for --analyze
ANALYZE_MODES = ["vulns", "crypto", "protocol", "electron", "validation"]


def run_cmd(
    goal: str = typer.Argument(..., help="Natural language task description."),
    target: str = typer.Option("", "--target", "-t", help="Target process/package name."),
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
    output: str = typer.Option("", "--output", "-o", help="Save report to file."),
    max_retries: int = typer.Option(3, "--retries", help="Max retry rounds on failure."),
    report_format: str = typer.Option("md", "--format", "-f", help="Report format: md, json."),
    analyze: str = typer.Option("", "--analyze", "-a",
        help="AI analysis mode on collected data: vulns, crypto, protocol, electron, validation. "
             "Runs the task, then sends results through the specified analysis prompt template."),
) -> None:
    """AI Agent: plan, execute, observe, fix, report - all from natural language.

    Use --analyze to run a specialized AI analysis after execution:
      fp run "hook BCrypt APIs" --target app.exe --analyze crypto
      fp run "monitor IPC" --target app.exe --analyze protocol
      fp run "analyze Electron app" --target app.exe --analyze electron
    """
    try:
        import litellm  # noqa: F401
    except ImportError:
        console.print("[red]Error: LLM support requires 'litellm'. Install with:[/red]")
        console.print("  pip install fridapilot[agent]")
        raise typer.Exit(1)

    if analyze and analyze not in ANALYZE_MODES:
        console.print(f"[red]Unknown analyze mode '{analyze}'. Available: {', '.join(ANALYZE_MODES)}[/red]")
        raise typer.Exit(1)

    asyncio.run(_run_agent(goal, target, device, host, output, max_retries, report_format, analyze))


async def _run_agent(
    goal: str,
    target: str,
    device: str,
    host: str,
    output: str,
    max_retries: int,
    report_format: str,
    analyze: str = "",
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
        console.print("\n[bold cyan]Phase 3: Reflecting...[/bold cyan]")
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
    console.print("\n[bold cyan]Phase 4: Generating report...[/bold cyan]")
    report = generate_report(plan, results, ctx, format=report_format)

    if output:
        save_report(report, output)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(report)

    # Phase 5: AI Analysis (optional --analyze mode)
    if analyze:
        console.print(f"\n[bold cyan]Phase 5: AI Analysis ({analyze})...[/bold cyan]")
        await _run_analysis(analyze, plan, results, ctx, target, output)


# ── Analyze mode: prompt template → LLM ──────────────────────

# Map --analyze mode names to prompt template names
_ANALYZE_MAP = {
    "vulns": "analyze_vulns",
    "crypto": "analyze_crypto",
    "protocol": "analyze_protocol",
    "electron": "analyze_electron",
    "validation": "analyze_validation",
}


async def _run_analysis(
    mode: str,
    plan,
    results: list,
    ctx,
    target: str,
    output: str,
) -> None:
    """Run AI analysis on collected execution data using prompt templates."""
    import json as json_mod
    from litellm import acompletion
    from fridapilot.agent.prompts import get_prompt
    from fridapilot.agent.reporter import _safe_str

    template_name = _ANALYZE_MAP.get(mode, mode)

    # Build context from execution results
    step_results = {}
    for r in results:
        if r.success and r.result is not None:
            step_results[r.tool] = _safe_str(r.result, max_len=2000)

    messages_str = ""
    if ctx.messages:
        messages_str = json_mod.dumps(ctx.messages[:50], indent=2, default=str)

    # Collect strings and imports from binary analysis results if available
    strings_str = step_results.get("binary_analysis.find_strings", "N/A")
    imports_str = step_results.get("binary_analysis.analyze_pe", "N/A")
    disasm_str = step_results.get("binary_analysis.disassemble", "N/A")
    binary_info = step_results.get("binary_analysis.analyze_pe",
                   step_results.get("binary_analysis.analyze_elf", f"Target: {target}"))

    # Build template context based on mode
    try:
        if mode == "vulns":
            prompt = get_prompt(template_name,
                binary_info=binary_info, code=disasm_str,
                imports=imports_str, strings=strings_str)
        elif mode == "crypto":
            crypto_scan = step_results.get("crypto_reverse.scan_binary", "N/A")
            prompt = get_prompt(template_name,
                crypto_scan=crypto_scan, protection_level="See crypto_scan results",
                imports=imports_str, strings=strings_str, disassembly=disasm_str)
        elif mode == "protocol":
            functions = step_results.get("recon.enumerate_exports",
                        step_results.get("binary_analysis.analyze_go_binary", "N/A"))
            prompt = get_prompt(template_name,
                messages=messages_str, binary_info=binary_info,
                strings=strings_str, functions=functions)
        elif mode == "electron":
            modules = step_results.get("recon.enumerate_modules", "N/A")
            prompt = get_prompt(template_name,
                app_info=binary_info, modules=modules,
                ipc_channels=messages_str, security_config="See modules",
                strings=strings_str)
        elif mode == "validation":
            xrefs = step_results.get("binary_analysis.xrefs_to", "N/A")
            prompt = get_prompt(template_name,
                binary_info=binary_info, validation_functions=xrefs,
                disassembly=disasm_str, exit_codes="See strings",
                strings=strings_str)

        else:
            console.print(f"[red]Unknown analysis mode: {mode}[/red]")
            return
    except KeyError as e:
        console.print(f"[red]Prompt template error: {e}[/red]")
        return

    console.print(f"[dim]Sending {len(prompt)} chars to LLM for {mode} analysis...[/dim]")

    response = await acompletion(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user", "content": f"Analyze the data above for target: {target}. "
                                         f"Goal was: {plan.goal}. Provide actionable findings."},
        ],
        temperature=0.2,
    )

    analysis = response.choices[0].message.content
    console.print(Panel(analysis, title=f"AI Analysis: {mode}", border_style="cyan"))

    # Save analysis alongside report if output specified
    if output:
        analysis_path = output.rsplit(".", 1)[0] + f"_analysis_{mode}.md"
        from pathlib import Path
        Path(analysis_path).write_text(
            f"# FridaPilot AI Analysis: {mode}\n\n"
            f"Target: {target}\nGoal: {plan.goal}\n\n"
            f"---\n\n{analysis}\n",
            encoding="utf-8",
        )
        console.print(f"[green]Analysis saved to {analysis_path}[/green]")
