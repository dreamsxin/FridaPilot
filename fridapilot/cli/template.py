"""fp template - Use built-in Frida script templates."""

import typer
from rich.console import Console
from rich.syntax import Syntax

console = Console()


def template_cmd(
    name: str = typer.Argument(..., help="Template name (e.g. ssl-bypass, java-hook)."),
    list_all: bool = typer.Option(False, "--list", "-l", help="List available templates."),
    output: str = typer.Option("", "--output", "-o", help="Write script to file instead of stdout."),
    class_name: str = typer.Option("", "--class", "-c", help="Class name for hook templates."),
    method_name: str = typer.Option("", "--method", "-m", help="Method name for hook templates."),
    module_name: str = typer.Option("", "--module", help="Module name for native templates."),
) -> None:
    """Use built-in Frida script templates."""
    from fridapilot.tools.script_forge import list_templates, get_template

    if list_all:
        for t in list_templates():
            console.print(f"  {t}")
        return

    kwargs = {}
    if class_name:
        kwargs["class_name"] = class_name
    if method_name:
        kwargs["method_name"] = method_name
    if module_name:
        kwargs["module_name"] = module_name

    try:
        script = get_template(name, **kwargs)
    except ValueError as exc:
        # Unknown template or unsubstituted placeholders (M-C7)
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if output:
        from pathlib import Path
        Path(output).write_text(script, encoding="utf-8")
        console.print(f"[green]Script written to {output}[/green]")
    else:
        syntax = Syntax(script, "javascript", theme="monokai", line_numbers=True)
        console.print(syntax)
