"""fp target - short aliases for long image paths.

Presentation only; the store lives in ``fridapilot.tools.targets``.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from fridapilot.tools.targets import TARGETS_PATH, add_target, list_targets, remove_target

target_app = typer.Typer(no_args_is_help=True)

console = Console()
err_console = Console(stderr=True)


@target_app.command("add")
def add_cmd(
    name: str = typer.Argument(..., help="Alias, e.g. anty."),
    path: str = typer.Argument(..., help="Path to the image the alias stands for."),
) -> None:
    """Store an alias for an image path, usable everywhere as @name.

    The path is resolved and checked now: an alias recorded from one working directory
    and used from another would otherwise point somewhere else, and a typo would only
    surface as a missing file in every later command.
    """
    try:
        stored = add_target(name, path)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[green]@{name}[/green] -> {stored}")


@target_app.command("list")
def list_cmd() -> None:
    """Show every alias and where it points."""
    targets = list_targets()
    if not targets:
        console.print(f"[dim]no targets defined ({TARGETS_PATH})[/dim]")
        return
    table = Table(header_style="bold")
    table.add_column("Alias", style="green", no_wrap=True)
    table.add_column("Path")
    table.add_column("Exists", no_wrap=True)
    for name, path in sorted(targets.items()):
        exists = Path(path).is_file()
        table.add_row(f"@{name}", path,
                      "yes" if exists else "[red]missing[/red]")
    console.print(table)
    console.print(f"[dim]{TARGETS_PATH}[/dim]")


@target_app.command("remove")
def remove_cmd(
    name: str = typer.Argument(..., help="Alias to forget."),
) -> None:
    """Forget an alias. The file it pointed at is untouched."""
    if remove_target(name):
        console.print(f"removed @{name}")
    else:
        err_console.print(f"[red]no such target: @{name}[/red]")
        raise typer.Exit(1)
