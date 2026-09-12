"""FridaPilot CLI - Main entry point.

Register all subcommands via Typer.
"""

import typer

from fridapilot import __version__

app = typer.Typer(
    name="fp",
    help="FridaPilot - AI Agent for Frida automation & dynamic instrumentation.",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"FridaPilot v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """FridaPilot CLI - Frida automation toolkit."""


# ── Subcommands ──────────────────────────────────────────────

from fridapilot.cli.ps import ps_cmd
from fridapilot.cli.attach import attach_cmd, spawn_cmd, detach_cmd
from fridapilot.cli.inject import inject_cmd
from fridapilot.cli.recon import recon_app
from fridapilot.cli.template import template_cmd
from fridapilot.cli.observe import observe_cmd
from fridapilot.cli.bypass import bypass_app
from fridapilot.cli.report import report_cmd

app.command("ps")(ps_cmd)
app.command("attach")(attach_cmd)
app.command("spawn")(spawn_cmd)
app.command("detach")(detach_cmd)
app.command("inject")(inject_cmd)
app.add_typer(recon_app, name="recon", help="Enumerate modules, classes, methods, exports.")
app.command("template")(template_cmd)
app.command("observe")(observe_cmd)
app.add_typer(bypass_app, name="bypass", help="SSL pinning, anti-debug, anti-Frida bypasses.")
app.command("report")(report_cmd)


if __name__ == "__main__":
    app()
