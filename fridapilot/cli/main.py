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
from fridapilot.cli.crypto import crypto_app
from fridapilot.cli.binary import binary_app
from fridapilot.cli.unpack import unpack_app
from fridapilot.cli.apk import apk_app

from fridapilot.cli.dbg import dbg_cmd
from fridapilot.cli.run import run_cmd

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
app.add_typer(crypto_app, name="crypto", help="Binary crypto analysis, key extraction, BCrypt hooking.")
app.add_typer(binary_app, name="binary", help="Static binary analysis: PE/ELF/Mach-O, disassembly, strings, Go analysis.")
app.add_typer(unpack_app, name="unpack", help="Packer detection, auto-unpacking, memory dump.")
app.add_typer(apk_app, name="apk", help="APK/DEX static analysis: manifest, components, protections.")

app.command("dbg")(dbg_cmd)
app.command("run")(run_cmd)


if __name__ == "__main__":
    app()
