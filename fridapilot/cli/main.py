"""FridaPilot CLI - Main entry point.

Register all subcommands via Typer.
"""

import sys

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

from fridapilot.cli.apk import apk_app
from fridapilot.cli.attach import attach_cmd, detach_cmd, resume_cmd, spawn_cmd
from fridapilot.cli.binary import binary_app
from fridapilot.cli.bypass import bypass_app
from fridapilot.cli.crypto import crypto_app
from fridapilot.cli.dbg import dbg_cmd
from fridapilot.cli.disasm import disasm_app
from fridapilot.cli.inject import inject_cmd
from fridapilot.cli.observe import observe_cmd
from fridapilot.cli.ps import ps_cmd
from fridapilot.cli.recon import recon_app
from fridapilot.cli.report import report_cmd
from fridapilot.cli.run import run_cmd
from fridapilot.cli.target import target_app
from fridapilot.cli.template import template_cmd
from fridapilot.cli.unpack import unpack_app

app.command("ps")(ps_cmd)
app.command("attach")(attach_cmd)
app.command("spawn")(spawn_cmd)
app.command("resume")(resume_cmd)
app.command("detach")(detach_cmd)
app.command("inject")(inject_cmd)
app.add_typer(recon_app, name="recon", help="Enumerate modules, classes, methods, exports.")
app.command("template")(template_cmd)
app.command("observe")(observe_cmd)
app.add_typer(bypass_app, name="bypass", help="SSL pinning, anti-debug, anti-Frida bypasses.")
app.command("report")(report_cmd)
app.add_typer(crypto_app, name="crypto", help="Binary crypto analysis, key extraction, BCrypt hooking.")
app.add_typer(binary_app, name="binary", help="Static binary analysis: PE/ELF/Mach-O, disassembly, strings, Go analysis.")
app.add_typer(disasm_app, name="disasm",
              help="Annotated disassembly listing: address + section + function.")
app.add_typer(unpack_app, name="unpack", help="Packer detection, auto-unpacking, memory dump.")
app.add_typer(apk_app, name="apk", help="APK/DEX static analysis: manifest, components, protections.")

app.command("dbg")(dbg_cmd)
app.command("run")(run_cmd)
app.add_typer(target_app, name="target",
              help="Name long image paths once and use them as @alias.")


def expand_target_aliases(argv: list[str]) -> list[str]:
    """Replace every ``@alias`` token with the path it stands for.

    Done on argv, before Click sees it, because the alias has to survive the
    per-command file-existence guards as well as the tool call - and because the problem
    it solves is a command *line* problem: one Chromium path is 90 characters, and the
    workflow that drove this was abandoning the CLI for hardcoded scripts after shell
    lines kept getting truncated.

    Only a token that is exactly ``@`` plus a defined alias is rewritten. An unknown
    alias is left alone so a genuine argument like ``--grep @dolphin`` keeps working, and
    the substitution is announced on stderr so it is never silently wrong.
    """
    from fridapilot.tools.targets import list_targets

    if not any(a.startswith("@") and len(a) > 1 for a in argv):
        return argv
    targets = list_targets()
    if not targets:
        return argv
    out = []
    for arg in argv:
        name = arg[1:] if arg.startswith("@") else ""
        if name in targets:
            print(f"[fp] @{name} -> {targets[name]}", file=sys.stderr)
            out.append(targets[name])
        else:
            out.append(arg)
    return out


def run_cli() -> None:
    """Console-script entry point: expand @aliases, then run the app."""
    sys.argv[1:] = expand_target_aliases(sys.argv[1:])
    app()


if __name__ == "__main__":
    run_cli()
