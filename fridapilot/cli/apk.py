"""fp apk - APK/DEX static analysis (offline, no device needed)."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
apk_app = typer.Typer(no_args_is_help=True)


@apk_app.command("analyze")
def analyze_cmd(
    apk: str = typer.Argument(..., help="Path to the .apk file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
    limit: int = typer.Option(20, "--limit", "-n", help="Max components/permissions to print."),
) -> None:
    """Manifest, components, native libs, signing info and protection indicators."""
    import json as json_mod
    from dataclasses import asdict

    from fridapilot.tools.apk_analysis import analyze_apk

    info = analyze_apk(apk)

    if json_output:
        console.print(json_mod.dumps(asdict(info), indent=2, ensure_ascii=False))
        return

    console.print(Panel(
        f"{info.filepath}\n"
        f"Package: [bold]{info.package_name or '(unknown)'}[/bold]\n"
        f"Version: {info.version_name or '?'} ({info.version_code})  "
        f"SDK: min={info.min_sdk or '?'} target={info.target_sdk or '?'}\n"
        f"DEX files: {info.dex_count}  Native code: {'yes' if info.has_native_code else 'no'}  "
        f"Signed: {'yes' if info.signing_info.get('signed') else 'no'}",
        title="APK Analysis",
    ))

    def _list(title: str, items: list[str]) -> None:
        if not items:
            return
        console.print(f"[bold]{title}[/bold] ({len(items)})")
        for s in items[:limit]:
            console.print(f"  {s}")
        if len(items) > limit:
            console.print(f"  [dim]... {len(items) - limit} more[/dim]")

    _list("Permissions", info.permissions)
    _list("Activities", info.activities)
    _list("Services", info.services)
    _list("Receivers", info.receivers)
    _list("Providers", info.providers)
    _list("Native libs", info.native_libs)

    if info.protections:
        table = Table(title="Protection Indicators")
        table.add_column("Category", style="cyan")
        table.add_column("Indicator")
        table.add_column("Description")
        table.add_column("Matched string", overflow="fold")
        for p in info.protections:
            table.add_row(p["category"], p["indicator"], p["description"], p.get("match", ""))
        console.print(table)
    else:
        console.print("[green]No protection indicators found.[/green]")


@apk_app.command("dex")
def dex_cmd(
    dex: str = typer.Argument(..., help="Path to a .dex file (e.g. extracted classes.dex)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
    limit: int = typer.Option(30, "--limit", "-n", help="Max classes/strings to print."),
) -> None:
    """DEX header, class/method/string counts, class names and a string sample."""
    import json as json_mod
    from dataclasses import asdict

    from fridapilot.tools.apk_analysis import analyze_dex

    info = analyze_dex(dex)

    if json_output:
        console.print(json_mod.dumps(asdict(info), indent=2, ensure_ascii=False))
        return

    if not info.magic:
        console.print(f"[red]Not a DEX file: {dex}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"{info.filepath}\n"
        f"Version: {info.version}  Checksum: 0x{info.checksum:08x}  Size: {info.file_size}\n"
        f"Classes: {info.class_count}  Methods: {info.method_count}  Strings: {info.string_count}",
        title="DEX Analysis",
    ))
    for s in info.classes[:limit]:
        console.print(f"  {s}")
    if len(info.classes) > limit:
        console.print(f"  [dim]... {len(info.classes) - limit} more classes[/dim]")


@apk_app.command("protections")
def protections_cmd(
    apk: str = typer.Argument(..., help="Path to the .apk file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Root / SSL-pinning / Frida / emulator detection and packer indicators."""
    import json as json_mod

    from fridapilot.tools.apk_analysis import detect_protections

    hits = detect_protections(apk)

    if json_output:
        console.print(json_mod.dumps(hits, indent=2, ensure_ascii=False))
        return

    if not hits:
        console.print("[green]No protection indicators found.[/green]")
        return

    table = Table(title="Protection Indicators")
    table.add_column("Category", style="cyan")
    table.add_column("Indicator")
    table.add_column("Description")
    table.add_column("Matched string", overflow="fold")
    for p in hits:
        table.add_row(p["category"], p["indicator"], p["description"], p.get("match", ""))
    console.print(table)
