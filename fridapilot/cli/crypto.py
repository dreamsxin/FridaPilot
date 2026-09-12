"""fp crypto - Binary encryption analysis and crypto reverse engineering."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
crypto_app = typer.Typer(no_args_is_help=True)


@crypto_app.command("scan")
def crypto_scan(
    binary: str = typer.Argument(..., help="Path to PE/ELF binary file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Scan a binary for crypto indicators, S-Box, imports, and protection level."""
    import json as json_mod
    from fridapilot.tools.crypto_reverse import scan_binary

    result = scan_binary(binary)

    if json_output:
        out = {
            "filepath": result.filepath,
            "is_pe": result.is_pe,
            "is_64bit": result.is_64bit,
            "is_dotnet": result.is_dotnet,
            "sbox_offsets": [f"0x{o:x}" for o in result.sbox_offsets],
            "crypto_imports": result.crypto_imports,
            "crypto_strings_count": len(result.crypto_strings),
            "hex_key_candidates": result.hex_key_candidates[:10],
            "protection_level": {
                "level": result.protection_level.level,
                "label": result.protection_level.label,
                "confidence": result.protection_level.confidence,
                "evidence": result.protection_level.evidence,
            } if result.protection_level else None,
        }
        console.print(json_mod.dumps(out, indent=2))
        return

    # Rich output
    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="Crypto Scan"))

    info_table = Table(show_header=False)
    info_table.add_row("Type", "PE" if result.is_pe else "ELF/Other")
    info_table.add_row("Arch", "x64" if result.is_64bit else "x86/Unknown")
    info_table.add_row(".NET", "Yes (use dnSpy)" if result.is_dotnet else "No")
    info_table.add_row("AES S-Box", f"{len(result.sbox_offsets)} found" if result.sbox_offsets
                        else "[yellow]Not found[/yellow]")
    console.print(info_table)

    if result.crypto_imports:
        console.print("\n[bold]Crypto API Imports:[/bold]")
        for api in result.crypto_imports:
            console.print(f"  {api}")

    if result.crypto_strings:
        console.print(f"\n[bold]Crypto Strings:[/bold] {len(result.crypto_strings)} found")
        for s in result.crypto_strings[:20]:
            console.print(f"  {s}")

    if result.hex_key_candidates:
        console.print(f"\n[bold]Hex Key Candidates:[/bold]")
        for h in result.hex_key_candidates[:5]:
            console.print(f"  {h}")

    if result.protection_level:
        pl = result.protection_level
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(pl.confidence, "white")
        console.print(f"\n[bold]Protection Level: L{pl.level} - {pl.label}[/bold] [{color}]({pl.confidence})[/{color}]")
        for e in pl.evidence:
            console.print(f"  {e}")


@crypto_app.command("hook-bcrypt")
def crypto_hook_bcrypt(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Hook Windows BCrypt APIs to capture encryption keys at runtime."""
    import time
    from fridapilot.models.schemas import DeviceType
    from fridapilot.tools.crypto_reverse import get_bcrypt_hook_script
    from fridapilot.tools.injector import attach, inject, detach

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    script_source = get_bcrypt_hook_script()
    inject(session, script_source)
    console.print(f"[green]BCrypt hooks injected into {session.target} (PID: {session.pid})[/green]")

    try:
        console.print("[dim]Monitoring crypto operations... Ctrl+C to stop.[/dim]")
        while True:
            time.sleep(0.5)
            for msg in session.observer.messages:
                if msg.payload and isinstance(msg.payload, dict):
                    if msg.payload.get("type") == "crypto_key":
                        console.print(f"  [red bold]KEY CAPTURED[/red bold] {msg.payload}")
                    else:
                        console.print(f"  [{msg.type}] {msg.payload}")
                else:
                    console.print(f"  [{msg.type}] {msg.payload}")
            session.observer.messages.clear()
    except KeyboardInterrupt:
        pass
    finally:
        detach(session)
        console.print("[green]Detached.[/green]")
