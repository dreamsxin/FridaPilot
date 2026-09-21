"""fp unpack - Packer detection, auto-unpacking, and memory dump."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
unpack_app = typer.Typer(no_args_is_help=True)


@unpack_app.command("detect")
def detect_cmd(
    binary: str = typer.Argument(..., help="Path to PE binary file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Detect if a binary is packed and identify the packer type."""
    import json as json_mod

    from fridapilot.tools.unpacker import detect_packer

    info = detect_packer(binary)

    if json_output:
        out = {
            "filepath": info.filepath,
            "packed": info.packed,
            "packer": info.packer_name,
            "confidence": info.confidence,
            "evidence": info.evidence,
            "sections": info.section_entropy,
        }
        console.print(json_mod.dumps(out, indent=2))
        return

    status = "[bold red]PACKED[/bold red]" if info.packed else "[bold green]NOT PACKED[/bold green]"
    console.print(Panel(f"{info.filepath}\nStatus: {status}", title="Packer Detection"))

    if info.packed:
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(info.confidence, "white")
        console.print(f"  Packer: [bold]{info.packer_name}[/bold] [{color}]({info.confidence})[/{color}]")
        for e in info.evidence:
            console.print(f"  {e}")

    if info.section_entropy:
        table = Table(title="Section Entropy")
        table.add_column("Name")
        table.add_column("Entropy", justify="right")
        table.add_column("Raw Size", justify="right")
        table.add_column("VSize", justify="right")
        for s in info.section_entropy:
            ent = s["entropy"]
            color = "red" if ent > 7.0 else "yellow" if ent > 6.0 else ""
            ent_str = f"[{color}]{ent:.2f}[/{color}]" if color else f"{ent:.2f}"
            table.add_row(s["name"], ent_str, str(s["raw_size"]), str(s["vsize"]))
        console.print(table)


@unpack_app.command("auto")
def auto_cmd(
    binary: str = typer.Argument(..., help="Path to potentially packed binary."),
    output: str = typer.Option("", "--output", "-o", help="Output path for unpacked binary."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Auto-unpack pipeline: detect packer -> try UPX -> report.

    For non-UPX packers, use `fp unpack dump` on the running process.
    """
    import json as json_mod

    from fridapilot.tools.unpacker import auto_unpack

    result = auto_unpack(binary, output)

    if json_output:
        out = {
            "success": result.success,
            "method": result.method,
            "output_path": result.output_path,
            "original_path": result.original_path,
            "error": result.error,
        }
        if result.packer_info:
            out["packer"] = {
                "packed": result.packer_info.packed,
                "name": result.packer_info.packer_name,
                "confidence": result.packer_info.confidence,
            }
        console.print(json_mod.dumps(out, indent=2))
        return

    if result.success:
        if result.method == "none":
            console.print("[green]Binary is not packed.[/green] No unpacking needed.")
        else:
            console.print("[bold green]Unpacked successfully![/bold green]")
            console.print(f"  Method: {result.method}")
            console.print(f"  Output: {result.output_path}")
    else:
        console.print("[bold red]Unpacking failed.[/bold red]")
        console.print(f"  {result.error}")
        if result.packer_info and result.packer_info.packed:
            console.print("\n[yellow]Suggestion:[/yellow] Run the packed binary, then use:")
            console.print(f"  fp unpack dump --target {binary}")


@unpack_app.command("dump")
def dump_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    output: str = typer.Option("", "--output", "-o", help="Output dump file path."),
    device: str = typer.Option("local", "--device", "-d", help="Device: local, usb, remote."),
) -> None:
    """Dump a running process's main module memory via Frida.

    Use this after the packed binary has unpacked itself in memory.
    """
    from fridapilot.tools.unpacker import dump_process_memory

    try:
        tgt: str | int = int(target)
    except ValueError:
        tgt = target

    console.print(f"[dim]Attaching to {target} and dumping main module...[/dim]")
    result = dump_process_memory(tgt, output_path=output or None, device_type=device)

    if result.success:
        console.print("[bold green]Memory dump saved![/bold green]")
        console.print(f"  Output: {result.output_path}")
        console.print("\n[dim]Next: analyze the dump with[/dim]")
        console.print(f"  fp binary analyze {result.output_path}")
    else:
        console.print(f"[bold red]Dump failed:[/bold red] {result.error}")
