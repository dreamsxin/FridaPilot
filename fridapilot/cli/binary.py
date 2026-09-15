"""fp binary - Static binary analysis commands."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
binary_app = typer.Typer(no_args_is_help=True)


@binary_app.command("analyze-pe")
def analyze_pe_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (.exe, .dll, .sys)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze PE binary: headers, sections, imports, exports, debug info."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import analyze_pe

    result = analyze_pe(binary)

    if json_output:
        console.print(json_mod.dumps(result.model_dump(), indent=2, default=str))
        return

    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="PE Analysis"))

    info = Table(show_header=False)
    info.add_row("Machine", result.machine)
    info.add_row("Arch", "x64" if result.is_64bit else "x86")
    info.add_row("Type", "DLL" if result.is_dll else "EXE")
    info.add_row(".NET", "Yes" if result.is_dotnet else "No")
    info.add_row("Entry Point", f"0x{result.entry_point:x}")
    info.add_row("Image Base", f"0x{result.image_base:x}")
    console.print(info)

    if result.sections:
        sec_table = Table(title="Sections")
        sec_table.add_column("Name")
        sec_table.add_column("VAddr", justify="right")
        sec_table.add_column("VSize", justify="right")
        sec_table.add_column("RawSize", justify="right")
        sec_table.add_column("Entropy", justify="right")
        for s in result.sections:
            color = "red" if s.entropy > 7.0 else "yellow" if s.entropy > 6.0 else ""
            ent_str = f"[{color}]{s.entropy:.2f}[/{color}]" if color else f"{s.entropy:.2f}"
            sec_table.add_row(
                s.name, f"0x{s.virtual_address:x}",
                str(s.virtual_size), str(s.raw_size), ent_str,
            )
        console.print(sec_table)
    if result.imports:
        console.print(f"\n[bold]Imports:[/bold] {len(result.imports)} functions")
        # Group by DLL
        dlls: dict[str, list[str]] = {}
        for imp in result.imports:
            dlls.setdefault(imp.dll, []).append(imp.name or f"ord_{imp.ordinal}")
        for dll, funcs in sorted(dlls.items()):
            console.print(f"  [cyan]{dll}[/cyan] ({len(funcs)} functions)")

    if result.exports:
        console.print(f"\n[bold]Exports:[/bold] {len(result.exports)} symbols")
        for name in result.exports[:20]:
            console.print(f"  {name}")
        if len(result.exports) > 20:
            console.print(f"  ... and {len(result.exports) - 20} more")

    if result.debug_info:
        console.print(f"\n[bold]Debug Info:[/bold]")
        for k, v in result.debug_info.items():
            console.print(f"  {k}: {v}")


@binary_app.command("analyze-elf")
def analyze_elf_cmd(
    binary: str = typer.Argument(..., help="Path to ELF binary."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze ELF binary: headers, sections, symbols, dynamic libraries."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import analyze_elf

    result = analyze_elf(binary)

    if json_output:
        console.print(json_mod.dumps(result.model_dump(), indent=2, default=str))
        return

    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="ELF Analysis"))

    info = Table(show_header=False)
    info.add_row("Machine", str(result.machine))
    info.add_row("Arch", "x64" if result.is_64bit else "x86/Other")
    info.add_row("PIE", "Yes" if result.is_pie else "No")
    info.add_row("Entry Point", f"0x{result.entry_point:x}")
    console.print(info)

    if result.sections:
        sec_table = Table(title="Sections")
        sec_table.add_column("Name")
        sec_table.add_column("VAddr", justify="right")
        sec_table.add_column("Size", justify="right")
        sec_table.add_column("Entropy", justify="right")
        for s in result.sections:
            if not s.name:
                continue
            sec_table.add_row(s.name, f"0x{s.virtual_address:x}", str(s.virtual_size), f"{s.entropy:.2f}")
        console.print(sec_table)

    if result.dynamic_libs:
        console.print(f"\n[bold]Dynamic Libraries:[/bold]")
        for lib in result.dynamic_libs:
            console.print(f"  {lib}")

    console.print(f"\n[bold]Function Symbols:[/bold] {len(result.symbols)}")
    for sym in result.symbols[:20]:
        console.print(f"  {sym}")
    if len(result.symbols) > 20:
        console.print(f"  ... and {len(result.symbols) - 20} more")


@binary_app.command("disassemble")
def disassemble_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    address: str = typer.Option(..., "--address", "-a", help="File offset (hex or decimal)."),
    count: int = typer.Option(20, "--count", "-n", help="Number of instructions."),
    arch: str = typer.Option("auto", "--arch", help="Architecture: auto, x86, x64, arm, arm64."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Disassemble instructions at a given file offset."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import disassemble

    addr = int(address, 0)  # supports 0x prefix
    result = disassemble(binary, addr, count=count, arch=arch)

    if json_output:
        console.print(json_mod.dumps(result.model_dump(), indent=2, default=str))
        return

    console.print(f"[bold]Disassembly[/bold] @ 0x{addr:x} ({result.architecture})")
    for insn in result.instructions:
        console.print(f"  0x{insn.address:08x}  {insn.bytes_hex:<20s}  {insn.mnemonic:<8s} {insn.op_str}")


@binary_app.command("find-strings")
def find_strings_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    min_len: int = typer.Option(4, "--min-len", "-m", help="Minimum string length."),
    encoding: str = typer.Option("all", "--encoding", "-e", help="Encoding: ascii, utf16le, utf8, all."),
    limit: int = typer.Option(200, "--limit", "-l", help="Maximum strings to show."),
    filter_str: str = typer.Option("", "--filter", "-f", help="Filter strings containing this text."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Extract strings from a binary file (ASCII, UTF-16LE, UTF-8)."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import find_strings

    results = find_strings(binary, min_len=min_len, encoding=encoding, limit=limit * 5)

    if filter_str:
        results = [s for s in results if filter_str.lower() in s.value.lower()]

    results = results[:limit]

    if json_output:
        console.print(json_mod.dumps([s.model_dump() for s in results], indent=2, default=str))
        return

    console.print(f"[bold]Strings[/bold] ({len(results)} found)")
    for s in results:
        enc_tag = f"[dim]{s.encoding}[/dim]" if s.encoding != "ascii" else ""
        console.print(f"  0x{s.offset:08x}  {s.value[:120]} {enc_tag}")


@binary_app.command("search-bytes")
def search_bytes_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    pattern: str = typer.Argument(..., help="Hex byte pattern (e.g. '4883ec20' or '48 8b ?? 48')."),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum matches."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Search for a byte pattern in a binary (supports ?? wildcards)."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import search_bytes

    results = search_bytes(binary, pattern, limit=limit)

    if json_output:
        console.print(json_mod.dumps([m.model_dump() for m in results], indent=2, default=str))
        return

    console.print(f"[bold]Byte Pattern Search[/bold] ({len(results)} matches)")
    for m in results:
        console.print(f"  0x{m.offset:08x}  {m.matched_bytes}")


@binary_app.command("xrefs")
def xrefs_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    address: str = typer.Option(..., "--address", "-a", help="Target address (hex or decimal)."),
    start: str = typer.Option("", "--start", help="Search range start offset."),
    end: str = typer.Option("", "--end", help="Search range end offset."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Find cross-references (CALL/JMP) to a target address."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import xrefs_to

    addr = int(address, 0)
    search_range = None
    if start and end:
        search_range = (int(start, 0), int(end, 0))

    results = xrefs_to(binary, addr, search_range=search_range)

    if json_output:
        console.print(json_mod.dumps([x.model_dump() for x in results], indent=2, default=str))
        return

    console.print(f"[bold]Cross-References to 0x{addr:x}[/bold] ({len(results)} found)")
    for x in results:
        console.print(f"  0x{x.from_address:08x}  [{x.xref_type}]  {x.instruction}")


@binary_app.command("analyze-go")
def analyze_go_cmd(
    binary: str = typer.Argument(..., help="Path to Go binary (PE or ELF)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze a Go-compiled binary: version, packages, functions, source paths."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import analyze_go_binary

    result = analyze_go_binary(binary)

    if json_output:
        console.print(json_mod.dumps(result.model_dump(), indent=2, default=str))
        return

    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="Go Binary Analysis"))

    info = Table(show_header=False)
    info.add_row("Go Version", result.go_version or "[dim]unknown[/dim]")
    info.add_row("Packages", str(len(result.packages)))
    info.add_row("Functions", str(len(result.functions)))
    info.add_row("Source Files", str(len(result.source_files)))
    console.print(info)

    if result.packages:
        console.print(f"\n[bold]Packages:[/bold] ({len(result.packages)})")
        for pkg in result.packages[:30]:
            console.print(f"  {pkg}")
        if len(result.packages) > 30:
            console.print(f"  ... and {len(result.packages) - 30} more")

    if result.source_files:
        console.print(f"\n[bold]Source Files:[/bold] ({len(result.source_files)})")
        for src in result.source_files[:20]:
            console.print(f"  {src}")
        if len(result.source_files) > 20:
            console.print(f"  ... and {len(result.source_files) - 20} more")

    if result.functions:
        console.print(f"\n[bold]Functions:[/bold] ({len(result.functions)})")
        for fn in result.functions[:30]:
            console.print(f"  {fn}")
        if len(result.functions) > 30:
            console.print(f"  ... and {len(result.functions) - 30} more")
