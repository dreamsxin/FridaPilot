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


@binary_app.command("analyze")
def analyze_cmd(
    binary: str = typer.Argument(..., help="Path to binary file (PE/ELF)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Comprehensive one-shot analysis: PE/ELF + crypto scan + strings + Go detection.

    Automatically detects binary type and runs all relevant analysis tools,
    producing a combined report. This is the most common RE workflow.
    """
    import json as json_mod
    from pathlib import Path as _Path

    filepath = _Path(binary)
    if not filepath.exists():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    data = filepath.read_bytes()
    combined: dict = {"filepath": str(filepath), "analyses": []}

    console.print(Panel(f"[bold]{binary}[/bold]", title="Comprehensive Binary Analysis"))

    # ── 1. PE or ELF analysis ──
    is_pe = data[:2] == b"MZ"
    is_elf = data[:4] == b"\x7fELF"

    if is_pe:
        from fridapilot.tools.binary_analysis import analyze_pe
        console.print("\n[cyan]1. PE Analysis[/cyan]")
        pe_result = analyze_pe(binary)
        combined["pe"] = pe_result.model_dump()
        combined["analyses"].append("pe")

        info = Table(show_header=False)
        info.add_row("Machine", pe_result.machine)
        info.add_row("Arch", "x64" if pe_result.is_64bit else "x86")
        info.add_row("Type", "DLL" if pe_result.is_dll else "EXE")
        info.add_row(".NET", "Yes" if pe_result.is_dotnet else "No")
        info.add_row("Entry Point", f"0x{pe_result.entry_point:x}")
        info.add_row("Sections", str(len(pe_result.sections)))
        info.add_row("Imports", str(len(pe_result.imports)))
        info.add_row("Exports", str(len(pe_result.exports)))
        console.print(info)

        if pe_result.debug_info.get("pdb_path"):
            console.print(f"  PDB: {pe_result.debug_info['pdb_path']}")

    elif is_elf:
        from fridapilot.tools.binary_analysis import analyze_elf
        console.print("\n[cyan]1. ELF Analysis[/cyan]")
        elf_result = analyze_elf(binary)
        combined["elf"] = elf_result.model_dump()
        combined["analyses"].append("elf")

        info = Table(show_header=False)
        info.add_row("Machine", str(elf_result.machine))
        info.add_row("Arch", "x64" if elf_result.is_64bit else "x86/Other")
        info.add_row("PIE", "Yes" if elf_result.is_pie else "No")
        info.add_row("Symbols", str(len(elf_result.symbols)))
        info.add_row("Dynamic Libs", str(len(elf_result.dynamic_libs)))
        console.print(info)
    else:
        console.print("[yellow]  Unknown binary format (not PE or ELF)[/yellow]")

    # ── 2. Crypto scan ──
    from fridapilot.tools.crypto_reverse import scan_binary
    console.print("\n[cyan]2. Crypto Scan[/cyan]")
    crypto = scan_binary(binary)
    combined["crypto"] = {
        "sbox_count": len(crypto.sbox_offsets),
        "crypto_imports": crypto.crypto_imports,
        "crypto_strings_count": len(crypto.crypto_strings),
        "hex_key_candidates": crypto.hex_key_candidates[:5],
        "protection_level": {
            "level": crypto.protection_level.level,
            "label": crypto.protection_level.label,
            "confidence": crypto.protection_level.confidence,
        } if crypto.protection_level else None,
    }
    combined["analyses"].append("crypto")

    if crypto.protection_level:
        pl = crypto.protection_level
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(pl.confidence, "white")
        console.print(f"  Protection Level: [bold]L{pl.level} - {pl.label}[/bold] [{color}]({pl.confidence})[/{color}]")
    if crypto.crypto_imports:
        console.print(f"  Crypto APIs: {', '.join(crypto.crypto_imports[:10])}")
    if crypto.sbox_offsets:
        console.print(f"  AES S-Box: {len(crypto.sbox_offsets)} found")
    if crypto.hex_key_candidates:
        console.print(f"  Hex key candidates: {len(crypto.hex_key_candidates)}")

    # ── 3. Go binary detection ──
    import re as _re
    go_marker = _re.search(rb"go1\.\d+", data)
    if go_marker:
        from fridapilot.tools.binary_analysis import analyze_go_binary
        console.print("\n[cyan]3. Go Binary Analysis[/cyan]")
        go_result = analyze_go_binary(binary)
        combined["go"] = go_result.model_dump()
        combined["analyses"].append("go")

        console.print(f"  Go Version: {go_result.go_version}")
        console.print(f"  Packages: {len(go_result.packages)}")
        console.print(f"  Functions: {len(go_result.functions)}")
        console.print(f"  Source Files: {len(go_result.source_files)}")
    else:
        console.print("\n[dim]3. Go Binary: Not detected[/dim]")

    # ── 4. Key strings ──
    from fridapilot.tools.binary_analysis import find_strings
    console.print("\n[cyan]4. Notable Strings[/cyan]")
    strings = find_strings(binary, min_len=6, encoding="all", limit=500)
    # Filter for interesting patterns
    interesting_kw = ["encrypt", "decrypt", "password", "token", "secret",
                      "key", "license", "verify", "auth", "pipe", "ipc",
                      "http", "api", "cert", "sign", "hash", "aes", "rsa"]
    notable = [s for s in strings if any(kw in s.value.lower() for kw in interesting_kw)]
    combined["notable_strings"] = [{"offset": s.offset, "value": s.value} for s in notable[:30]]
    combined["analyses"].append("strings")

    console.print(f"  Total strings: {len(strings)}")
    console.print(f"  Notable (security-related): {len(notable)}")
    for s in notable[:15]:
        console.print(f"    0x{s.offset:08x}  {s.value[:100]}")
    if len(notable) > 15:
        console.print(f"    ... and {len(notable) - 15} more")

    # ── Summary ──
    console.print(f"\n[bold green]Analysis complete.[/bold green] Ran: {', '.join(combined['analyses'])}")

    if json_output:
        console.print(json_mod.dumps(combined, indent=2, default=str))


# ── RVA-aware commands (ImageBase-correct; see tools/pe_rva.py) ──


@binary_app.command("disasm-rva")
def disasm_rva_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (.dll/.exe)."),
    rva: str = typer.Option(..., "--rva", "-r", help="Start RVA (hex/decimal), NOT a file offset."),
    count: int = typer.Option(40, "--count", "-n", help="Number of instructions."),
    symbols: str = typer.Option("", "--symbols", "-s", help="Symbol map 'rva:name,rva:name' (hex rva)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """RVA-aware disassembly: correct ImageBase, annotated rip-relative & call targets.

    Use this instead of `disassemble` for real PEs whose section RVA differs from
    the file offset (e.g. chrome.dll). Rip-relative data references and call/jmp
    targets are resolved to RVA and tagged with any supplied symbol names.
    """
    import json as json_mod
    from fridapilot.tools.pe_rva import disassemble_rva

    sym_map: dict[int, str] = {}
    if symbols:
        for pair in symbols.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                sym_map[int(k.strip(), 0)] = v.strip()

    result = disassemble_rva(binary, int(rva, 0), count=count, symbols=sym_map)

    if json_output:
        console.print(json_mod.dumps(result, indent=2, default=str))
        return

    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
        return
    console.print(f"[bold]Disassembly[/bold] @ RVA 0x{result['start_rva']:x} "
                  f"(ImageBase 0x{result['image_base']:x})")
    for ln in result["lines"]:
        note = f"  [cyan]{ln['note']}[/cyan]" if ln["note"] else ""
        console.print(f"  RVA 0x{ln['rva']:08x}  {ln['bytes_hex']:<20s}  "
                      f"{ln['mnemonic']:<8s} {ln['op_str']}{note}")


@binary_app.command("find-string-rva")
def find_string_rva_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    needles: str = typer.Argument(..., help="Comma-separated exact strings to locate."),
    encoding: str = typer.Option("ascii", "--encoding", "-e", help="ascii or utf16le."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Locate exact strings and report their RVA (for subsequent xrefs/disasm)."""
    import json as json_mod
    from fridapilot.tools.pe_rva import find_string_rvas

    needle_list = [n for n in needles.split(",") if n]
    results = find_string_rvas(binary, needle_list, encoding=encoding)

    if json_output:
        console.print(json_mod.dumps(results, indent=2, default=str))
        return

    console.print(f"[bold]String RVA lookup[/bold] ({len(results)} hits)")
    for r in results:
        if r["rva"] is None:
            console.print(f"  [dim]not found:[/dim] {r['needle'][:60]}")
        else:
            console.print(f"  RVA 0x{r['rva']:08x}  off 0x{r['offset']:08x}  {r['needle'][:80]}")


@binary_app.command("func-bounds")
def func_bounds_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (x64)."),
    rva: str = typer.Option(..., "--rva", "-r", help="Any RVA inside the function."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Exact function bounds from the x64 .pdata (SEH RUNTIME_FUNCTION) table.

    Instant and exact — beats scanning backwards for a prologue, which is
    unreliable on optimised code with shrink-wrapped or split prologues.

    Example: you found a string xref at 0xd6ba5db and want the whole function:
      fp binary func-bounds chrome.dll --rva 0xd6ba5db
      fp binary disasm-rva chrome.dll --rva <begin_rva> -n 400
    """
    import json as json_mod
    from fridapilot.tools.pe_rva import function_bounds

    res = function_bounds(binary, int(rva, 0))
    if json_output:
        console.print(json_mod.dumps(res, indent=2, default=str))
        return
    if res is None:
        console.print(f"[yellow]No .pdata entry covering RVA 0x{int(rva,0):x}[/yellow] "
                      "(leaf function, or outside .pdata coverage)")
        return
    console.print(f"[bold]Function containing RVA 0x{int(rva,0):x}[/bold]")
    console.print(f"  begin       RVA 0x{res['begin_rva']:08x}")
    console.print(f"  end         RVA 0x{res['end_rva']:08x}")
    console.print(f"  size        0x{res['size']:x} ({res['size']} bytes)")
    console.print(f"  unwind info RVA 0x{res['unwind_info_rva']:08x}")

def xrefs_rva_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    target: str = typer.Option(..., "--target", "-t", help="Target RVA to find references to."),
    start: str = typer.Option(..., "--start", help="Scan range start RVA."),
    end: str = typer.Option(..., "--end", help="Scan range end RVA."),
    kinds: str = typer.Option(
        "rip,call,jmp", "--kinds", "-k",
        help="Comma list: rip,call,jmp,imm64,ptr,rva32. Use 'ptr' (scan .rdata) "
             "when a string is clearly used but rip finds nothing — it may live in "
             "a const char* pointer table.",
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify",
        help="Skip per-candidate capstone verification (faster, slightly noisier).",
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """RVA-aware xref scan: rip-relative data refs + direct call/jmp to a target RVA.

    Byte-pattern scanning with capstone verification — linear disassembly of a large
    .text desynchronises on embedded data and silently misses most references.

    Examples:
      # code referencing a config field string
      fp binary xrefs-rva chrome.dll --target 0xfae6439 --start 0x1000 --end 0xf545000

      # string referenced only from a pointer table (scan .rdata, not .text)
      fp binary xrefs-rva chrome.dll --target 0xfb3dfc0 --start 0xf545000 \\
          --end 0x11394000 --kinds ptr
    """
    import json as json_mod
    from fridapilot.tools.pe_rva import xrefs_to_rva

    kind_tuple = tuple(k.strip() for k in kinds.split(",") if k.strip())
    results = xrefs_to_rva(binary, int(target, 0), int(start, 0), int(end, 0),
                           kinds=kind_tuple, verify=not no_verify)

    if json_output:
        console.print(json_mod.dumps(results, indent=2, default=str))
        return

    console.print(f"[bold]RVA xrefs to 0x{int(target,0):x}[/bold] "
                  f"in [0x{int(start,0):x},0x{int(end,0):x}) — {len(results)} found")
    for x in results:
        console.print(f"  RVA 0x{x['from_rva']:08x}  [{x['kind']:<5s}]  "
                      f"{x['mnemonic']} {x['op_str']}")
    if not results and "ptr" not in kind_tuple:
        console.print("[dim]  Tip: 0 hits for a string that is clearly used? It may be "
                      "in a const char* table — retry with --kinds ptr over .rdata.[/dim]")

