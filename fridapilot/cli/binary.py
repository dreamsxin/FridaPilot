"""fp binary - Static binary analysis commands."""

import json as _json
import sys
from pathlib import Path


import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.panel import Panel

console = Console()
err_console = Console(stderr=True)
binary_app = typer.Typer(no_args_is_help=True)


def _emit_json(obj) -> None:
    """Write JSON to stdout verbatim.

    Never route machine-readable output through ``rich.Console``: it soft-wraps at
    the terminal width (80 columns when stdout is a pipe) and parses ``[...]`` as
    markup. Both corrupt the payload silently — no error, no missing line, just
    wrong bytes. Progress/status text belongs on stderr (``err_console``) so that
    ``--json`` output stays parseable when redirected to a file.
    """
    sys.stdout.write(_json.dumps(obj, indent=2, default=str) + "\n")



@binary_app.command("analyze-pe")
def analyze_pe_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (.exe, .dll, .sys)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze PE binary: headers, sections, imports, exports, debug info."""
    from fridapilot.tools.binary_analysis import analyze_pe

    result = analyze_pe(binary)

    if json_output:
        _emit_json(result.model_dump())
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
        console.print("\n[bold]Debug Info:[/bold]")
        for k, v in result.debug_info.items():
            console.print(f"  {k}: {v}")


@binary_app.command("analyze-elf")
def analyze_elf_cmd(
    binary: str = typer.Argument(..., help="Path to ELF binary."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze ELF binary: headers, sections, symbols, dynamic libraries."""
    from fridapilot.tools.binary_analysis import analyze_elf

    result = analyze_elf(binary)

    if json_output:
        _emit_json(result.model_dump())
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
        console.print("\n[bold]Dynamic Libraries:[/bold]")
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
    from fridapilot.tools.binary_analysis import disassemble

    addr = int(address, 0)  # supports 0x prefix
    result = disassemble(binary, addr, count=count, arch=arch)

    if json_output:
        _emit_json(result.model_dump())
        return

    console.print(f"[bold]Disassembly[/bold] @ 0x{addr:x} ({result.architecture})")
    for insn in result.instructions:
        console.print(f"  0x{insn.address:08x}  {insn.bytes_hex:<20s}  {insn.mnemonic:<8s} {escape(insn.op_str)}")


@binary_app.command("find-strings")
def find_strings_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    min_len: int = typer.Option(4, "--min-len", "-m", help="Minimum string length."),
    encoding: str = typer.Option("all", "--encoding", "-e", help="Encoding: ascii, utf16le, utf8, all."),
    codepage: str = typer.Option(
        "", "--codepage", "-c",
        help="Also extract a legacy code page: gbk, gb18030, big5, cp932, cp949, cp1251, cp1252.",
    ),
    limit: int = typer.Option(200, "--limit", "-l", help="Maximum strings to show."),
    filter_str: str = typer.Option("", "--filter", "-f", help="Filter strings containing this text."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Extract strings from a binary (ASCII, UTF-16LE, UTF-8, or a legacy code page).

    The ASCII pass only accepts bytes 0x20-0x7e, so GBK / Shift-JIS / CP1251 text is
    invisible to it - pass --codepage for those. For PE input each hit also carries
    its RVA and section, which is what the *-rva commands take.
    """
    from fridapilot.tools.binary_analysis import find_strings

    results = find_strings(binary, min_len=min_len, encoding=encoding,
                           limit=limit * 5, codepage=codepage)

    if filter_str:
        results = [s for s in results if filter_str.lower() in s.value.lower()]

    results = results[:limit]

    if json_output:
        _emit_json([s.model_dump() for s in results])
        return

    console.print(f"[bold]Strings[/bold] ({len(results)} found)")
    for s in results:
        rva = f"rva 0x{s.rva:x} {s.section}" if s.rva is not None else ""
        enc_tag = f"[dim]{s.encoding}[/dim]" if s.encoding != "ascii" else ""
        console.print(f"  0x{s.offset:08x}  {escape(s.value[:110])} [dim]{rva}[/dim] {enc_tag}")


@binary_app.command("find-text")
def find_text_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    text: str = typer.Option(..., "--text", "-t", help="Text to locate."),
    encodings: str = typer.Option(
        "ascii,utf8,utf16le,gbk", "--encodings", "-e",
        help="Comma-separated codecs to try: ascii, utf8, utf16le, utf16be, gbk, "
             "gb18030, big5, cp932, cp949, cp1251, cp1252, latin1.",
    ),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum matches."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Locate one piece of text encoded several ways at once, and report the RVA.

    Use this when the encoding is unknown: the same UI string may be UTF-8 in one
    build, UTF-16LE in another and CP936 in a third. The encodings that appear in
    the output are the ones the binary actually uses; codecs that cannot represent
    the text are skipped, and codecs that produce identical bytes are merged.

    Example:
      fp binary find-text app.exe --text "license expired" --encodings ascii,utf16le
    """
    from fridapilot.tools.binary_analysis import find_text

    codecs = tuple(e.strip() for e in encodings.split(",") if e.strip())
    results = find_text(binary, text, encodings=codecs, limit=limit)

    if json_output:
        _emit_json([s.model_dump() for s in results])
        return

    if not results:
        console.print(f"[yellow]Not found in any of: {', '.join(codecs)}[/yellow]")
        return

    table = Table(title=f"'{text}' ({len(results)} matches)")
    table.add_column("Offset", style="cyan")
    table.add_column("RVA", style="green")
    table.add_column("Section")
    table.add_column("Encoding")
    for s in results:
        table.add_row(f"0x{s.offset:x}",
                      f"0x{s.rva:x}" if s.rva is not None else "-",
                      s.section or "-", s.encoding)
    console.print(table)


@binary_app.command("search-bytes")
def search_bytes_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    pattern: str = typer.Argument(..., help="Hex byte pattern (e.g. '4883ec20' or '48 8b ?? 48')."),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum matches."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Search for a byte pattern in a binary (supports ?? wildcards).

    For PE input each match also carries its RVA and section, so a hit can be fed
    straight to func-bounds / disasm-rva.
    """
    from fridapilot.tools.binary_analysis import search_bytes

    results = search_bytes(binary, pattern, limit=limit)

    if json_output:
        _emit_json([m.model_dump() for m in results])
        return

    console.print(f"[bold]Byte Pattern Search[/bold] ({len(results)} matches)")
    for m in results:
        rva = f"rva 0x{m.rva:x} {m.section}" if m.rva is not None else ""
        console.print(f"  0x{m.offset:08x}  {m.matched_bytes} [dim]{rva}[/dim]")



@binary_app.command("xrefs")
def xrefs_cmd(
    binary: str = typer.Argument(..., help="Path to binary file."),
    address: str = typer.Option(..., "--address", "-a", help="Target address (hex or decimal)."),
    start: str = typer.Option("", "--start", help="Search range start offset."),
    end: str = typer.Option("", "--end", help="Search range end offset."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Find cross-references (CALL/JMP) to a target address."""
    from fridapilot.tools.binary_analysis import xrefs_to

    addr = int(address, 0)
    search_range = None
    if start and end:
        search_range = (int(start, 0), int(end, 0))

    results = xrefs_to(binary, addr, search_range=search_range)

    if json_output:
        _emit_json([x.model_dump() for x in results])
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
    from fridapilot.tools.binary_analysis import analyze_go_binary

    result = analyze_go_binary(binary)

    if json_output:
        _emit_json(result.model_dump())
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
        # Skip rich output above when --json is used; emit clean JSON only
        _emit_json(combined)
        return


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
    from fridapilot.tools.pe_rva import disassemble_rva

    sym_map: dict[int, str] = {}
    if symbols:
        for pair in symbols.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                sym_map[int(k.strip(), 0)] = v.strip()

    result = disassemble_rva(binary, int(rva, 0), count=count, symbols=sym_map)

    if json_output:
        _emit_json(result)
        return

    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
        return
    console.print(f"[bold]Disassembly[/bold] @ RVA 0x{result['start_rva']:x} "
                  f"(ImageBase 0x{result['image_base']:x})")
    for ln in result["lines"]:
        note = f"  [cyan]{escape(ln['note'])}[/cyan]" if ln["note"] else ""
        console.print(f"  RVA 0x{ln['rva']:08x}  {ln['bytes_hex']:<20s}  "
                      f"{ln['mnemonic']:<8s} {escape(ln['op_str'])}{note}")


@binary_app.command("find-string-rva")
def find_string_rva_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    needles: str = typer.Argument(..., help="Comma-separated exact strings to locate."),
    encoding: str = typer.Option("ascii", "--encoding", "-e", help="ascii or utf16le."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Locate exact strings and report their RVA (for subsequent xrefs/disasm)."""
    from fridapilot.tools.pe_rva import find_string_rvas

    needle_list = [n for n in needles.split(",") if n]
    results = find_string_rvas(binary, needle_list, encoding=encoding)

    if json_output:
        _emit_json(results)
        return

    console.print(f"[bold]String RVA lookup[/bold] ({len(results)} hits)")
    for r in results:
        if r["rva"] is None:
            console.print(f"  [dim]not found:[/dim] {r['needle'][:60]}")
        else:
            console.print(f"  RVA 0x{r['rva']:08x}  off 0x{r['offset']:08x}  {r['needle'][:80]}")


@binary_app.command("inline-strings")
def inline_strings_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    text: str = typer.Option(..., "--text", "-t", help="String the code builds inline."),
    encoding: str = typer.Option("utf8", "--encoding", "-e",
                                 help="Codec for the text: utf8, utf16le, gbk, cp932, ..."),
    section: str = typer.Option(".text", "--section", help="Section to search."),
    window: int = typer.Option(96, "--window", help="Bytes after the anchor to confirm in."),
    confirmed: bool = typer.Option(False, "--confirmed",
                                   help="Only sites whose anchor is a real MOV imm operand."),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum sites to report."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Find a string the code CONSTRUCTS in registers (movabs), not one it points at.

    Use this when find-string-rva finds the string but xrefs-rva finds no references,
    or when find-string-rva finds nothing at all: an inline string has no .rdata copy
    and its characters are split by the opcode bytes carrying them, so no contiguous
    search and no xref scan can reach it.
    """
    from fridapilot.tools.pe_rva import find_inline_strings

    filepath = Path(binary)
    if not filepath.exists():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    try:
        hits = find_inline_strings(binary, text, encoding=encoding, section=section,
                                  window=window, limit=limit)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if confirmed:
        hits = [h for h in hits if h["opcode"]]

    if json_output:
        _emit_json(hits)
        return

    if not hits:
        console.print(f"[yellow]No inline construction of {text!r} found in {section}.[/yellow]")
        console.print("[dim]It may be a normal .rdata string - try `find-string-rva` / "
                      "`find-text`, or widen --window.[/dim]")
        return

    table = Table(title=f"Inline construction of {text!r} ({len(hits)} site(s))")
    table.add_column("RVA", style="cyan")
    table.add_column("Section")
    table.add_column("Carrier", style="green")
    table.add_column("Groups")
    table.add_column("Function", style="dim")
    for h in hits:
        func = (f"0x{h['func_begin_rva']:x}-0x{h['func_end_rva']:x}"
                if h["func_begin_rva"] is not None else "(no .pdata entry)")
        table.add_row(
            f"0x{h['from_rva']:08x}",
            h["section"],
            h["opcode"] or "[yellow]unconfirmed[/yellow]",
            f"{h['chunks_found']}/{h['chunks_total']}",
            func,
        )
    console.print(table)
    console.print("[dim]Carrier 'unconfirmed' means the bytes matched but no MOV imm opcode "
                  "precedes them - could be data. Disassemble to confirm.[/dim]")


@binary_app.command("field-refs")
def field_refs_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (x64)."),
    offset: str = typer.Option(..., "--offset", "-o", help="Struct field offset, e.g. 0xB0."),
    start: str = typer.Option("", "--start-rva", help="Scan start RVA (default: .text)."),
    end: str = typer.Option("", "--end-rva", help="Scan end RVA (default: end of .text)."),
    kind: str = typer.Option("both", "--kind", "-k", help="read | write | both."),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip capstone verification."),
    with_func: bool = typer.Option(False, "--with-func", help="Also resolve containing function."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Find reads/writes of a struct field at [reg + offset].

    Answers "who writes this->field_ at +0xB0?" — the practical question when
    reverse-engineering a C++ object. Uses the section table for RVA conversion; a
    hand-rolled scan with a single RVA->offset constant silently produces garbage
    the moment it crosses a section boundary.

    Always sanity-check with a known reference first:
      fp binary field-refs chrome.dll -o 0xB0 --kind read --start-rva 0x1c42000 \\
          --end-rva 0x1c43f00        # must include the known read site
    """

    from fridapilot.tools.pe_rva import field_refs, function_bounds

    res = field_refs(binary, int(offset, 0),
                     int(start, 0) if start else None,
                     int(end, 0) if end else None,
                     kind=kind, verify=not no_verify)
    if with_func:
        for r in res:
            fb = function_bounds(binary, r["from_rva"])
            r["func_begin_rva"] = fb["begin_rva"] if fb else None
            r["func_size"] = fb["size"] if fb else None

    if json_output:
        _emit_json(res)
        return

    writes = [r for r in res if r["kind"] == "write"]
    reads = [r for r in res if r["kind"] == "read"]
    console.print(f"[bold]Refs to reg+{offset}[/bold] — "
                  f"{len(writes)} write(s), {len(reads)} read(s)")
    for label, group in (("WRITE", writes), ("READ", reads)):
        if not group:
            continue
        console.print(f"\n[cyan]{label}[/cyan]")
        for r in group:
            fn = ""
            if with_func and r.get("func_begin_rva"):
                fn = f"   [dim]fn 0x{r['func_begin_rva']:08x} ({r['func_size']}B)[/dim]"
            console.print(f"  RVA 0x{r['from_rva']:08x}  {r['mnemonic']} {escape(r['op_str'])}{fn}")


@binary_app.command("map-refs")

def map_refs_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (x64)."),
    strings: str = typer.Option(
        "", "--strings", "-s",
        help="Comma-separated exact strings to locate and map."),
    prefix: str = typer.Option(
        "", "--prefix", "-p",
        help="Auto-collect every NUL-terminated .rdata string starting with this "
             "prefix (e.g. 'np-'). Combines with --strings."),
    start: str = typer.Option("", "--start", help="Scan start RVA (default: .text)."),
    end: str = typer.Option("", "--end", help="Scan end RVA (default: end of .text)."),
    kinds: str = typer.Option("rip", "--kinds", "-k", help="rip,ptr,imm64."),
    min_labels: int = typer.Option(1, "--min-labels", help="Only show functions with >= N distinct strings."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Map many strings to the functions that reference them, in one pass.

    Answers "which functions consume these N strings, and which does each use?" —
    the practical shape of mapping a patched binary. Running xrefs-rva N times would
    rescan the section N times; this scans once and groups by .pdata function.

    Example: map every custom switch of a patched Chromium to its consuming function:
      fp binary map-refs chrome.dll --prefix np- --min-labels 2
    """
    import re

    from fridapilot.tools.pe_rva import PEImage, map_refs_to_functions

    img = PEImage(binary)
    targets: dict[str, int] = {}

    def _put(label: str, rva: int) -> None:
        """Register one occurrence, keeping every copy of a duplicated literal.

        MSVC does not always pool identical string literals across translation
        units, so the same switch name can sit at several ``.rdata`` addresses —
        typically one copy per component (e.g. the browser's copy and the
        font_data service's copy). Keeping only the first occurrence silently
        under-reports which functions use that string. Extra copies get a
        ``name@0xRVA`` label so the grouping stays readable.
        """
        if label not in targets:
            targets[label] = rva
        elif targets[label] != rva:
            targets[f"{label}@0x{rva:x}"] = rva

    def _add(sv: str) -> None:
        pat = sv.encode("utf-8")
        pos = 0
        while True:
            i = img._data.find(pat, pos)
            if i < 0:
                break
            pos = i + 1
            rva = img.off_to_rva(i)
            if rva is not None and img.section_of(rva) in (".rdata", ".rodata", ".data"):
                _put(sv, rva)

    for sv in (s.strip() for s in strings.split(",")):
        if sv:
            _add(sv)

    if prefix:
        rd = None
        for va, vs, praw, rsize, name in img._sections:
            if name == ".rdata":
                rd = (va, praw, min(vs, rsize))
                break
        if rd:
            rva0, praw, size = rd
            blob = img._data[praw:praw + size]
            pat = re.compile(re.escape(prefix.encode("ascii")) + rb"[\x20-\x7e]{1,60}")

            for m in pat.finditer(blob):
                s = m.group(0)
                # only accept a NUL-terminated standalone string
                endi = m.end()
                if endi < len(blob) and blob[endi] != 0:
                    continue
                if m.start() > 0 and blob[m.start() - 1] not in (0,):
                    continue
                try:
                    label = s.decode("ascii")
                except UnicodeDecodeError:
                    continue
                _put(label, rva0 + m.start())


    if not targets:
        console.print("[red]No target strings resolved.[/red]")
        return

    kind_tuple = tuple(k.strip() for k in kinds.split(",") if k.strip())
    res = map_refs_to_functions(binary, targets,
                                int(start, 0) if start else None,
                                int(end, 0) if end else None,
                                kinds=kind_tuple)
    err_console.print(
        f"[bold]{len(targets)} target strings[/bold], scanned "
        f"[0x{res['scan_start_rva']:x},0x{res['scan_end_rva']:x}) = "
        f"{res['section_coverage'] * 100:.1f}% of {res['section'] or '?'}")

    if json_output:
        _emit_json(res)
        return

    if res["section_coverage"] < 0.999:
        console.print("[yellow]Partial scan: an incomplete range under-reports and "
                      "looks like 'no references'.[/yellow]")

    shown = [f for f in res["functions"] if len(f["labels"]) >= min_labels]

    console.print(f"\n[bold]{len(shown)} function(s)[/bold] "
                  f"(of {len(res['functions'])}) with >= {min_labels} distinct string(s):\n")
    for f in shown:
        console.print(f"[cyan]RVA 0x{f['begin_rva']:08x}–0x{f['end_rva']:08x}[/cyan] "
                      f"({f['size']} bytes)  {len(f['labels'])} strings, "
                      f"{len(f['refs'])} refs")
        for lb in f["labels"]:
            console.print(f"    {lb}")
        console.print("")
    if res["orphans"]:
        console.print(f"[yellow]{len(res['orphans'])} ref(s) outside any .pdata entry "
                      "(leaf functions)[/yellow]")
    if res["unreferenced"]:
        console.print(f"[dim]{len(res['unreferenced'])} string(s) with no reference in "
                      f"range: {', '.join(res['unreferenced'][:12])}"
                      f"{'…' if len(res['unreferenced']) > 12 else ''}[/dim]")


@binary_app.command("func-bounds")

def func_bounds_cmd(
    binary: str = typer.Argument(..., help="Path to PE file (x64)."),
    rva: str = typer.Option(..., "--rva", "-r", help="Any RVA inside the function."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Exact function bounds from the x64 .pdata (SEH RUNTIME_FUNCTION) table.

    Instant and exact — beats scanning backwards for a prologue, which is
    unreliable on optimised code with shrink-wrapped or split prologues.

    Example: you found a string xref at 0x1c43550 and want the whole function:
      fp binary func-bounds chrome.dll --rva 0x1c43550
      fp binary disasm-rva chrome.dll --rva <begin_rva> -n 400
    """
    from fridapilot.tools.pe_rva import function_bounds

    res = function_bounds(binary, int(rva, 0))
    if json_output:
        _emit_json(res)
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

@binary_app.command("xrefs-rva")
def xrefs_rva_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    target: str = typer.Option(..., "--target", "-t", help="Target RVA to find references to."),
    start: str = typer.Option("", "--start", help="Scan start RVA (default: start of --section)."),
    end: str = typer.Option("", "--end", help="Scan end RVA (default: end of --section)."),
    section: str = typer.Option(
        ".text", "--section", "-s",
        help="Section to scan when --start/--end are omitted. Use .rdata with --kinds ptr.",
    ),
    kinds: str = typer.Option(
        "rip,call,jmp", "--kinds", "-k",
        help="Comma list: rip,call,jmp,imm64,ptr,rva32. Use 'ptr' (scan .rdata) "
             "when a string is clearly used but rip finds nothing — it may live in "
             "a const char* pointer table.",
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify",
        help="Skip per-candidate capstone verification in the gap scan "
             "(faster, slightly noisier).",
    ),
    pdata_only: bool = typer.Option(
        False, "--pdata-only",
        help="Only scan code covered by .pdata RUNTIME_FUNCTIONs. Fewer false "
             "positives when the range spans data, but misses leaf functions.",
    ),
    no_index: bool = typer.Option(
        False, "--no-index",
        help="Ignore the prebuilt rip index (see `index-build`) and rescan.",
    ),

    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """RVA-aware xref scan: rip-relative data refs + direct call/jmp to a target RVA.

    Rip references come from disassembling each .pdata function, plus an
    opcode-agnostic displacement scan of the ranges .pdata does not cover. A single
    linear sweep of a large .text desynchronises on embedded data and silently
    misses most references.

    The range defaults to the whole section, and the scanned extent is printed with
    its coverage: a truncated range returns fewer hits, which is indistinguishable
    from "no references" unless you can see how much was actually scanned.

    Examples:
      # whole .text, no addresses to look up
      fp binary xrefs-rva chrome.dll --target 0x2f10a40

      # string referenced only from a pointer table
      fp binary xrefs-rva chrome.dll --target 0x2f11800 --section .rdata --kinds ptr

      # deliberately narrowed to one function (fast)
      fp binary xrefs-rva chrome.dll --target 0x2f10a40 --start 0x1c42000 --end 0x1c43f00
    """
    from fridapilot.tools.pe_rva import section_range, xrefs_to_rva

    kind_tuple = tuple(k.strip() for k in kinds.split(",") if k.strip())
    start_rva = int(start, 0) if start else None
    end_rva = int(end, 0) if end else None
    results = xrefs_to_rva(binary, int(target, 0), start_rva, end_rva,
                           kinds=kind_tuple, verify=not no_verify,
                           scan_gaps=not pdata_only,
                           section="" if (start_rva is not None and end_rva is not None)
                                   else section,
                           use_index=not no_index)


    if json_output:
        _emit_json(results)
        return

    # Show what was actually covered - the fix for the failure mode where a third of
    # a 240 MB .text was scanned and the empty result was read as "no references".
    sec = section_range(binary, section) if section else None
    scanned_lo = start_rva if start_rva is not None else (sec or {}).get("start_rva", 0)
    scanned_hi = end_rva if end_rva is not None else (sec or {}).get("end_rva", 0)
    span = max(scanned_hi - scanned_lo, 0)
    coverage = ""
    if sec and sec["size"]:
        pct = 100.0 * span / sec["size"]
        coverage = f" = {pct:.1f}% of {section}"
        if pct < 99.9:
            coverage += " [yellow](partial!)[/yellow]"

    console.print(f"[bold]RVA xrefs to 0x{int(target, 0):x}[/bold] — {len(results)} found")
    console.print(f"[dim]scanned 0x{scanned_lo:x}-0x{scanned_hi:x} "
                  f"({span / 1048576:.2f} MB{coverage})[/dim]")
    for x in results:
        console.print(f"  RVA 0x{x['from_rva']:08x}  [{x['kind']:<5s}]  "
                      f"{x['mnemonic']} {escape(x['op_str'])}")
    if not results and "ptr" not in kind_tuple:
        from fridapilot.tools.pe_rva import PEImage
        img = PEImage(binary)
        tgt = int(target, 0)
        if img.is_executable(img.section_of(tgt) or ""):
            console.print("[yellow]  0 hits on a CODE address.[/yellow] A function that is only "
                          "dispatched indirectly (C++ virtual, Blink IDL binding table, import "
                          "thunk) is never the operand of a call/jmp — its address sits in a "
                          "data-section pointer table.")
            console.print(f"[dim]  Run: fp binary callers {binary} --target 0x{tgt:x}[/dim]")
        else:
            console.print("[dim]  Tip: 0 hits for a string that is clearly used? It may be "
                          "in a const char* table — retry with --section .rdata --kinds ptr, "
                          "or the string may be built inline with movabs immediates "
                          "(use inline-strings instead).[/dim]")


@binary_app.command("vtable")
def vtable_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    target: str = typer.Option(..., "--target", "-t",
                               help="RVA of the virtual method BODY (not a slot)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Which vtable holds this method, at which slot, and for which class.

    This is the decidable direction of the vtable question. The reverse — taking a
    slot offset such as 0x1f8 from a dispatch site and asking which class it belongs
    to — is NOT decidable statically: the object's dynamic type is not in the
    instruction stream, so `field-refs --offset 0x1f8` matches unrelated classes
    (measured: 200+ hits in one Chromium-sized DLL). Start from the implementation.

    Examples:
      fp binary vtable target.dll --target 0x4f1a20
      fp binary vtable target.dll --target 0x4f1a20 --json
    """
    from fridapilot.tools.pe_rva import vtable_of_function

    filepath = Path(binary)
    if not filepath.exists():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    try:
        tables = vtable_of_function(binary, int(target, 0))
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    if json_output:
        _emit_json(tables)
        return

    if not tables:
        console.print(f"[yellow]0x{int(target, 0):x} is in no pointer table.[/yellow]")
        console.print("[dim]  It is probably called directly — try "
                      f"`fp binary callers {binary} --target {target}`.[/dim]")
        return

    table = Table(title=f"Tables containing 0x{int(target, 0):x} ({len(tables)})")
    table.add_column("Table RVA", style="cyan")
    table.add_column("Slot", justify="right")
    table.add_column("Entries", justify="right")
    table.add_column("Section")
    table.add_column("RTTI class", style="green")
    table.add_column("Installed by", style="dim")
    for t in tables:
        rtti = t["rtti"]["mangled"] if t["rtti"] else "-"
        refs = ", ".join(f"0x{r:x}" for r in t["vtable_refs"][:3]) or "-"
        if len(t["vtable_refs"]) > 3:
            refs += f" (+{len(t['vtable_refs']) - 3})"
        table.add_row(f"0x{t['vtable_rva']:08x}", f"#{t['slot_index']}",
                      str(t["entries"]), t["section"], escape(rtti), refs)
    console.print(table)

    if all(t["rtti"] is None for t in tables):
        console.print("[dim]No RTTI (normal for -fno-rtti builds such as Chromium). The "
                      "'Installed by' constructors are the route to the class name: "
                      "disassemble them and look at the other members they touch.[/dim]")
    lone = [t for t in tables if t["entries"] == 1]
    if lone:
        console.print(f"[dim]{len(lone)} single-entry table(s): an isolated function "
                      "pointer (callback / thunk), not a vtable.[/dim]")


@binary_app.command("callers")
def callers_cmd(
    binary: str = typer.Argument(..., help="Path to PE file."),
    target: str = typer.Option(..., "--target", "-t", help="RVA of the function."),
    follow: bool = typer.Option(
        False, "--follow",
        help="Also find the instructions that load the pointer slots (the dispatch "
             "sites). One extra scan of the code sections, regardless of slot count.",
    ),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip capstone verification."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Who reaches this function — direct call/jmp AND pointer-table entries.

    `xrefs-rva --kinds call,jmp` only answers "who branches straight to this address".
    Virtual methods, script-binding table entries, import thunks and callbacks have no
    such instruction anywhere: the only occurrence of their address is an 8-byte pointer
    in a data section. Asking "who calls it" then returns 0 whether the function is hot
    or dead. This command scans every code section for branches and every data section
    for pointers, and states which case it found.

    Examples:
      fp binary callers target.dll --target 0x4f1a20
      fp binary callers target.dll --target 0x4f1a20 --follow --json
    """
    from fridapilot.tools.pe_rva import function_xrefs

    filepath = Path(binary)
    if not filepath.exists():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    res = function_xrefs(binary, int(target, 0), follow=follow, verify=not no_verify)

    if json_output:
        _emit_json(res)
        return

    console.print(f"[bold]Callers of 0x{res['target_rva']:x}[/bold] "
                  f"({res['target_section'] or 'unmapped'}, "
                  f"{'code' if res['target_is_code'] else 'data'})")
    console.print(f"[dim]swept {len(res['scanned'])} section(s): "
                  + ", ".join(f"{s['section']}[{s['kinds']}]" for s in res["scanned"])
                  + "[/dim]")

    if res["direct"]:
        table = Table(title=f"Direct branches ({len(res['direct'])})")
        table.add_column("RVA", style="cyan")
        table.add_column("Kind")
        table.add_column("Section")
        table.add_column("In function", style="dim")
        for r in res["direct"]:
            fn = f"0x{r['func_begin_rva']:x}" if r.get("func_begin_rva") is not None else "-"
            table.add_row(f"0x{r['from_rva']:08x}", r["kind"], r["section"], fn)
        console.print(table)

    if res["indirect"]:
        table = Table(title=f"Pointer-table slots ({len(res['indirect'])})")
        table.add_column("Slot RVA", style="cyan")
        table.add_column("Section")
        for r in res["indirect"]:
            table.add_row(f"0x{r['from_rva']:08x}", r["section"])
        console.print(table)

    if res["dispatchers"]:
        table = Table(title=f"Dispatch sites ({len(res['dispatchers'])})")
        table.add_column("RVA", style="cyan")
        table.add_column("Loads slot")
        table.add_column("Instruction", style="green")
        table.add_column("In function", style="dim")
        for d in res["dispatchers"]:
            fn = f"0x{d['func_begin_rva']:x}" if d.get("func_begin_rva") is not None else "-"
            table.add_row(f"0x{d['from_rva']:08x}", f"0x{d['slot_rva']:x}",
                          f"{d['mnemonic']} {escape(d['op_str'])}", fn)
        console.print(table)

    style = "green" if (res["direct"] or res["indirect"]) else "yellow"
    console.print(f"[{style}]{res['verdict']}[/{style}]")
    if res["indirect"] and not follow:
        console.print("[dim]  Add --follow to find the code that loads those slots.[/dim]")



@binary_app.command("analyze-macho")
def analyze_macho_cmd(
    binary: str = typer.Argument(..., help="Path to Mach-O binary."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Analyze a Mach-O binary: header, segments, load commands, FairPlay encryption, dylibs."""
    import json as json_mod
    from fridapilot.tools.binary_analysis import analyze_macho

    result = analyze_macho(binary)

    if json_output:
        out = {
            "filepath": result.filepath,
            "is_fat": result.is_fat,
            "architectures": result.architectures,
            "cpu_type": result.cpu_type,
            "is_64bit": result.is_64bit,
            "encrypted": result.encrypted,
            "cryptid": result.cryptid,
            "min_os": result.min_os,
            "segments": [{"name": s.name, "vmaddr": s.vmaddr, "vmsize": s.vmsize,
                          "fileoff": s.fileoff, "filesize": s.filesize,
                          "sections": s.sections} for s in result.segments],
            "dylibs": result.dylibs,
            "load_commands_count": len(result.load_commands),
        }
        console.print(json_mod.dumps(out, indent=2, default=str))
        return

    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="Mach-O Analysis"))

    info = Table(show_header=False)
    info.add_row("CPU", result.cpu_type)
    info.add_row("64-bit", "Yes" if result.is_64bit else "No")
    info.add_row("Fat Binary", "Yes" if result.is_fat else "No")
    if result.is_fat:
        info.add_row("Architectures", ", ".join(result.architectures))
    enc_color = "red" if result.encrypted else "green"
    info.add_row("Encrypted", f"[{enc_color}]{'Yes (cryptid=' + str(result.cryptid) + ')' if result.encrypted else 'No'}[/{enc_color}]")
    if result.min_os:
        info.add_row("Min OS", result.min_os)
    info.add_row("Load Commands", str(len(result.load_commands)))
    console.print(info)

    if result.segments:
        seg_table = Table(title="Segments")
        seg_table.add_column("Name")
        seg_table.add_column("VMAddr", justify="right")
        seg_table.add_column("VMSize", justify="right")
        seg_table.add_column("FileOff", justify="right")
        seg_table.add_column("Sections")
        for s in result.segments:
            secs = ", ".join(sec["name"] for sec in s.sections[:5])
            if len(s.sections) > 5:
                secs += f" +{len(s.sections) - 5}"
            seg_table.add_row(s.name, f"0x{s.vmaddr:x}", f"0x{s.vmsize:x}",
                              f"0x{s.fileoff:x}", secs)
        console.print(seg_table)

    if result.dylibs:
        console.print(f"\n[bold]Dynamic Libraries:[/bold] ({len(result.dylibs)})")
        for lib in result.dylibs[:20]:
            console.print(f"  {lib}")
        if len(result.dylibs) > 20:
            console.print(f"  ... and {len(result.dylibs) - 20} more")

    if result.encrypted:
        console.print("\n[bold yellow]FairPlay DRM detected![/bold yellow] Use frida-ios-dump to decrypt:")
        console.print("  frida-ios-dump -H <device_ip> -p 22 \"App Name\"")


@binary_app.command("index-build")
def index_build_cmd(
    binary: str = typer.Argument(..., help="Path to a PE file."),
    section: str = typer.Option(".text", "--section", "-s", help="Code section to scan."),
    targets_in: str = typer.Option(
        "", "--targets-in",
        help="Comma list of data sections whose targets to record (default: all "
             "non-executable sections).",
    ),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Scan once, then answer xref queries from an index instead of rescanning.

    xrefs-rva costs the same whether you ask about one target or twenty, so a
    multi-day investigation re-decodes the same .text over and over. This decodes
    every .pdata function once and stores each rip reference whose target lands in a
    data section; afterwards `xrefs-rva --kinds rip` is a database query.

    The index records the range, section and target sections it covers, and refuses
    queries outside them, so it can never answer with a short list that looks
    complete. Rebuild after patching the binary - the index is keyed by file hash,
    so a modified file simply has no index rather than a stale one.
    """
    from fridapilot.tools.rip_index import build_rip_index

    if not Path(binary).is_file():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    sections = [s.strip() for s in targets_in.split(",") if s.strip()] or None
    err_console.print(f"[dim]Scanning {section} of {Path(binary).name}…[/dim]")
    stats = build_rip_index(binary, section=section, target_sections=sections)

    if json_output:
        _emit_json(stats)
        return

    console.print(f"[green]Indexed[/green] {stats['refs']} rip references to "
                  f"{stats['targets']} distinct targets in {stats['seconds']}s")
    console.print(f"  scanned {section} 0x{stats['scan_start_rva']:x}-"
                  f"0x{stats['scan_end_rva']:x}")
    console.print("  target sections: " + ", ".join(
        f"{name} (0x{lo:x}-0x{hi:x})" for lo, hi, name in stats["target_ranges"]))
    console.print(f"  [dim]{stats['db_path']}[/dim]")


@binary_app.command("index-info")
def index_info_cmd(
    binary: str = typer.Argument("", help="Path to a PE file (omit to list all indexes)."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Show the stored rip index for a file, or list every index."""
    from fridapilot.tools.rip_index import index_info, list_indexes

    if not binary:
        entries = list_indexes()
        if json_output:
            _emit_json(entries)
            return
        if not entries:
            console.print("No indexes built yet. Run: fp binary index-build <file>")
            return
        table = Table(title="Rip indexes")
        table.add_column("File", overflow="fold")
        table.add_column("Section")
        table.add_column("Refs", justify="right")
        table.add_column("Build s", justify="right")
        table.add_column("Built at")
        for e in entries:
            table.add_row(e["filepath"], e["section"], str(e["ref_count"]),
                          f"{e['build_seconds']:.1f}", e["built_at"])
        console.print(table)
        return

    if not Path(binary).is_file():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)

    info = index_info(binary)
    if info is None:
        console.print("[yellow]No index for this file content.[/yellow] "
                      "Build one: fp binary index-build <file>")
        raise typer.Exit(1)

    if json_output:
        _emit_json(info)
        return

    console.print(Panel(
        f"{info['filepath']}\n"
        f"sha256: {info['sha256'][:32]}…\n"
        f"section: {info['section']}  0x{info['scan_start_rva']:x}-0x{info['scan_end_rva']:x}\n"
        f"refs: {info['ref_count']}   built: {info['built_at']} "
        f"({info['build_seconds']:.1f}s)\n"
        f"targets: " + ", ".join(f"{n}" for _lo, _hi, n in info["target_ranges"]),
        title="Rip index",
    ))


@binary_app.command("index-drop")
def index_drop_cmd(
    binary: str = typer.Argument(..., help="Path to a PE file."),
) -> None:
    """Delete the stored rip index for this file content."""
    from fridapilot.tools.rip_index import drop_index

    if not Path(binary).is_file():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)
    if drop_index(binary):
        console.print("[green]Index dropped.[/green]")
    else:
        console.print("[yellow]No index for this file content.[/yellow]")


@binary_app.command("metadata")

def metadata_cmd(
    binary: str = typer.Argument(..., help="Path to a PE file (.exe / .dll)."),
    limit: int = typer.Option(15, "--limit", "-l", help="Max rows per list."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Metadata recon: PDB GUID, version resource, manifest, Rich header, toolchain.

    Run this *first*. It is the cheapest pass there is and it often decides the rest
    of the session: a PDB GUID pulls public symbols off the symbol server, a Rust
    panic path spells out the original source tree, a version resource names the
    vendor. Reaching for the disassembler before checking what the build leaked is
    doing the work in the wrong order.
    """
    from fridapilot.tools.pe_metadata import pe_metadata

    if not Path(binary).is_file():
        console.print(f"[red]File not found: {binary}[/red]")
        raise typer.Exit(1)


    meta = pe_metadata(binary)

    if json_output:
        _emit_json(meta)
        return

    dbg = meta["debug"]
    console.print(Panel(
        f"{meta['filepath']}\n"
        f"{'DLL' if meta['is_dll'] else 'EXE'}  machine={meta['machine']}  "
        f"{'.NET  ' if meta['is_dotnet'] else ''}toolchain={', '.join(meta['toolchain']['guesses'])}\n"
        f"PDB: {dbg.get('pdb_path') or '(none)'}\n"
        f"GUID/Age: {dbg.get('pdb_guid', '-')} / {dbg.get('pdb_age', '-')}\n"
        f"Symbol server key: {dbg.get('symbol_server_key', '-')}",
        title="PE Metadata",
    ))

    if meta["version_info"]:
        table = Table(title="Version Resource")
        table.add_column("Key", style="cyan")
        table.add_column("Value", overflow="fold")
        for key, value in list(meta["version_info"].items())[:limit]:
            table.add_row(key, str(value))
        console.print(table)

    if meta["manifest"]:
        console.print("[bold]Manifest[/bold]")
        for key, value in meta["manifest"].items():
            console.print(f"  {key}: {escape(str(value)[:200])}")

    sec = meta["security"]
    console.print("[bold]Security[/bold]  " + "  ".join(
        f"{k}={'[green]on[/green]' if v else '[red]off[/red]'}" for k, v in sec.items()))

    dyn = meta["dynamic_api_resolution"]
    console.print(f"[bold]Imports[/bold] {dyn['imported_functions']} functions; "
                  f"resolvers: {', '.join(dyn['resolvers']) or 'none'}"
                  + ("  [yellow](APIs likely resolved at runtime)[/yellow]"
                     if dyn["suspicious"] else ""))

    if meta["coff_symbols"]:
        console.print(f"[bold]COFF symbols[/bold] ({len(meta['coff_symbols'])}, kept by the linker)")
        for name in meta["coff_symbols"][:limit]:
            console.print(f"  {name}")

    rust = meta.get("rust")
    if rust:
        console.print(f"[bold]Rust source paths[/bold] ({len(rust['source_paths'])}, "
                      f"{len(rust['own_source_paths'])} outside the toolchain)")
        for path in rust["own_source_paths"][:limit]:
            console.print(f"  {escape(path)}")
        if rust["crates"]:
            console.print("[bold]Crates[/bold] " + ", ".join(
                f"{c['name']} {c['version']}" for c in rust["crates"][:limit]))

    rich_hdr = meta["rich_header"]
    if rich_hdr.get("entries"):
        console.print(f"[bold]Rich header[/bold] checksum=0x{rich_hdr['checksum']:x}, "
                      f"{len(rich_hdr['entries'])} build records")

    if meta["resources"]:
        console.print("[bold]Resources[/bold] " + ", ".join(
            f"{k}={v}" for k, v in meta["resources"].items()))

    table = Table(title="Sections")
    table.add_column("Name", style="cyan")
    table.add_column("RVA", justify="right")
    table.add_column("VSize", justify="right")
    table.add_column("Entropy", justify="right")
    table.add_column("Flags")
    for s in meta["sections"]:
        flags = ("X" if s["executable"] else "") + ("W" if s["writable"] else "")
        entropy = f"{s['entropy']:.2f}"
        style = "yellow" if s["entropy"] > 7.2 else ""
        table.add_row(s["name"], f"0x{s['virtual_address']:x}", f"0x{s['virtual_size']:x}",
                      f"[{style}]{entropy}[/{style}]" if style else entropy, flags)
    console.print(table)


