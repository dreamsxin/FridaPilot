"""fp disasm - symbol- and section-annotated disassembly listing.

Presentation only: every address, section and function name comes from
``fridapilot.tools.disasm_view``. Three views over the same records - ``group``
(objdump-like, grouped under section/function headers), ``table`` (one row per
line, for filtering and sorting) and ``json``.
"""

from __future__ import annotations

import json as _json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

disasm_app = typer.Typer(no_args_is_help=True)

console = Console()
err_console = Console(stderr=True)

# Section colours: the reader's fastest signal is "am I still in code?".
_SECTION_STYLES = {
    ".text": "green", "__text": "green", ".init": "green", ".plt": "green",
    ".rdata": "blue", ".rodata": "blue", "__cstring": "blue", "__const": "blue",
    ".data": "yellow", "__data": "yellow", ".bss": "magenta", "__bss": "magenta",
    ".pdata": "cyan", ".idata": "cyan", ".edata": "cyan",
}


def _require_file(path: str) -> Path:
    p = Path(path)
    if not p.exists():
        err_console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(1)
    return p


def _section_style(name: str) -> str:
    short = name.split(",")[-1]
    return _SECTION_STYLES.get(name) or _SECTION_STYLES.get(short) or "white"


def _open_console(output: str, no_color: bool) -> tuple[Console, object | None]:
    """Console to render into, plus the file handle to close (None for stdout).

    A file gets a fixed width and no colour: Rich otherwise wraps at the terminal
    width and writes ANSI escapes into the file, which makes the saved listing
    unreadable in an editor.
    """
    if output:
        fh = open(output, "w", encoding="utf-8")
        return Console(file=fh, no_color=True, width=200, soft_wrap=False), fh
    return Console(no_color=no_color, soft_wrap=True), None


def _emit_json(obj, output: str) -> None:
    """Write JSON verbatim - never through Rich, which wraps and eats markup."""
    text = _json.dumps(obj, indent=2, default=str) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
        err_console.print(f"[dim]wrote {output}[/dim]")
    else:
        sys.stdout.write(text)


def _safe(text: str, limit: int = 120) -> str:
    """Make a string lifted out of a binary printable on THIS console."""
    cleaned = "".join(c if c.isprintable() else "." for c in text[:limit])
    codec = getattr(console.file, "encoding", None) or "utf-8"
    return escape(cleaned.encode(codec, "replace").decode(codec, "replace"))


def _instruction_text(line: dict) -> str:
    if line["kind"] == "insn":
        return f"{line['mnemonic']} {line['op_str']}".strip()
    if line["kind"] == "string":
        return f'"{line["text"]}"'
    if line["kind"] == "bad":
        return "(undecodable byte)"
    return line.get("text", "")


def _source_label(line: dict) -> str:
    if line.get("source_file") and line.get("source_line"):
        return f"{line['source_file']}:{line['source_line']}"
    return ""


def _print_header(out: Console, result: dict) -> None:
    out.print(f"[bold]{result['path']}[/bold]  {result['format'].upper()} "
              f"{result['arch']}/{result['bits']}  "
              f"image base 0x{result['image_base']:x}"
              + (f"  scope: {result['scope']}" if result.get("scope") else ""))
    for note in result.get("notes", []):
        out.print(f"[dim]note: {_safe(note, 300)}[/dim]")


def _render_group(out: Console, result: dict) -> None:
    """objdump-like: a header per section, a sub-header per function."""
    cur_section = cur_function = cur_source = None
    for line in result["lines"]:
        if line["section"] != cur_section:
            cur_section = line["section"]
            cur_function = None
            style = _section_style(cur_section)
            out.print(f"\n[{style} bold]{cur_section or '(no section)'}[/{style} bold]")
        if line["function"] != cur_function:
            cur_function = line["function"]
            cur_source = None
            if cur_function:
                # '?' marks an implied end: the symbol source recorded no size, so the
                # function was attributed from the preceding symbol. Not a measurement.
                mark = "" if line["function_exact"] else " [yellow](implied bounds)[/yellow]"
                out.print(f"  [cyan bold]{_safe(cur_function)}[/cyan bold]:{mark}")
            else:
                out.print("  [dim](no symbol)[/dim]")
        source = _source_label(line)
        if source and source != cur_source:
            # Printed once per change, the way objdump -S groups by source line -
            # repeating it on every instruction buries the disassembly.
            cur_source = source
            out.print(f"    [magenta]; {_safe(source, 120)}[/magenta]")
        target = f"   [cyan]; {_safe(line['target'], 90)}[/cyan]" if line["target"] else ""
        out.print(f"    [dim]{line['va']:016x}[/dim]  "
                  f"[dim]{line['bytes_hex'][:32]:<32s}[/dim]  "
                  f"{_safe(_instruction_text(line))}{target}")


def _render_table(out: Console, result: dict, show_bytes: bool, show_source: bool) -> None:
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Address", style="dim", no_wrap=True)
    if show_bytes:
        table.add_column("Bytes", style="dim", no_wrap=True)
    table.add_column("Instruction")
    table.add_column("Section", no_wrap=True)
    table.add_column("Function", style="cyan")
    if show_source:
        table.add_column("Source", style="magenta", no_wrap=True)
    for line in result["lines"]:
        style = _section_style(line["section"])
        func = line["function"] or ""
        if func and line["func_offset"]:
            func += f"+0x{line['func_offset']:x}"
        if func and not line["function_exact"]:
            func += "?"
        row = [f"0x{line['va']:x}"]
        if show_bytes:
            row.append(line["bytes_hex"][:32])
        row += [_safe(_instruction_text(line), 90),
                f"[{style}]{line['section']}[/{style}]", _safe(func, 80)]
        if show_source:
            row.append(_safe(_source_label(line), 80))
        table.add_row(*row)
    out.print(table)


@disasm_app.command("view")
def view_cmd(
    binary: str = typer.Argument(..., help="Path to a PE, ELF or Mach-O image."),
    section: str = typer.Option("", "--section", "-s",
                                help="List this section (.text, __text, ...)."),
    function: str = typer.Option("", "--function", "-f",
                                 help="List exactly this function's bounds."),
    start: str = typer.Option("", "--start", help="Start virtual address (hex/decimal)."),
    end: str = typer.Option("", "--end", help="End virtual address (exclusive)."),
    count: int = typer.Option(200, "--count", "-n", help="Maximum lines."),
    fmt: str = typer.Option("group", "--format", help="group, table or json."),
    show_bytes: bool = typer.Option(True, "--show-bytes/--no-bytes",
                                    help="Show raw bytes in the table view."),
    source: bool = typer.Option(False, "--source", "-S",
                                help="Resolve DWARF file:line per line (ELF only)."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colour."),
    output: str = typer.Option("", "--output", "-o", help="Write to a file instead of stdout."),
) -> None:
    """Disassembly with the address, section and owning function on every line.

    Addresses are VIRTUAL addresses (ImageBase applied for PE, link-time for ELF),
    not file offsets - unlike `fp binary disassemble`. Non-executable sections are
    shown as strings and hex rows rather than decoded, because feeding .rdata to a
    disassembler yields instructions that never execute.

    Default scope is the entry point; pass --section, --function or --start/--end.
    """
    from fridapilot.tools.disasm_view import disasm_listing

    _require_file(binary)
    if fmt not in ("group", "table", "json"):
        err_console.print(f"[red]Unknown --format {fmt!r}[/red] (group, table, json)")
        raise typer.Exit(1)
    try:
        result = disasm_listing(
            binary,
            section=section or None,
            function=function or None,
            start=int(start, 0) if start else None,
            end=int(end, 0) if end else None,
            count=count,
            source=source,
        )
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if fmt == "json":
        _emit_json(result, output)
        return
    if result.get("error"):
        err_console.print(f"[red]{_safe(result['error'], 300)}[/red]")
        raise typer.Exit(1)

    out, fh = _open_console(output, no_color)
    try:
        _print_header(out, result)
        if fmt == "table":
            _render_table(out, result, show_bytes, source)
        else:
            _render_group(out, result)
        if result["truncated"]:
            out.print(f"[yellow]truncated at {len(result['lines'])} lines[/yellow]")
    finally:
        if fh is not None:
            fh.close()
            err_console.print(f"[dim]wrote {output}[/dim]")


@disasm_app.command("sections")
def sections_cmd(
    binary: str = typer.Argument(..., help="Path to a PE, ELF or Mach-O image."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Section table: VA range, file offset, permissions, symbol count."""
    from fridapilot.tools.disasm_view import sections_view

    _require_file(binary)
    try:
        result = sections_view(binary)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if json_output:
        _emit_json(result, "")
        return

    console.print(f"[bold]{result['path']}[/bold]  {result['format'].upper()} "
                  f"{result['arch']}/{result['bits']}  "
                  f"image base 0x{result['image_base']:x}"
                  + (f"  entry 0x{result['entry_va']:x}" if result["entry_va"] else ""))
    for note in result["notes"]:
        console.print(f"[dim]note: {_safe(note, 300)}[/dim]")
    table = Table(header_style="bold")
    for col in ("Section", "VA", "End VA", "Size", "File off", "Perms", "Symbols"):
        table.add_column(col, no_wrap=True)
    for sec in result["sections"]:
        style = _section_style(sec["name"])
        table.add_row(
            f"[{style}]{sec['name']}[/{style}]",
            f"0x{sec['va']:x}", f"0x{sec['end_va']:x}", f"0x{sec['size']:x}",
            "-" if sec["file_offset"] < 0 else f"0x{sec['file_offset']:x}",
            sec["perms"], str(sec["symbols"]))
    console.print(table)


@disasm_app.command("symbols")
def symbols_cmd(
    binary: str = typer.Argument(..., help="Path to a PE, ELF or Mach-O image."),
    pattern: str = typer.Option("", "--pattern", "-p", help="Case-insensitive substring."),
    limit: int = typer.Option(200, "--limit", "-l", help="Maximum symbols to show."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Function symbols with section, size and where the name came from.

    A size of 0 means the source did not record one (PE exports, Mach-O nlist): the
    listing then attributes addresses to the preceding symbol and marks the bounds
    as implied.
    """
    from fridapilot.tools.disasm_view import symbols_view

    _require_file(binary)
    try:
        result = symbols_view(binary, pattern=pattern or None, limit=limit)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if json_output:
        _emit_json(result, "")
        return

    console.print(f"[bold]{result['path']}[/bold]  {result['format'].upper()}  "
                  f"{result['shown']} of {result['total']} symbols")
    for note in result["notes"]:
        console.print(f"[dim]note: {_safe(note, 300)}[/dim]")
    table = Table(header_style="bold")
    for col in ("VA", "Size", "Section", "Source", "Name"):
        table.add_column(col, no_wrap=col != "Name")
    for sym in result["symbols"]:
        name = _safe(sym["name"], 100)
        if sym["aliases"]:
            name += f" [dim](+{len(sym['aliases'])} alias)[/dim]"
        table.add_row(f"0x{sym['va']:x}",
                      f"0x{sym['size']:x}" if sym["size"] else "[dim]?[/dim]",
                      f"[{_section_style(sym['section'])}]{sym['section']}[/]",
                      sym["source"], name)
    console.print(table)
