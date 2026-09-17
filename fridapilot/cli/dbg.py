"""fp dbg - Interactive Frida-based debugger with GDB-like commands.

Usage:
    fp dbg --target notepad.exe
    fp dbg --target 1234
    fp dbg --target com.example.app --device usb --spawn

Commands (GDB-style):
    b/break <addr>           Set breakpoint (0x... or module!export)
    b/break <addr> if <cond> Conditional breakpoint (JS expression)
    d/delete <id>            Remove breakpoint
    bl/info break            List breakpoints
    c/continue               Wait for next breakpoint hit
    r/regs                   Show registers
    x <addr> [size]          Examine memory (hex dump)
    x/s <addr>               Examine as string
    dis <addr> [count]       Disassemble at address
    bt/backtrace             Show backtrace (from last hit)
    p <expr>                 Evaluate JS expression in target
    w/watch <addr> <size>    Watch memory region for changes
    info modules             List loaded modules
    info exports <module>    List module exports
    info threads             List threads
    set <addr> <hex>         Write memory
    resolve <module!export>  Resolve symbol to address
    help                     Show this help
    q/quit                   Detach and exit
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def dbg_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d", help="Device: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
    spawn: bool = typer.Option(False, "--spawn", "-s", help="Spawn process instead of attach."),
) -> None:
    """Interactive Frida debugger with GDB-like commands (break, regs, examine, disasm)."""
    from fridapilot.models.schemas import DeviceType
    from fridapilot.tools.debugger import DebugSession

    device_type = DeviceType(device)

    # Resolve target as PID or name
    try:
        tgt: str | int = int(target)
    except ValueError:
        tgt = target

    console.print(Panel(
        f"[bold]FridaPilot Debugger[/bold]\n"
        f"Target: {target}  Device: {device}  Spawn: {spawn}\n"
        f"Type [cyan]help[/cyan] for commands, [cyan]q[/cyan] to quit.",
        title="fp dbg",
    ))

    dbg = DebugSession(tgt, device_type, host, spawn=spawn)
    try:
        dbg.connect()
        console.print(f"[green]Connected[/green] PID={dbg.pid} Arch={dbg.arch} Platform={dbg.platform}")
    except Exception as e:
        console.print(f"[red]Failed to connect: {e}[/red]")
        raise typer.Exit(1)

    last_hit = None  # Most recent BreakpointHit

    # ── REPL Loop ─────────────────────────────────────────
    try:
        while True:
            try:
                raw = console.input("[bold cyan]fp-dbg>[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not raw:
                continue

            parts = raw.split(None, 1)
            cmd = parts[0].lower()
            args_str = parts[1] if len(parts) > 1 else ""

            # ── Quit ──
            if cmd in ("q", "quit", "exit"):
                break

            # ── Help ──
            elif cmd == "help":
                _show_help()

            # ── Break ──
            elif cmd in ("b", "break"):
                _cmd_break(dbg, args_str)

            # ── Delete breakpoint ──
            elif cmd in ("d", "delete"):
                _cmd_delete(dbg, args_str)

            # ── List breakpoints ──
            elif cmd in ("bl", "info") and args_str.startswith("break"):
                _cmd_list_bp(dbg)

            # ── Continue (wait for hit) ──
            elif cmd in ("c", "continue"):
                last_hit = _cmd_continue(dbg, args_str)

            # ── Registers ──
            elif cmd in ("r", "regs", "registers"):
                _cmd_regs(dbg, last_hit)

            # ── Examine memory ──
            elif cmd in ("x", "examine"):
                _cmd_examine(dbg, args_str)

            # ── Disassemble ──
            elif cmd in ("dis", "disasm", "disassemble"):
                _cmd_disasm(dbg, args_str, last_hit)

            # ── Backtrace ──
            elif cmd in ("bt", "backtrace"):
                _cmd_backtrace(last_hit)

            # ── Print / Evaluate ──
            elif cmd in ("p", "print", "eval"):
                _cmd_eval(dbg, args_str)

            # ── Watch ──
            elif cmd in ("w", "watch"):
                _cmd_watch(dbg, args_str)

            # ── Set memory ──
            elif cmd == "set":
                _cmd_set_memory(dbg, args_str)

            # ── Resolve symbol ──
            elif cmd == "resolve":
                _cmd_resolve(dbg, args_str)

            # ── Info commands ──
            elif cmd == "info":
                _cmd_info(dbg, args_str)

            else:
                console.print(f"[yellow]Unknown command: {cmd}. Type 'help' for commands.[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        dbg.disconnect()
        console.print("[dim]Detached.[/dim]")


# ── Command Implementations ───────────────────────────────────


def _show_help() -> None:
    help_text = """\
[bold]Breakpoints:[/bold]
  b <addr>              Set breakpoint (0x... or module!export)
  b <addr> if <cond>    Conditional breakpoint (JS condition)
  d <id>                Delete breakpoint
  bl / info break       List all breakpoints

[bold]Execution:[/bold]
  c [timeout]           Wait for breakpoint hit (default: forever)

[bold]Inspection:[/bold]
  r / regs              Show CPU registers
  x <addr> [size]       Examine memory as hex dump (default 64 bytes)
  x/s <addr>            Examine memory as string
  dis <addr> [count]    Disassemble instructions (default 10)
  bt / backtrace        Show call stack from last hit

[bold]Modification:[/bold]
  set <addr> <hex>      Write hex bytes to memory
  w <addr> <size>       Watch memory region (poll for changes)

[bold]Info:[/bold]
  info modules          List loaded modules
  info exports <mod>    List exports of a module
  info threads          List threads
  resolve <mod!sym>     Resolve symbol to address

[bold]Evaluate:[/bold]
  p <js_expression>     Evaluate JS in target process

[bold]Other:[/bold]
  help                  Show this help
  q / quit              Detach and exit"""
    console.print(Panel(help_text, title="Commands"))


def _cmd_break(dbg, args_str: str) -> None:
    if not args_str:
        console.print("[red]Usage: b <address> [if <condition>][/red]")
        return
    condition = ""
    if " if " in args_str:
        addr_part, condition = args_str.split(" if ", 1)
        addr_part = addr_part.strip()
        condition = condition.strip()
    else:
        addr_part = args_str.strip()
    try:
        bp = dbg.add_breakpoint(addr_part, condition)
        cond_str = f" [dim]if {condition}[/dim]" if condition else ""
        console.print(f"  Breakpoint #{bp.id} at {bp.resolved_address}{cond_str}")
    except Exception as e:
        console.print(f"[red]Failed to set breakpoint: {e}[/red]")


def _cmd_delete(dbg, args_str: str) -> None:
    if not args_str:
        console.print("[red]Usage: d <breakpoint_id>[/red]")
        return
    try:
        bp_id = int(args_str.strip())
        if dbg.remove_breakpoint(bp_id):
            console.print(f"  Breakpoint #{bp_id} removed")
        else:
            console.print(f"[yellow]Breakpoint #{bp_id} not found[/yellow]")
    except ValueError:
        console.print("[red]Invalid breakpoint ID[/red]")


def _cmd_list_bp(dbg) -> None:
    bps = dbg.list_breakpoints()
    if not bps:
        console.print("  No breakpoints set.")
        return
    table = Table(title="Breakpoints")
    table.add_column("#", style="cyan", width=4)
    table.add_column("Address")
    table.add_column("Resolved")
    table.add_column("Hits", justify="right")
    table.add_column("Condition", style="dim")
    for bp in bps:
        table.add_row(str(bp.id), bp.address, bp.resolved_address, str(bp.hit_count), bp.condition or "-")
    console.print(table)

def _cmd_continue(dbg, args_str: str):
    timeout = float(args_str.strip()) if args_str.strip() else 0
    console.print("[dim]Waiting for breakpoint hit... (Ctrl+C to cancel)[/dim]")
    try:
        hit = dbg.wait_for_hit(timeout=timeout)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted[/yellow]")
        return None
    if hit:
        sym = dbg.resolve_address(hit.address)
        console.print(f"  [bold red]Hit[/bold red] BP#{hit.bp_id} at {hit.address} ({sym}) thread={hit.thread_id}")
        if hit.disassembly:
            for line in hit.disassembly[:5]:
                console.print(f"    {line}")
        return hit
    else:
        console.print("[yellow]Timeout, no breakpoint hit[/yellow]")
        return None


def _cmd_regs(dbg, last_hit) -> None:
    if last_hit and last_hit.registers.registers:
        regs = last_hit.registers.registers
    else:
        state = dbg.get_registers()
        regs = state.registers
    if not regs:
        console.print("[yellow]No register data available[/yellow]")
        return
    table = Table(title="Registers", show_header=False)
    table.add_column("Register", style="cyan", width=6)
    table.add_column("Value")
    for name, value in sorted(regs.items()):
        table.add_row(name, value)
    console.print(table)


def _cmd_examine(dbg, args_str: str) -> None:
    if not args_str:
        console.print("[red]Usage: x <address> [size] or x/s <address>[/red]")
        return
    # x/s <addr> — string mode
    if args_str.startswith("/s "):
        addr = args_str[3:].strip()
        try:
            s = dbg.read_string(addr)
            console.print(f"  {addr}: \"{s}\"")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        return
    parts = args_str.split()
    addr = parts[0]
    size = int(parts[1]) if len(parts) > 1 else 64
    try:
        dump = dbg.examine(addr, size)
        console.print(dump)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _cmd_disasm(dbg, args_str: str, last_hit) -> None:
    if not args_str and last_hit:
        # Disassemble at last hit PC
        addr = last_hit.address
        count = 10
    elif args_str:
        parts = args_str.split()
        addr = parts[0]
        count = int(parts[1]) if len(parts) > 1 else 10
    else:
        console.print("[red]Usage: dis <address> [count][/red]")
        return
    try:
        insns = dbg.disassemble(addr, count)
        for insn in insns:
            sym = dbg.resolve_address(insn["address"])
            prefix = f"  {insn['address']}"
            if sym and sym != insn["address"]:
                prefix += f" <{sym}>"
            console.print(f"{prefix}:  {insn['mnemonic']:<8s} {insn['opStr']}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _cmd_backtrace(last_hit) -> None:
    if not last_hit or not last_hit.backtrace:
        console.print("[yellow]No backtrace available. Use 'c' to hit a breakpoint first.[/yellow]")
        return
    console.print("[bold]Backtrace:[/bold]")
    for i, frame in enumerate(last_hit.backtrace):
        console.print(f"  #{i}  {frame}")


def _cmd_eval(dbg, args_str: str) -> None:
    if not args_str:
        console.print("[red]Usage: p <js_expression>[/red]")
        return
    result = dbg.evaluate(args_str)
    if result.get("success"):
        console.print(f"  = {result['result']}")
    else:
        console.print(f"  [red]Error: {result.get('error')}[/red]")


def _cmd_watch(dbg, args_str: str) -> None:
    parts = args_str.split()
    if len(parts) < 2:
        console.print("[red]Usage: w <address> <size>[/red]")
        return
    addr, size = parts[0], int(parts[1])
    console.print(f"  Watching {size} bytes at {addr}... (Ctrl+C to stop)")
    prev = dbg.read_memory(addr, size)
    try:
        import time
        while True:
            time.sleep(0.5)
            current = dbg.read_memory(addr, size)
            if current != prev:
                console.print(f"  [bold red]CHANGED[/bold red] at {addr}")
                console.print(f"    Old: {prev[:64]}{'...' if len(prev) > 64 else ''}")
                console.print(f"    New: {current[:64]}{'...' if len(current) > 64 else ''}")
                prev = current
    except KeyboardInterrupt:
        console.print("[dim]Watch stopped.[/dim]")


def _cmd_set_memory(dbg, args_str: str) -> None:
    parts = args_str.split()
    if len(parts) < 2:
        console.print("[red]Usage: set <address> <hex_bytes>[/red]")
        return
    addr, hex_data = parts[0], parts[1]
    try:
        written = dbg.write_memory(addr, hex_data)
        console.print(f"  Wrote {written} bytes to {addr}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _cmd_resolve(dbg, args_str: str) -> None:
    if not args_str or "!" not in args_str:
        console.print("[red]Usage: resolve module!export[/red]")
        return
    try:
        resolved = dbg._resolve_address(args_str.strip())
        console.print(f"  {args_str} -> {resolved}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _cmd_info(dbg, args_str: str) -> None:
    sub = args_str.strip().split(None, 1)
    subcmd = sub[0] if sub else ""

    if subcmd == "modules":
        mods = dbg.get_modules()
        table = Table(title=f"Modules ({len(mods)})")
        table.add_column("Name")
        table.add_column("Base", justify="right")
        table.add_column("Size", justify="right")
        for m in mods[:50]:
            table.add_row(m["name"], m["base"], str(m["size"]))
        console.print(table)
        if len(mods) > 50:
            console.print(f"  ... and {len(mods) - 50} more")

    elif subcmd == "exports":
        mod = sub[1].strip() if len(sub) > 1 else ""
        if not mod:
            console.print("[red]Usage: info exports <module_name>[/red]")
            return
        exports = dbg.get_exports(mod)
        table = Table(title=f"Exports: {mod} ({len(exports)})")
        table.add_column("Name")
        table.add_column("Address", justify="right")
        table.add_column("Type")
        for e in exports[:50]:
            table.add_row(e["name"], e["address"], e["type"])
        console.print(table)

    elif subcmd == "threads":
        threads = dbg.get_threads()
        table = Table(title=f"Threads ({len(threads)})")
        table.add_column("ID", justify="right")
        table.add_column("State")
        table.add_column("PC")
        for t in threads:
            table.add_row(str(t["id"]), t["state"], t.get("context_pc", ""))
        console.print(table)

    elif subcmd.startswith("break"):
        _cmd_list_bp(dbg)

    else:
        console.print("[yellow]info modules | info exports <mod> | info threads | info break[/yellow]")
