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
    c/continue               Resume paused hits, then wait for the next hit
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
    session create <n> --target <proc> [--spawn]
                             Attach an extra process as a named session
    session list|switch <n>|remove <n>
                             Manage sessions; switch routes all commands to one
    wait-any [timeout]       Wait for a hit from any session
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
    multi_state = {"mgr": None, "active_session": None,
                   "device_type": device_type, "host": host}  # Multi-session state

    # ── REPL Loop ─────────────────────────────────────────
    try:
        while True:
            try:
                label = multi_state.get("active_session") or ""
                raw = console.input(
                    "[bold cyan]fp-dbg%s>[/bold cyan] " % (":" + label if label else "")
                ).strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not raw:
                continue

            parts = raw.split(None, 1)
            cmd = parts[0].lower()
            args_str = parts[1] if len(parts) > 1 else ""
            # GDB muscle memory: `x/s 0x401000` must reach the examine
            # handler with the /s flag intact (audit finding M-D1 - it
            # used to fall through to "Unknown command").
            if cmd.startswith("x/"):
                args_str = cmd[1:] + ((" " + args_str) if args_str else "")
                cmd = "x"

            # Everything below acts on the active session (`session switch`), or on
            # the --target process when none is selected.
            cur = _active_dbg(dbg, multi_state)

            # ── Quit ──
            if cmd in ("q", "quit", "exit"):
                break

            # ── Help ──
            elif cmd == "help":
                _show_help()

            # ── Session management (multi-process) ──
            elif cmd == "session":
                _cmd_session(args_str, multi_state)

            # ── Wait for hit from any session ──
            elif cmd in ("wait-any", "waitany"):
                last_hit = _cmd_wait_any(multi_state, args_str)

            # ── Break ──
            elif cmd in ("b", "break"):
                _cmd_break(cur, args_str)

            # ── Delete breakpoint ──
            elif cmd in ("d", "delete"):
                _cmd_delete(cur, args_str)

            # ── List breakpoints ──
            elif cmd in ("bl", "info") and args_str.startswith("break"):
                _cmd_list_bp(cur)

            # ── Continue (wait for hit) ──
            elif cmd in ("c", "continue"):
                last_hit = _cmd_continue(cur, args_str)

            # ── Registers ──
            elif cmd in ("r", "regs", "registers"):
                _cmd_regs(cur, last_hit)

            # ── Examine memory ──
            elif cmd in ("x", "examine"):
                _cmd_examine(cur, args_str)

            # ── Disassemble ──
            elif cmd in ("dis", "disasm", "disassemble"):
                _cmd_disasm(cur, args_str, last_hit)

            # ── Backtrace ──
            elif cmd in ("bt", "backtrace"):
                _cmd_backtrace(last_hit)

            # ── Print / Evaluate ──
            elif cmd in ("p", "print", "eval"):
                _cmd_eval(cur, args_str)

            # ── Watch ──
            elif cmd in ("w", "watch"):
                _cmd_watch(cur, args_str)

            # ── Set memory ──
            elif cmd == "set":
                _cmd_set_memory(cur, args_str)

            # ── Resolve symbol ──
            elif cmd == "resolve":
                _cmd_resolve(cur, args_str)

            # ── Info commands ──
            elif cmd == "info":
                _cmd_info(cur, args_str)

            else:
                console.print(f"[yellow]Unknown command: {cmd}. Type 'help' for commands.[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        mgr = multi_state.get("mgr")
        if mgr is not None:
            mgr.disconnect_all()
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

[bold]Multi-process:[/bold]
  session create <n> --target <proc> [--spawn]
                        Attach an extra process as a named session
  session list          List sessions (* = active)
  session switch <n>    Route all commands to that session ('-' = --target process)
  session remove <n>    Detach and drop a session
  wait-any [timeout]    Wait for a breakpoint hit from any session

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
    try:
        timeout = float(args_str.strip()) if args_str.strip() else 0
    except ValueError:
        console.print("[red]Usage: c [timeout-seconds][/red]")
        return None
    if timeout != timeout or timeout == float("inf") or timeout < 0:
        console.print("[red]Invalid timeout: use a finite number >= 0[/red]")
        return None
    # GDB semantics: `c` releases threads frozen on a paused hit, then
    # waits for the NEXT hit (audit finding H-D2).
    try:
        resumed = dbg.continue_execution()
    except Exception:
        resumed = 0
    if resumed:
        console.print(f"[green]Resumed {resumed} paused hit(s)[/green]")
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
        try:
            state = dbg.get_registers()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return
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
    try:
        size = int(parts[1]) if len(parts) > 1 else 64
    except ValueError:
        console.print("[red]Usage: x <address> [size] - size must be an integer[/red]")
        return
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
        try:
            count = int(parts[1]) if len(parts) > 1 else 10
        except ValueError:
            console.print("[red]Usage: dis <address> [count] - count must be an integer[/red]")
            return
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
    try:
        addr, size = parts[0], int(parts[1])
    except ValueError:
        console.print("[red]Usage: w <address> <size> - size must be an integer[/red]")
        return
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
        try:
            mods = dbg.get_modules()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return
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
        try:
            exports = dbg.get_exports(mod)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return
        table = Table(title=f"Exports: {mod} ({len(exports)})")
        table.add_column("Name")
        table.add_column("Address", justify="right")
        table.add_column("Type")
        for e in exports[:50]:
            table.add_row(e["name"], e["address"], e["type"])
        console.print(table)

    elif subcmd == "threads":
        try:
            threads = dbg.get_threads()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return
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


# ── Multi-Session Commands ────────────────────────────────────

def _active_dbg(default_dbg, state: dict):
    """The session that commands operate on.

    ``session switch`` only records a name; without resolving it here every
    command would keep talking to the ``--target`` process, so switching looked
    like it worked and silently did nothing.
    """
    name = state.get("active_session")
    mgr = state.get("mgr")
    if not name or mgr is None:
        return default_dbg
    try:
        return mgr.session(name)
    except KeyError:
        state["active_session"] = None
        console.print(f"[yellow]Session '{name}' is gone; using the --target process.[/yellow]")
        return default_dbg


def _cmd_session(args_str: str, state: dict) -> None:
    """Handle session management commands for multi-process debugging."""
    from fridapilot.tools.debugger import DebugSessionManager

    mgr = state.get("mgr")
    parts = args_str.strip().split(None, 1)
    subcmd = parts[0] if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    if subcmd == "create":
        # session create <name> --target <proc> [--spawn]
        if not mgr:
            mgr = DebugSessionManager()
            state["mgr"] = mgr
        tokens = rest.split()
        if len(tokens) < 3 or "--target" not in tokens:
            console.print("[red]Usage: session create <name> --target <proc> [--spawn][/red]")
            return
        name = tokens[0]
        target_idx = tokens.index("--target") + 1
        target = tokens[target_idx] if target_idx < len(tokens) else ""
        spawn = "--spawn" in tokens
        try:
            tgt: str | int
            try:
                tgt = int(target)
            except ValueError:
                tgt = target
            sess = mgr.create(name, tgt, device_type=state.get("device_type"),
                              host=state.get("host", ""), spawn=spawn)
            sess.connect()
            console.print(f"  [green]Session '{name}' created[/green]: PID={sess.pid} Arch={sess.arch}")
        except Exception as e:
            console.print(f"  [red]Failed: {e}[/red]")
            # Roll back the half-created entry so `session list` does not
            # show a dead session (audit finding M-D5).
            try:
                mgr.remove(name)
            except Exception:
                pass

    elif subcmd == "list":
        if not mgr:
            console.print("  No sessions. Use: session create <name> --target <proc>")
            return
        sessions = mgr.list_sessions()
        if not sessions:
            console.print("  No active sessions.")
            return
        active = state.get("active_session")
        table = Table(title="Debug Sessions")
        table.add_column("", style="bold green")
        table.add_column("Name", style="cyan")
        table.add_column("Target")
        table.add_column("PID", justify="right")
        table.add_column("Arch")
        table.add_column("BPs", justify="right")
        table.add_column("Connected")
        for s in sessions:
            table.add_row("*" if s["name"] == active else "",
                          s["name"], str(s["target"]), str(s["pid"]), s["arch"],
                          str(s["breakpoints"]), "[green]Yes[/green]" if s["connected"] else "[red]No[/red]")
        console.print(table)

    elif subcmd == "switch":
        name = rest.strip()
        if not name:
            console.print("[red]Usage: session switch <name> | session switch - (back to --target)[/red]")
            return
        if name == "-":
            state["active_session"] = None
            console.print("  Switched back to the --target process.")
            return
        if not mgr:
            console.print("[red]No sessions. Use: session create <name> --target <proc>[/red]")
            return
        try:
            sess = mgr.session(name)
            state["active_session"] = name
            console.print(f"  Switched to session '{name}' (PID={sess.pid})")
        except KeyError as e:
            console.print(f"  [red]{e}[/red]")

    elif subcmd == "remove":
        if not mgr or not rest.strip():
            console.print("[red]Usage: session remove <name>[/red]")
            return
        name = rest.strip()
        mgr.remove(name)
        if state.get("active_session") == name:
            state["active_session"] = None
        console.print(f"  Session '{name}' removed.")

    else:
        console.print("[yellow]session create <name> --target <proc> [--spawn][/yellow]")
        console.print("[yellow]session list | session switch <name>|- | session remove <name>[/yellow]")



def _cmd_wait_any(state: dict, args_str: str):
    """Wait for a breakpoint hit from any session."""
    mgr = state.get("mgr")
    if not mgr:
        console.print("[yellow]No multi-session manager. Use 'session create' first.[/yellow]")
        return None

    try:
        timeout = float(args_str.strip()) if args_str.strip() else 0
    except ValueError:
        console.print("[red]Usage: wait-any [timeout-seconds][/red]")
        return None
    if timeout != timeout or timeout == float("inf") or timeout < 0:
        console.print("[red]Invalid timeout: use a finite number >= 0[/red]")
        return None
    console.print("[dim]Waiting for hit from any session... (Ctrl+C to cancel)[/dim]")
    try:
        result = mgr.wait_any(timeout=timeout)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted[/yellow]")
        return None

    if result:
        name, hit = result
        console.print(f"  [bold red]Hit[/bold red] in session [cyan]{name}[/cyan] "
                      f"BP#{hit.bp_id} at {hit.address} thread={hit.thread_id}")
        if hit.disassembly:
            for line in hit.disassembly[:5]:
                console.print(f"    {line}")
        return hit
    else:
        console.print("[yellow]Timeout[/yellow]")
        return None
