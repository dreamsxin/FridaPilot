"""fp bypass - SSL pinning, anti-debug, anti-Frida bypasses."""

import typer
from rich.console import Console

from fridapilot.models.schemas import DeviceType

console = Console()
bypass_app = typer.Typer(no_args_is_help=True)


@bypass_app.command("ssl-pinning")
def bypass_ssl(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Bypass SSL certificate pinning."""
    import time

    from fridapilot.tools.bypass import get_ssl_bypass_script
    from fridapilot.tools.injector import attach, inject, detach

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    script_source = get_ssl_bypass_script()
    inject(session, script_source)
    console.print(f"[green]SSL pinning bypass injected into {session.target}[/green]")

    try:
        console.print("[dim]Running... Ctrl+C to stop.[/dim]")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        detach(session)
        console.print("[green]Detached.[/green]")


@bypass_app.command("anti-debug")
def bypass_anti_debug(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Bypass anti-debug detection (ptrace)."""
    import time

    from fridapilot.tools.bypass import get_anti_debug_script
    from fridapilot.tools.injector import attach, inject, detach

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    script_source = get_anti_debug_script()
    inject(session, script_source)
    console.print(f"[green]Anti-debug bypass injected into {session.target}[/green]")

    try:
        console.print("[dim]Running... Ctrl+C to stop.[/dim]")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        detach(session)
        console.print("[green]Detached.[/green]")
