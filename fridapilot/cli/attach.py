"""fp attach / spawn / detach - Session lifecycle commands."""

from typing import Optional

import typer
from rich.console import Console

from fridapilot.models.schemas import DeviceType

console = Console()

# Module-level session reference (single-session CLI mode)
_current_session = None


def attach_cmd(
    target: str = typer.Argument(..., help="Process name or PID to attach to."),
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
) -> None:
    """Attach to a running process."""
    from fridapilot.tools.injector import attach

    global _current_session
    device_type = DeviceType(device)

    # Try to parse as PID
    try:
        pid = int(target)
        _current_session = attach(pid, device_type, host)
    except ValueError:
        _current_session = attach(target, device_type, host)

    console.print(f"[green]Attached to {_current_session.target} (PID: {_current_session.pid})[/green]")


def spawn_cmd(
    package: str = typer.Argument(..., help="Package/bundle to spawn."),
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
) -> None:
    """Spawn an application and attach."""
    from fridapilot.tools.injector import spawn

    global _current_session
    device_type = DeviceType(device)
    _current_session = spawn(package, device_type, host)
    console.print(f"[green]Spawned {package} (PID: {_current_session.pid})[/green]")


def detach_cmd() -> None:
    """Detach from the current session."""
    from fridapilot.tools.injector import detach

    global _current_session
    if _current_session is None:
        console.print("[yellow]No active session.[/yellow]")
        raise typer.Exit(1)
    detach(_current_session)
    console.print(f"[green]Detached from {_current_session.target}.[/green]")
    _current_session = None
