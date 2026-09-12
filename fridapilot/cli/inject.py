"""fp inject - Inject a Frida script into a running session."""

import typer
from rich.console import Console

from fridapilot.models.schemas import DeviceType

console = Console()


def inject_cmd(
    script: str = typer.Option(..., "--script", "-s", help="Path to Frida script file."),
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
    timeout: int = typer.Option(0, "--timeout", help="Seconds to collect messages (0 = until Ctrl+C)."),
) -> None:
    """Inject a Frida script into a target process."""
    import time

    from fridapilot.tools.injector import attach, inject, detach
    from fridapilot.tools.script_forge import load_script_file

    device_type = DeviceType(device)
    script_source = load_script_file(script)

    # Attach
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    console.print(f"[green]Attached to {session.target} (PID: {session.pid})[/green]")

    # Inject
    inject(session, script_source)
    console.print(f"[green]Script injected.[/green]")

    # Collect messages
    try:
        if timeout > 0:
            console.print(f"[dim]Collecting messages for {timeout}s...[/dim]")
            time.sleep(timeout)
        else:
            console.print("[dim]Collecting messages (Ctrl+C to stop)...[/dim]")
            while True:
                time.sleep(0.5)
                for msg in session.observer.messages:
                    console.print(f"  [{msg.type}] {msg.payload}")
                session.observer.messages.clear()
    except KeyboardInterrupt:
        pass
    finally:
        detach(session)
        console.print("[green]Detached.[/green]")
