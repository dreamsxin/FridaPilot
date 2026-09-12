"""fp observe - Collect messages from a running Frida session."""

import typer
from rich.console import Console

from fridapilot.models.schemas import DeviceType

console = Console()


def observe_cmd(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    script: str = typer.Option(..., "--script", "-s", help="Path to Frida script file."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
    output: str = typer.Option("", "--output", "-o", help="Output file (json or md)."),
    timeout: int = typer.Option(0, "--timeout", help="Seconds to observe (0 = until Ctrl+C)."),
) -> None:
    """Inject a script and observe messages, then optionally write a report."""
    import json
    import time

    from fridapilot.tools.injector import attach, inject, detach
    from fridapilot.tools.script_forge import load_script_file

    device_type = DeviceType(device)
    script_source = load_script_file(script)

    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    inject(session, script_source)
    console.print(f"[green]Observing {session.target} (PID: {session.pid})...[/green]")

    try:
        if timeout > 0:
            time.sleep(timeout)
        else:
            while True:
                time.sleep(0.5)
                for msg in session.observer.messages:
                    console.print(f"  [{msg.type}] {msg.payload}")
                session.observer.messages.clear()
    except KeyboardInterrupt:
        pass
    finally:
        messages = [m.to_dict() for m in session.observer.messages]
        detach(session)

    if output:
        from pathlib import Path
        Path(output).write_text(json.dumps(messages, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Messages written to {output}[/green]")
    else:
        console.print(f"[dim]Collected {len(messages)} messages.[/dim]")
