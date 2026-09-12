"""fp ps - List processes on the target device."""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from fridapilot.models.schemas import DeviceType

console = Console()


def ps_cmd(
    device: str = typer.Option("local", "--device", "-d", help="Device type: local, usb, remote."),
    host: str = typer.Option("", "--host", "-H", help="Remote frida-server host:port."),
) -> None:
    """List running processes on the target device."""
    from fridapilot.tools.recon import list_processes

    device_type = DeviceType(device)
    processes = list_processes(device_type, host)

    table = Table(title=f"Processes ({device})")
    table.add_column("PID", style="cyan", justify="right")
    table.add_column("Name", style="green")
    for p in sorted(processes, key=lambda x: x.name.lower()):
        table.add_row(str(p.pid), p.name)
    console.print(table)
    console.print(f"[dim]Total: {len(processes)} processes[/dim]")
