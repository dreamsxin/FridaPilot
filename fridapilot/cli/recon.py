"""fp recon - Enumerate modules, classes, methods, exports."""

import typer
from rich.console import Console
from rich.table import Table

from fridapilot.models.schemas import DeviceType

console = Console()
recon_app = typer.Typer(no_args_is_help=True)


@recon_app.command("modules")
def recon_modules(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Enumerate loaded modules."""
    from fridapilot.tools.injector import attach, detach
    from fridapilot.tools.recon import enumerate_modules

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    try:
        modules = enumerate_modules(session.frida_session)
        table = Table(title=f"Modules ({session.target})")
        table.add_column("Name", style="cyan")
        table.add_column("Base", style="green")
        table.add_column("Size", justify="right")
        for m in modules:
            table.add_row(m.name, m.base_address, str(m.size))
        console.print(table)
    finally:
        detach(session)


@recon_app.command("classes")
def recon_classes(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    filter: str = typer.Option("", "--filter", "-f", help="Filter class names by prefix."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Enumerate Java/ObjC classes."""
    from fridapilot.tools.injector import attach, detach
    from fridapilot.tools.recon import enumerate_classes

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    try:
        classes = enumerate_classes(session.frida_session, filter_prefix=filter)
        for c in classes:
            console.print(c.name)
        console.print(f"[dim]Total: {len(classes)} classes[/dim]")
    finally:
        detach(session)


@recon_app.command("methods")
def recon_methods(
    target: str = typer.Option(..., "--target", "-t"),
    class_name: str = typer.Option(..., "--class", "-c", help="Fully qualified class name."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Enumerate methods of a class."""
    from fridapilot.tools.injector import attach, detach
    from fridapilot.tools.recon import enumerate_methods

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    try:
        methods = enumerate_methods(session.frida_session, class_name)
        for m in methods:
            console.print(m)
        console.print(f"[dim]Total: {len(methods)} methods[/dim]")
    finally:
        detach(session)


@recon_app.command("exports")
def recon_exports(
    target: str = typer.Option(..., "--target", "-t"),
    module: str = typer.Option(..., "--module", "-m", help="Module name."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Enumerate exports of a module."""
    from fridapilot.tools.injector import attach, detach
    from fridapilot.tools.recon import enumerate_exports

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    exports = enumerate_exports(session.frida_session, module)
    table = Table(title=f"Exports ({module})")
    table.add_column("Name", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Type")
    for e in exports:
        table.add_row(e.name, e.address, e.type)
    console.print(table)
    detach(session)
