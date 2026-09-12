"""fp report - Generate Markdown/JSON reports from collected data."""

import typer
from rich.console import Console

console = Console()


def report_cmd(
    input_file: str = typer.Option("", "--input", "-i", help="Input JSON messages file."),
    output: str = typer.Option("report.md", "--output", "-o", help="Output report file."),
    format: str = typer.Option("md", "--format", "-f", help="Report format: md, json."),
) -> None:
    """Generate a report from collected observation data."""
    import json
    from pathlib import Path

    if not input_file:
        console.print("[yellow]No input file specified. Use --input to provide a JSON messages file.[/yellow]")
        raise typer.Exit(1)

    data = json.loads(Path(input_file).read_text(encoding="utf-8"))

    if format == "json":
        Path(output).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    else:
        lines = [
            "# FridaPilot Report\n",
            f"## Messages ({len(data)} total)\n",
        ]
        for msg in data:
            lines.append(f"- **[{msg.get('type', '?')}]** `{msg.get('payload', '')}`")
            if msg.get("stack"):
                lines.append(f"  ```\n  {msg['stack']}\n  ```")
        lines.append("")
        Path(output).write_text("\n".join(lines), encoding="utf-8")

    console.print(f"[green]Report written to {output}[/green]")
