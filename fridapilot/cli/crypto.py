"""fp crypto - Binary encryption analysis and crypto reverse engineering."""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
crypto_app = typer.Typer(no_args_is_help=True)


@crypto_app.command("scan")
def crypto_scan(
    binary: str = typer.Argument(..., help="Path to PE/ELF binary file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Scan a binary for crypto indicators, S-Box, imports, and protection level."""
    import json as json_mod
    from fridapilot.tools.crypto_reverse import scan_binary

    result = scan_binary(binary)

    if json_output:
        out = {
            "filepath": result.filepath,
            "is_pe": result.is_pe,
            "is_64bit": result.is_64bit,
            "is_dotnet": result.is_dotnet,
            "sbox_offsets": [f"0x{o:x}" for o in result.sbox_offsets],
            "crypto_imports": result.crypto_imports,
            "crypto_strings_count": len(result.crypto_strings),
            "hex_key_candidates": result.hex_key_candidates[:10],
            "protection_level": {
                "level": result.protection_level.level,
                "label": result.protection_level.label,
                "confidence": result.protection_level.confidence,
                "evidence": result.protection_level.evidence,
            } if result.protection_level else None,
        }
        console.print(json_mod.dumps(out, indent=2))
        return

    # Rich output
    console.print(Panel(f"[bold]{result.filepath}[/bold]", title="Crypto Scan"))

    info_table = Table(show_header=False)
    info_table.add_row("Type", "PE" if result.is_pe else "ELF/Other")
    info_table.add_row("Arch", "x64" if result.is_64bit else "x86/Unknown")
    info_table.add_row(".NET", "Yes (use dnSpy)" if result.is_dotnet else "No")
    info_table.add_row("AES S-Box", f"{len(result.sbox_offsets)} found" if result.sbox_offsets
                        else "[yellow]Not found[/yellow]")
    console.print(info_table)

    if result.crypto_imports:
        console.print("\n[bold]Crypto API Imports:[/bold]")
        for api in result.crypto_imports:
            console.print(f"  {api}")

    if result.crypto_strings:
        console.print(f"\n[bold]Crypto Strings:[/bold] {len(result.crypto_strings)} found")
        for s in result.crypto_strings[:20]:
            console.print(f"  {s}")

    if result.hex_key_candidates:
        console.print(f"\n[bold]Hex Key Candidates:[/bold]")
        for h in result.hex_key_candidates[:5]:
            console.print(f"  {h}")

    if result.protection_level:
        pl = result.protection_level
        color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(pl.confidence, "white")
        console.print(f"\n[bold]Protection Level: L{pl.level} - {pl.label}[/bold] [{color}]({pl.confidence})[/{color}]")
        for e in pl.evidence:
            console.print(f"  {e}")


@crypto_app.command("hook-bcrypt")
def crypto_hook_bcrypt(
    target: str = typer.Option(..., "--target", "-t", help="Process name or PID."),
    device: str = typer.Option("local", "--device", "-d"),
    host: str = typer.Option("", "--host", "-H"),
) -> None:
    """Hook Windows BCrypt APIs to capture encryption keys at runtime."""
    import time
    from fridapilot.models.schemas import DeviceType
    from fridapilot.tools.crypto_reverse import get_bcrypt_hook_script
    from fridapilot.tools.injector import attach, inject, detach

    device_type = DeviceType(device)
    try:
        pid = int(target)
        session = attach(pid, device_type, host)
    except ValueError:
        session = attach(target, device_type, host)

    script_source = get_bcrypt_hook_script()
    inject(session, script_source)
    console.print(f"[green]BCrypt hooks injected into {session.target} (PID: {session.pid})[/green]")

    try:
        console.print("[dim]Monitoring crypto operations... Ctrl+C to stop.[/dim]")
        while True:
            time.sleep(0.5)
            for msg in session.observer.messages:
                if msg.payload and isinstance(msg.payload, dict):
                    if msg.payload.get("type") == "crypto_key":
                        console.print(f"  [red bold]KEY CAPTURED[/red bold] {msg.payload}")
                    else:
                        console.print(f"  [{msg.type}] {msg.payload}")
                else:
                    console.print(f"  [{msg.type}] {msg.payload}")
            session.observer.messages.clear()
    except KeyboardInterrupt:
        pass
    finally:
        detach(session)
        console.print("[green]Detached.[/green]")


@crypto_app.command("bruteforce")
def crypto_bruteforce(
    binary: str = typer.Argument(..., help="Path to binary containing the key."),
    ciphertext_file: str = typer.Option(..., "--ciphertext", "-c", help="Path to encrypted file."),
    encoding: str = typer.Option("raw", "--encoding", "-e", help="Ciphertext encoding: raw, base64, hex."),
    key_size: str = typer.Option("16,32", "--key-size", "-k", help="Key sizes to try (comma-separated)."),
    alignment: int = typer.Option(16, "--alignment", "-a", help="Byte alignment: 16 (fast), 4, 1 (exhaustive)."),
    iv_strategy: str = typer.Option("first16,zero,adjacent", "--iv", help="IV strategies (comma-separated)."),
    threshold: float = typer.Option(0.75, "--threshold", help="Printable char ratio threshold."),
) -> None:
    """Brute-force search for AES key in a binary by attempting decryption."""
    import base64
    from pathlib import Path
    from fridapilot.tools.crypto_reverse import bruteforce_key

    ct_data = Path(ciphertext_file).read_bytes()
    if encoding == "base64":
        ct_data = base64.b64decode(ct_data.strip())
    elif encoding == "hex":
        ct_data = bytes.fromhex(ct_data.strip().decode())

    key_sizes = [int(s.strip()) for s in key_size.split(",")]
    iv_strategies = [s.strip() for s in iv_strategy.split(",")]

    console.print(f"[bold]Brute-force AES key search[/bold]")
    console.print(f"  Binary: {binary}")
    console.print(f"  Ciphertext: {ciphertext_file} ({len(ct_data)} bytes, {encoding})")
    console.print(f"  Key sizes: {key_sizes}, Alignment: {alignment}")
    console.print(f"  IV strategies: {iv_strategies}")
    console.print("[dim]Searching...[/dim]")

    results = bruteforce_key(
        binary, ct_data,
        key_sizes=key_sizes,
        alignment=alignment,
        iv_strategies=iv_strategies,
        printable_threshold=threshold,
    )

    if not results:
        console.print("[yellow]No valid key found.[/yellow]")
        return

    for i, r in enumerate(results):
        console.print(f"\n[green bold]Candidate #{i+1}[/green bold]")
        console.print(f"  Key:      {r.key_hex}")
        console.print(f"  IV:       {r.iv_hex}")
        console.print(f"  Offset:   0x{r.key_offset:x}")
        console.print(f"  Key size: {r.key_size} bytes")
        console.print(f"  IV mode:  {r.iv_strategy}")
        console.print(f"  Ratio:    {r.printable_ratio:.2%}")
        console.print(f"  Preview:  {r.plaintext_preview[:100]}")


@crypto_app.command("xor")
def crypto_xor(
    ciphertext_file: str = typer.Argument(..., help="Path to XOR-encrypted file."),
    key_hex: str = typer.Option("", "--key", "-k", help="Known XOR key (hex). If empty, brute-force single-byte."),
    known_plaintext: str = typer.Option("", "--known", help="Known plaintext prefix (hex) for key recovery."),
    output: str = typer.Option("", "--output", "-o", help="Output decrypted file path."),
) -> None:
    """XOR deobfuscation: single-byte brute-force or known-key decryption."""
    from pathlib import Path
    from fridapilot.tools.crypto_reverse import (
        xor_deobfuscate, find_xor_key, bruteforce_single_byte_xor,
    )

    ct_data = Path(ciphertext_file).read_bytes()

    if known_plaintext:
        # Known-plaintext attack
        pt = bytes.fromhex(known_plaintext)
        recovered_key = find_xor_key(ct_data, pt)
        console.print(f"[green]Recovered XOR key:[/green] {recovered_key.hex()}")
        decrypted = xor_deobfuscate(ct_data, recovered_key)
    elif key_hex:
        # Decrypt with known key
        key = bytes.fromhex(key_hex)
        decrypted = xor_deobfuscate(ct_data, key)
        console.print(f"[green]Decrypted with key {key_hex}[/green]")
    else:
        # Single-byte brute-force
        console.print("[bold]Single-byte XOR brute-force:[/bold]")
        results = bruteforce_single_byte_xor(ct_data)
        for key_byte, ratio, preview in results:
            console.print(f"  Key=0x{key_byte:02x} ratio={ratio:.2%} | {preview}")
        if results:
            best_key = results[0][0]
            decrypted = bytes(b ^ best_key for b in ct_data)
            console.print(f"\n[green]Best key: 0x{best_key:02x}[/green]")
        else:
            return

    if output:
        Path(output).write_bytes(decrypted)
        console.print(f"[green]Written to {output}[/green]")
