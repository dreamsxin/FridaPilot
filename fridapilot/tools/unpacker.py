"""Unpacker - Packer detection, UPX auto-unpack, and Frida-based memory dump.

Provides the missing "unpack" capability for analyzing packed/protected binaries.
Follows the IAT repair iron rule: try auto-unpack → try dump → report failure.

No LLM dependency.
"""

from __future__ import annotations

import math
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PackerInfo:
    """Result of packer detection."""
    filepath: str
    packed: bool = False
    packer_name: str = "unknown"
    confidence: str = "LOW"  # HIGH / MEDIUM / LOW
    evidence: list[str] = field(default_factory=list)
    section_entropy: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class UnpackResult:
    """Result of an unpack attempt."""
    success: bool
    method: str = ""  # "upx", "memory_dump", "none"
    output_path: str = ""
    original_path: str = ""
    error: str = ""
    packer_info: PackerInfo | None = None


# ── Known packer signatures ──────────────────────────────────

_PACKER_SIGNATURES: dict[str, list[tuple[str, int | None]]] = {
    "UPX": [
        ("UPX0", None), ("UPX1", None), ("UPX!", None),
    ],
    "VMProtect": [
        (".vmp0", None), (".vmp1", None), (".vmp2", None),
    ],
    "Themida": [
        (".themida", None), (".Themida", None),
    ],
    "ASPack": [
        (".aspack", None), (".adata", None),
    ],
    "PECompact": [
        ("PEC2", None), (".petite", None),
    ],
    "Enigma": [
        (".enigma1", None), (".enigma2", None),
    ],
}

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for c in freq:
        if c > 0:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def detect_packer(filepath: str | Path) -> PackerInfo:
    """Detect if a PE binary is packed and identify the packer.

    Uses section name signatures, entropy analysis, and import table heuristics.

    Args:
        filepath: Path to the PE file.

    Returns:
        PackerInfo with detection results.
    """
    filepath = Path(filepath)
    data = filepath.read_bytes()
    result = PackerInfo(filepath=str(filepath))

    if data[:2] != b"MZ":
        result.evidence.append("Not a PE file")
        return result

    # Parse PE sections for names and entropy
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            result.evidence.append("Invalid PE signature")
            return result
        num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        sec_offset = pe_off + 24 + opt_hdr_size

        for i in range(num_sections):
            off = sec_offset + i * 40
            name = data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", data, off + 8)[0]
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
            sec_data = data[raw_ptr:raw_ptr + raw_size] if raw_size > 0 else b""
            ent = round(_shannon_entropy(sec_data), 2) if sec_data else 0.0
            result.section_entropy.append({"name": name, "entropy": ent, "raw_size": raw_size, "vsize": vsize})

            # Check packer signatures
            for packer, sigs in _PACKER_SIGNATURES.items():
                for sig_name, _ in sigs:
                    if name.startswith(sig_name) or sig_name in name:
                        result.packed = True
                        result.packer_name = packer
                        result.confidence = "HIGH"
                        result.evidence.append(f"Section name '{name}' matches {packer} signature")
    except Exception as e:
        result.evidence.append(f"PE parse error: {e}")
        return result

    # Entropy heuristic: high entropy sections suggest packing
    high_ent = [s for s in result.section_entropy if s["entropy"] > 7.0 and s["raw_size"] > 1024]
    if high_ent and not result.packed:
        result.packed = True
        result.packer_name = "unknown (high entropy)"
        result.confidence = "MEDIUM"
        for s in high_ent:
            result.evidence.append(f"Section '{s['name']}' entropy={s['entropy']} (> 7.0)")

    # Import table heuristic: very few DLL references suggest packing
    try:
        total_dll_refs = data.lower().count(b".dll")

        if total_dll_refs <= 3 and not result.packed:
            result.packed = True
            result.packer_name = result.packer_name if result.packer_name != "unknown" else "unknown (minimal imports)"
            result.confidence = "MEDIUM" if result.confidence == "LOW" else result.confidence
            result.evidence.append(f"Only {total_dll_refs} DLL references (minimal imports)")
    except Exception:
        pass

    # String scarcity heuristic
    printable_ratio = sum(1 for b in data if 0x20 <= b < 0x7f) / len(data) if data else 0
    if printable_ratio < 0.15 and not result.packed:
        result.packed = True
        result.confidence = "MEDIUM"
        result.evidence.append(f"Low printable ratio: {printable_ratio:.1%}")

    return result


def unpack_upx(filepath: str | Path, output_path: str | Path | None = None) -> UnpackResult:
    """Unpack a UPX-packed binary.

    Args:
        filepath: Path to the packed binary.
        output_path: Output path for unpacked binary. If None, uses <name>_unpacked<ext>.

    Returns:
        UnpackResult with success status and output path.
    """
    filepath = Path(filepath)
    if output_path is None:
        output_path = filepath.parent / f"{filepath.stem}_unpacked{filepath.suffix}"
    else:
        output_path = Path(output_path)

    upx = shutil.which("upx")
    if not upx:
        return UnpackResult(success=False, method="upx", original_path=str(filepath),
                           error="UPX not found in PATH. Install: apt install upx / brew install upx")

    # Copy to output first, then unpack in-place
    shutil.copy2(filepath, output_path)
    try:
        result = subprocess.run(
            [upx, "-d", str(output_path)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return UnpackResult(success=True, method="upx", output_path=str(output_path),
                               original_path=str(filepath))
        else:
            output_path.unlink(missing_ok=True)
            return UnpackResult(success=False, method="upx", original_path=str(filepath),
                               error=result.stderr.strip() or result.stdout.strip())
    except subprocess.TimeoutExpired:
        output_path.unlink(missing_ok=True)
        return UnpackResult(success=False, method="upx", original_path=str(filepath),
                           error="UPX timeout (60s)")
    except Exception as e:
        output_path.unlink(missing_ok=True)
        return UnpackResult(success=False, method="upx", original_path=str(filepath), error=str(e))


def dump_process_memory(
    target: str | int,
    output_path: str | Path | None = None,
    device_type: str = "local",
) -> UnpackResult:
    """Dump a running process's main module memory via Frida.

    This is the fallback when static unpacking fails. Attach to the running
    (already unpacked in memory) process and dump its main module.

    Args:
        target: Process name or PID.
        output_path: Path to write the dump. If None, uses <target>_dump.bin.
        device_type: Device type (local/usb/remote).

    Returns:
        UnpackResult with dump file path.
    """
    from fridapilot.models.schemas import DeviceType
    from fridapilot.tools.recon import get_device

    if output_path is None:
        output_path = Path(f"{target}_dump.bin")
    else:
        output_path = Path(output_path)

    try:
        device = get_device(DeviceType(device_type))
        if isinstance(target, int):
            session = device.attach(target)
        else:
            # Find process by name
            pid = None
            for proc in device.enumerate_processes():
                if proc.name == target:
                    pid = proc.pid
                    break
            if pid is None:
                return UnpackResult(success=False, method="memory_dump",
                                   error=f"Process not found: {target}")
            session = device.attach(pid)

        script = session.create_script("""
            rpc.exports.dumpMain = () => {
                const main = Process.enumerateModules()[0];
                const buf = Memory.readByteArray(main.base, main.size);
                return {
                    name: main.name,
                    base: main.base.toString(),
                    size: main.size,
                    data: buf ? Array.from(new Uint8Array(buf)) : []
                };
            };
        """)
        script.load()
        result = script.exports_sync.dump_main()
        script.unload()
        session.detach()

        dump_data = bytes(result.get("data", []))
        if not dump_data:
            return UnpackResult(success=False, method="memory_dump", error="Empty dump")

        output_path.write_bytes(dump_data)
        return UnpackResult(
            success=True, method="memory_dump",
            output_path=str(output_path), original_path=str(target),
        )
    except Exception as e:
        return UnpackResult(success=False, method="memory_dump", error=str(e))


def auto_unpack(filepath: str | Path, output_path: str | Path = "") -> UnpackResult:
    """Full unpack pipeline: detect packer → try UPX → report.

    For non-UPX packers, use dump_process_memory separately on the running process.

    Args:
        filepath: Path to the potentially packed binary.
        output_path: Where to write the unpacked binary. Empty string means
            the default location (<name>_unpacked<ext> next to the input).

    Returns:
        UnpackResult from the best available method.
    """
    filepath = Path(filepath)
    info = detect_packer(filepath)

    if not info.packed:
        return UnpackResult(success=True, method="none", output_path=str(filepath),
                           original_path=str(filepath), packer_info=info)

    # Try UPX first (works for UPX and sometimes UPX-compatible packers)
    if info.packer_name == "UPX" or info.packer_name.startswith("unknown"):
        upx_result = unpack_upx(filepath, output_path or None)
        upx_result.packer_info = info
        if upx_result.success:
            return upx_result

    # For other packers, report that memory dump is needed
    return UnpackResult(
        success=False, method="none", original_path=str(filepath),
        error=f"Packer '{info.packer_name}' detected. Use dump_process_memory() on the running process, "
              f"or use fp dbg --spawn to find OEP and dump manually.",
        packer_info=info,
    )
