"""Dump Tools - Memory, string, and object graph extraction.

Enhanced memory dump with hex view, region enumeration, and pattern-aware extraction.
No LLM dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import frida


@dataclass
class MemoryRegion:
    """A memory region in the target process."""
    base: str
    size: int
    protection: str
    file_path: str = ""


@dataclass
class DumpResult:
    """Result of a memory dump operation."""
    address: str
    size: int
    data: bytes = b""
    hex_view: str = ""
    ascii_preview: str = ""


def list_memory_regions(
    session: frida.core.Session,
    protection: str = "r--",
) -> list[MemoryRegion]:
    """Enumerate memory regions with the specified protection.

    Args:
        session: Active Frida session.
        protection: Memory protection filter (e.g., 'r--', 'rwx', 'r-x').

    Returns:
        List of MemoryRegion with base, size, protection, and file path.
    """
    script = session.create_script(f"""
        rpc.exports.getRegions = () => {{
            return Process.enumerateRanges('{protection}').map(r => ({{
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file_path: r.file ? r.file.path : ''
            }}));
        }};
    """)
    script.load()
    regions = script.exports_sync.get_regions()
    script.unload()
    return [MemoryRegion(**r) for r in regions]


def dump_memory(session: frida.core.Session, address: str, size: int) -> DumpResult:
    """Read raw bytes from target process memory with hex view.

    Args:
        session: Active Frida session.
        address: Memory address as hex string (e.g., '0x7ff...').
        size: Number of bytes to read.

    Returns:
        DumpResult with raw bytes, hex view, and ASCII preview.
    """
    script = session.create_script(f"""
        rpc.exports.dump = () => {{
            const buf = ptr('{address}').readByteArray({size});
            return buf ? Array.from(new Uint8Array(buf)) : [];
        }};
    """)
    script.load()
    byte_array = script.exports_sync.dump()
    script.unload()

    data = bytes(byte_array) if byte_array else b""
    hex_view = _format_hex_view(data, address)
    ascii_chars = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data[:200])

    return DumpResult(
        address=address,
        size=len(data),
        data=data,
        hex_view=hex_view,
        ascii_preview=ascii_chars,
    )


def dump_strings(
    session: frida.core.Session,
    min_length: int = 4,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Extract readable strings from target process memory ranges.

    Enhanced version: returns strings with their addresses and regions.

    Args:
        session: Active Frida session.
        min_length: Minimum string length to capture.
        limit: Maximum number of strings to return.

    Returns:
        List of dicts with 'address', 'value', 'region' fields.
    """
    script = session.create_script(f"""
        rpc.exports.getStrings = () => {{
            const results = [];
            const minLen = {min_length};
            const maxResults = {limit};
            Process.enumerateRanges('r--').forEach(range => {{
                if (results.length >= maxResults) return;
                try {{
                    const size = Math.min(range.size, 1048576); // Max 1MB per region
                    const data = range.base.readByteArray(size);
                    if (!data) return;
                    const bytes = new Uint8Array(data);
                    let current = [];
                    let startAddr = 0;
                    for (let i = 0; i < bytes.length; i++) {{
                        if (bytes[i] >= 0x20 && bytes[i] < 0x7f) {{
                            if (current.length === 0) startAddr = i;
                            // Cap the run: String.fromCharCode.apply throws
                            // RangeError beyond ~1e5 args and the outer catch
                            // silently skipped the rest of the region; the value
                            // is truncated to 200 chars anyway (audit M-C4).
                            if (current.length < 256) current.push(bytes[i]);
                        }} else {{
                            if (current.length >= minLen) {{
                                results.push({{
                                    address: range.base.add(startAddr).toString(),
                                    value: String.fromCharCode.apply(null, current).substring(0, 200),
                                    region: range.file ? range.file.path : ''
                                }});
                                if (results.length >= maxResults) return;
                            }}
                            current = [];
                        }}
                    }}
                    if (current.length >= minLen) {{
                        results.push({{
                            address: range.base.add(startAddr).toString(),
                            value: String.fromCharCode.apply(null, current).substring(0, 200),
                            region: range.file ? range.file.path : ''
                        }});
                    }}
                }} catch(e) {{}}
            }});
            return results;
        }};
    """)
    script.load()
    result = script.exports_sync.get_strings()
    script.unload()
    return result


def dump_module_memory(
    session: frida.core.Session,
    module_name: str,
) -> DumpResult:
    """Dump the entire memory of a loaded module.

    Args:
        session: Active Frida session.
        module_name: Name of the loaded module (e.g., 'chrome.dll').

    Returns:
        DumpResult with the module's memory contents.
    """
    script = session.create_script(f"""
        rpc.exports.dumpModule = () => {{
            const mod = Process.findModuleByName('{module_name}');
            if (!mod) return {{ error: 'Module not found', data: [] }};
            const capped = Math.min(mod.size, 10485760); // Max 10MB
            const buf = mod.base.readByteArray(capped);
            return {{
                base: mod.base.toString(),
                size: buf ? capped : 0,        // size of the data actually returned
                module_size: mod.size,         // full module size
                truncated: !!buf && mod.size > capped,
                data: buf ? Array.from(new Uint8Array(buf)) : []
            }};
        }};
    """)
    script.load()
    result = script.exports_sync.dump_module()
    script.unload()

    if "error" in result:
        return DumpResult(address="0x0", size=0)

    data = bytes(result.get("data", []))
    if result.get("truncated"):
        # size must describe the DATA returned (audit finding M-C3: it
        # used to report the full module size while capping at 10MB).
        import logging
        logging.getLogger(__name__).warning(
            "dump_module_memory: module %s has %s bytes; returned the "
            "first %s (10MB cap)", module_name,
            result.get("module_size", 0), len(data))
    return DumpResult(
        address=result.get("base", "0x0"),
        size=len(data),
        data=data,
        hex_view=_format_hex_view(data[:256], result.get("base", "0x0")),
        ascii_preview="".join(chr(b) if 0x20 <= b < 0x7f else "." for b in data[:200]),
    )


def _format_hex_view(data: bytes, base_addr: str, bytes_per_line: int = 16) -> str:
    """Format raw bytes as a classic hex dump view."""
    lines = []
    try:
        addr = int(base_addr, 0) if isinstance(base_addr, str) else int(base_addr)
    except (ValueError, TypeError):
        addr = 0

    for i in range(0, min(len(data), 512), bytes_per_line):  # Max 512 bytes in view
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"  {addr + i:08x}  {hex_part:<{bytes_per_line * 3}}  {ascii_part}")

    return "\n".join(lines)
