"""Dump Tools - Memory, string, and object graph extraction.

No LLM dependency.
"""

from __future__ import annotations

import frida


def dump_memory(session: frida.core.Session, address: str, size: int) -> bytes:
    """Read raw bytes from target process memory."""
    script = session.create_script(f"""
        rpc.exports.dump = () => {{
            const buf = Memory.readByteArray(ptr('{address}'), {size});
            return buf;
        }};
    """)
    script.load()
    data = script.exports_sync.dump()
    script.unload()
    return bytes(data) if data else b""


def dump_strings(
    session: frida.core.Session,
    min_length: int = 4,
) -> list[str]:
    """Extract readable strings from target process memory ranges."""
    script = session.create_script("""
        rpc.exports.getStrings = (minLen) => {
            const strings = [];
            Process.enumerateRanges('r--').forEach(range => {
                try {
                    const data = Memory.readUtf8String(range.base, range.size);
                    if (data && data.length >= minLen) {
                        strings.push(data.substring(0, 200));
                    }
                } catch(e) {}
            });
            return strings;
        };
    """)
    script.load()
    result = script.exports_sync.get_strings(min_length)
    script.unload()
    return result
