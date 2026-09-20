"""PE metadata reconnaissance - the zero-cost pass that belongs before disassembly.


Everything here is information the build left behind by accident: PDB path and
GUID, version resource, manifest, Rich header, COFF symbols, toolchain
fingerprints, Rust panic source paths. On a binary that was not carefully stripped
this collapses the work: a PDB GUID pulls public symbols off the symbol server, a
Rust panic string spells out the original source tree, and a version resource names
the vendor. Doing this after a reverse-engineering session is doing it backwards.

Pure Python (pefile only), no LLM, no network.
"""

from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any

# IMAGE_DEBUG_TYPE_* values that actually turn up in the wild.
DEBUG_TYPES = {
    0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION",
    6: "FIXUP", 7: "OMAP_TO_SRC", 8: "OMAP_FROM_SRC", 9: "BORLAND", 10: "RESERVED10",
    11: "CLSID", 12: "VC_FEATURE", 13: "POGO", 14: "ILTCG", 15: "MPX",
    16: "REPRO", 17: "SPGO", 20: "EX_DLLCHARACTERISTICS",
}

# Toolchain markers. Rust and Go leak the most: both embed source paths and
# package names that survive symbol stripping, because panic/runtime messages need
# them at runtime.
TOOLCHAIN_MARKERS: list[tuple[str, bytes]] = [
    ("rust", rb"core::panicking"),
    ("rust", rb"/rustc/"),
    ("rust", rb"\.cargo[\\/]registry"),
    ("rust", rb"library[\\/]core[\\/]src"),
    ("rust", rb"RUST_BACKTRACE"),
    ("go", rb"Go build ID"),
    ("go", rb"go:buildid"),
    ("go", rb"runtime\.main"),
    ("mingw", rb"__mingw_"),
    ("mingw", rb"libgcc"),
    ("msvc", rb"VCRUNTIME"),
    ("msvc", rb"Microsoft Visual C\+\+"),
    ("delphi", rb"Borland|Embarcadero"),
    ("pyinstaller", rb"pyi-|PyInstaller"),
    ("nsis", rb"Nullsoft Install System"),
    ("electron", rb"electron\.asar|node_modules"),
]

RUST_SOURCE_PATH = re.compile(rb"[A-Za-z0-9_\-.\\/:+]{4,160}\.rs")
CARGO_CRATE = re.compile(rb"registry[\\/]src[\\/][^\\/]+[\\/]([A-Za-z0-9_\-]+)-(\d[\w.\-]*)")
UAC_LEVEL = re.compile(r'level\s*=\s*"([^"]+)"')
DPI_AWARE = re.compile(r"<dpiAware[^>]*>([^<]+)</dpiAware>", re.IGNORECASE)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return round(-sum((c / total) * math.log2(c / total) for c in counts if c), 3)


def pe_metadata(binary_path: str | Path) -> dict[str, Any]:
    """Collect every accidental identifier a PE carries.

    Returns a dict with: debug (PDB path/GUID/age + symbol-server key),
    version_info, manifest, rich_header, coff_symbols, resources, toolchain,
    rust, security, sections, dynamic_api_resolution.
    """
    import pefile

    path = Path(binary_path)
    data = path.read_bytes()
    pe = pefile.PE(str(path))

    result: dict[str, Any] = {
        "filepath": str(path),
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "is_dotnet": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "debug": _debug_info(pe, data),
        "version_info": _version_info(pe),
        "manifest": _manifest(pe),
        "rich_header": _rich_header(pe),
        "coff_symbols": _coff_symbols(pe, data),
        "resources": _resource_types(pe),
        "security": _security(pe),
        "sections": [
            {
                "name": s.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                "virtual_address": s.VirtualAddress,
                "virtual_size": s.Misc_VirtualSize,
                "raw_size": s.SizeOfRawData,
                "entropy": _entropy(s.get_data()[:1 << 20]),
                "executable": bool(s.Characteristics & 0x20000000),
                "writable": bool(s.Characteristics & 0x80000000),
            }
            for s in pe.sections
        ],
        "dynamic_api_resolution": _dynamic_api_resolution(pe),
    }
    result["toolchain"] = _toolchain(data, result["is_dotnet"])
    if "rust" in result["toolchain"]["guesses"]:
        result["rust"] = _rust_details(data)
    return result


def _parse_codeview(blob: bytes) -> dict[str, Any]:
    """Parse an RSDS CodeView record into GUID, age and PDB path.

    Read from the raw record rather than taken from pefile's ``Signature_String``:
    that string already has the age appended, so appending the age again yields a
    33-character key no symbol server will match. The canonical key is
    ``<pdb>/<32 hex GUID><age in hex>/<pdb>``, with the first three GUID fields
    little-endian and the last eight bytes verbatim.
    """
    if len(blob) < 24 or blob[:4] != b"RSDS":
        return {}
    d1, d2, d3 = struct.unpack_from("<IHH", blob, 4)
    d4 = blob[12:20]
    age = struct.unpack_from("<I", blob, 20)[0]
    path = blob[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    guid = "%08X%04X%04X%s" % (d1, d2, d3, d4.hex().upper())
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    out: dict[str, Any] = {"pdb_path": path, "pdb_guid": guid, "pdb_age": age}
    if name:
        out["symbol_server_key"] = f"{name}/{guid}{age:X}/{name}"
    return out


def _debug_info(pe, data: bytes) -> dict[str, Any]:
    """PDB path, GUID and age, plus the symbol-server lookup key.

    The GUID+age pair is the part that matters: with it, public symbols for a
    Microsoft-built binary can be fetched without the PDB being shipped.
    """
    info: dict[str, Any] = {"entries": []}
    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        type_id = dbg.struct.Type
        info["entries"].append({
            "type": type_id,
            "type_name": DEBUG_TYPES.get(type_id, f"TYPE_{type_id}"),
            "size": dbg.struct.SizeOfData,
        })
        start = dbg.struct.PointerToRawData
        blob = data[start:start + dbg.struct.SizeOfData]
        if type_id == 2:                                     # CODEVIEW
            info.update(_parse_codeview(blob))
        elif type_id == 16:                                  # REPRO build hash
            if len(blob) > 4:
                info["repro_hash"] = blob[4:36].hex()
        elif type_id == 20 and dbg.entry is not None:        # CET / extended flags
            info["ex_dll_characteristics"] = getattr(dbg.entry, "ExDllCharacteristics", 0)
    return info



def _version_info(pe) -> dict[str, Any]:
    """RT_VERSION: company, product, original filename - the vendor's own labels."""
    out: dict[str, Any] = {}
    fixed = getattr(pe, "VS_FIXEDFILEINFO", None)
    if fixed:
        ffi = fixed[0]
        out["file_version"] = "%d.%d.%d.%d" % (
            ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xFFFF,
            ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xFFFF)
        out["product_version"] = "%d.%d.%d.%d" % (
            ffi.ProductVersionMS >> 16, ffi.ProductVersionMS & 0xFFFF,
            ffi.ProductVersionLS >> 16, ffi.ProductVersionLS & 0xFFFF)

    for block in getattr(pe, "FileInfo", []) or []:
        for item in block:
            if getattr(item, "Key", b"") != b"StringFileInfo":
                continue
            for table in getattr(item, "StringTable", []):
                for key, value in table.entries.items():
                    out[key.decode("utf-8", errors="replace")] = \
                        value.decode("utf-8", errors="replace")
    return out


def _find_resource(pe, type_id: int) -> bytes:
    for entry in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
        if getattr(entry.struct, "Id", None) != type_id:
            continue
        for name in getattr(entry.directory, "entries", []):
            for lang in getattr(name.directory, "entries", []):
                rva = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                return pe.get_data(rva, size)
    return b""


def _manifest(pe) -> dict[str, Any]:
    """RT_MANIFEST: the UAC level and DPI awareness the program asks for."""
    blob = _find_resource(pe, 24)
    if not blob:
        return {}
    text = blob.decode("utf-8", errors="replace")
    out: dict[str, Any] = {"excerpt": " ".join(text.split())[:400]}
    level = UAC_LEVEL.search(text)
    if level:
        out["requested_execution_level"] = level.group(1)
    dpi = DPI_AWARE.search(text)
    if dpi:
        out["dpi_aware"] = dpi.group(1).strip()
    return out


def _rich_header(pe) -> dict[str, Any]:
    """Rich header: which compiler/linker builds contributed, and how many objects.

    Microsoft linkers stamp this; its absence on an MSVC-looking binary, or a
    checksum that does not match, suggests the file was rebuilt or patched.
    """
    try:
        rich = pe.parse_rich_header()
    except Exception:
        return {}
    if not rich:
        return {}
    values = rich.get("values", []) or []
    entries = []
    for i in range(0, len(values) - 1, 2):
        comp_id, count = values[i], values[i + 1]
        entries.append({"prod_id": comp_id >> 16, "build": comp_id & 0xFFFF,
                        "count": count})
    return {"checksum": rich.get("checksum"), "entries": entries}


def _coff_symbols(pe, data: bytes, limit: int = 200) -> list[str]:
    """COFF symbol table names, when the linker kept them (MinGW often does)."""
    ptr = pe.FILE_HEADER.PointerToSymbolTable
    count = pe.FILE_HEADER.NumberOfSymbols
    if not ptr or not count or ptr + count * 18 > len(data):
        return []
    strings_at = ptr + count * 18
    names: list[str] = []
    for i in range(min(count, 20000)):
        record = data[ptr + i * 18:ptr + i * 18 + 18]
        if len(record) < 18:
            break
        if record[:4] == b"\x00\x00\x00\x00":
            offset = struct.unpack_from("<I", record, 4)[0]
            end = data.find(b"\x00", strings_at + offset)
            name = data[strings_at + offset:end].decode("utf-8", errors="replace")
        else:
            name = record[:8].rstrip(b"\x00").decode("utf-8", errors="replace")
        if name and name not in names:
            names.append(name)
        if len(names) >= limit:
            break
    return names


def _resource_types(pe) -> dict[str, int]:
    import pefile

    names = {v: k for k, v in pefile.RESOURCE_TYPE.items()}
    out: dict[str, int] = {}
    for entry in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
        type_id = getattr(entry.struct, "Id", None)
        label = names.get(type_id, f"ID_{type_id}")
        leaves = 0
        for name in getattr(entry.directory, "entries", []):
            leaves += len(getattr(name.directory, "entries", []))
        out[label] = leaves
    return out


def _security(pe) -> dict[str, bool]:
    dll_flags = pe.OPTIONAL_HEADER.DllCharacteristics
    file_flags = pe.FILE_HEADER.Characteristics
    guard_flags = getattr(getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None), "struct", None)
    return {
        "aslr": bool(dll_flags & 0x0040),
        "high_entropy_va": bool(dll_flags & 0x0020),
        "dep": bool(dll_flags & 0x0100),
        "no_seh": bool(dll_flags & 0x0400),
        "cfg": bool(dll_flags & 0x4000),
        "cet_compat": bool(dll_flags & 0x8000),
        "relocs_stripped": bool(file_flags & 0x0001),
        "has_load_config": guard_flags is not None,
    }


def _dynamic_api_resolution(pe) -> dict[str, Any]:
    """A tiny import table plus LoadLibrary/GetProcAddress means APIs are hidden."""
    imported: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imported.append(imp.name.decode("utf-8", errors="replace"))
    resolvers = [n for n in imported
                 if n in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                          "LoadLibraryExW", "GetProcAddress", "GetModuleHandleA",
                          "GetModuleHandleW")]
    return {
        "imported_functions": len(imported),
        "resolvers": sorted(set(resolvers)),
        "suspicious": bool(resolvers) and len(imported) < 50,
    }


def _toolchain(data: bytes, is_dotnet: bool) -> dict[str, Any]:
    guesses: list[str] = []
    evidence: list[str] = []
    for name, marker in TOOLCHAIN_MARKERS:
        if re.search(marker, data):
            if name not in guesses:
                guesses.append(name)
            evidence.append(f"{name}: {marker.decode('utf-8', errors='replace')}")
    if is_dotnet:
        guesses.insert(0, "dotnet")
        evidence.append("dotnet: CLR runtime data directory present")
    return {"guesses": guesses or ["unknown"], "evidence": evidence[:20]}


def _rust_details(data: bytes, limit: int = 80) -> dict[str, Any]:
    """Rust panic metadata: source paths and crate names survive symbol stripping.

    `panic!` needs `file!()` at runtime, so the original source tree is embedded
    whether or not symbols were kept.
    """
    paths: list[str] = []
    for match in RUST_SOURCE_PATH.finditer(data):
        value = match.group().decode("utf-8", errors="replace")
        if ("/" in value or "\\" in value) and value not in paths:
            paths.append(value)
        if len(paths) >= limit:
            break

    crates: dict[str, str] = {}
    for match in CARGO_CRATE.finditer(data):
        crate = match.group(1).decode("utf-8", errors="replace")
        version = match.group(2).decode("utf-8", errors="replace")
        crates.setdefault(crate, version)

    # own source tree = paths that are not from the toolchain or the registry
    own = [p for p in paths
           if "/rustc/" not in p and "\\rustc\\" not in p
           and "cargo" not in p and "library/core" not in p.replace("\\", "/")]
    return {"source_paths": paths, "own_source_paths": own[:limit],
            "crates": [{"name": k, "version": v} for k, v in sorted(crates.items())]}
