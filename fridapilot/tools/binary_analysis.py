"""Binary Analysis Tools - Static PE/ELF analysis, disassembly, and Go binary parsing.

Provides offline binary analysis capabilities without requiring a running process.
Complements the dynamic Frida tools with static analysis for complete RE workflow.

Inspired by binary-mcp and Capstone MCP Server architectures.
No LLM dependency.
"""

from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from typing import Any

from fridapilot.models.schemas import (
    ByteMatch,
    DisassemblyLine,
    DisassemblyResult,
    ELFAnalysis,
    GoAnalysis,
    ImportEntry,
    PEAnalysis,
    SectionInfo,
    StringMatch,
    XrefResult,
)


# ── PE Analysis ───────────────────────────────────────────────


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def analyze_pe(filepath: str | Path) -> PEAnalysis:
    """Full PE binary analysis: headers, sections, imports, exports, debug info.

    Args:
        filepath: Path to the PE file (.exe, .dll, .sys).

    Returns:
        PEAnalysis with all extracted metadata.
    """
    import pefile

    filepath = Path(filepath)
    pe = pefile.PE(str(filepath), fast_load=False)

    result = PEAnalysis(filepath=str(filepath))
    result.is_64bit = pe.FILE_HEADER.Machine == 0x8664
    result.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result.machine = {
        0x14C: "i386", 0x8664: "AMD64", 0xAA64: "ARM64",
    }.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
    result.timestamp = pe.FILE_HEADER.TimeDateStamp
    result.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    result.image_base = pe.OPTIONAL_HEADER.ImageBase

    # .NET detection
    if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR"):
        result.is_dotnet = True
    else:
        result.is_dotnet = b"BSJB" in filepath.read_bytes()

    # Sections
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        result.sections.append(SectionInfo(
            name=name,
            virtual_address=section.VirtualAddress,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            entropy=section.get_entropy(),
            characteristics=f"0x{section.Characteristics:08x}",
        ))

    # Imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
            for imp in entry.imports:
                func_name = imp.name.decode("utf-8", errors="replace") if imp.name else ""
                result.imports.append(ImportEntry(
                    dll=dll_name, name=func_name, ordinal=imp.ordinal,
                ))

    # Exports
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ordinal_{exp.ordinal}"
            result.exports.append(name)

    # Debug info (PDB path)
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(dbg, "entry") and hasattr(dbg.entry, "PdbFileName"):
                pdb = dbg.entry.PdbFileName.rstrip(b"\x00").decode("utf-8", errors="replace")
                result.debug_info["pdb_path"] = pdb

    pe.close()
    return result


# ── ELF Analysis ──────────────────────────────────────────────


def analyze_elf(filepath: str | Path) -> ELFAnalysis:
    """Full ELF binary analysis: headers, sections, symbols, dynamic libs.

    Args:
        filepath: Path to the ELF file.

    Returns:
        ELFAnalysis with all extracted metadata.
    """
    from elftools.elf.elffile import ELFFile

    filepath = Path(filepath)
    result = ELFAnalysis(filepath=str(filepath))

    with open(filepath, "rb") as f:
        elf = ELFFile(f)
        result.is_64bit = elf.elfclass == 64
        result.is_pie = elf.header.e_type == "ET_DYN"
        result.machine = elf.header.e_machine
        result.entry_point = elf.header.e_entry

        # Sections
        for section in elf.iter_sections():
            data = section.data() if section["sh_size"] > 0 else b""
            entropy = _shannon_entropy(data) if data else 0.0
            result.sections.append(SectionInfo(
                name=section.name,
                virtual_address=section["sh_addr"],
                virtual_size=section["sh_size"],
                raw_size=section["sh_size"],
                entropy=round(entropy, 2),
                characteristics=section["sh_type"],
            ))

        # Symbols (from .symtab and .dynsym)
        from elftools.elf.sections import SymbolTableSection
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol.name and symbol["st_info"]["type"] == "STT_FUNC":
                        result.symbols.append(symbol.name)

        # Dynamic libraries
        from elftools.elf.dynamic import DynamicSection
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        result.dynamic_libs.append(tag.needed)

    return result


def disassemble(
    binary_path: str | Path,
    address: int,
    count: int = 20,
    arch: str = "auto",
) -> DisassemblyResult:
    """Disassemble instructions at a given file offset or virtual address.

    Args:
        binary_path: Path to the binary file.
        address: File offset to start disassembly from.
        count: Number of instructions to disassemble.
        arch: Architecture ("x86", "x64", "arm", "arm64", "auto").

    Returns:
        DisassemblyResult with decoded instructions.
    """
    import capstone

    binary_path = Path(binary_path)
    data = binary_path.read_bytes()

    # Auto-detect architecture from PE/ELF headers
    if arch == "auto":
        if data[:2] == b"MZ":
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 6 < len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                arch = "x64" if machine == 0x8664 else "x86"
            else:
                arch = "x86"
        elif data[:4] == b"\x7fELF":
            ei_class = data[4]
            e_machine = struct.unpack_from("<H", data, 18)[0]
            if e_machine == 0xB7:
                arch = "arm64"
            elif e_machine in (0x28,):
                arch = "arm"
            else:
                arch = "x64" if ei_class == 2 else "x86"
        else:
            arch = "x64"

    arch_map = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    cs_arch, cs_mode = arch_map.get(arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False

    # Read from offset
    chunk = data[address:address + count * 15]  # max 15 bytes per x86 instruction
    instructions = []
    for insn in md.disasm(chunk, address):
        instructions.append(DisassemblyLine(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes_hex=insn.bytes.hex(),
        ))
        if len(instructions) >= count:
            break

    return DisassemblyResult(
        start_address=address,
        instructions=instructions,
        architecture=arch,
        mode=f"{cs_arch}/{cs_mode}",
    )


# ── String Extraction ─────────────────────────────────────────


def find_strings(
    binary_path: str | Path,
    min_len: int = 4,
    encoding: str = "all",
    limit: int = 1000,
) -> list[StringMatch]:
    """Extract strings from a binary file.

    Supports ASCII, UTF-16LE, and UTF-8 extraction.

    Args:
        binary_path: Path to the binary file.
        min_len: Minimum string length.
        encoding: "ascii", "utf16le", "utf8", or "all".
        limit: Maximum number of strings to return.

    Returns:
        List of StringMatch with offset, value, and encoding.
    """
    data = Path(binary_path).read_bytes()
    results: list[StringMatch] = []

    def _extract_ascii(data: bytes) -> list[StringMatch]:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        matches = []
        for m in pattern.finditer(data):
            matches.append(StringMatch(
                offset=m.start(),
                value=m.group().decode("ascii"),
                encoding="ascii",
            ))
            if len(matches) >= limit:
                break
        return matches

    def _extract_utf16le(data: bytes) -> list[StringMatch]:
        pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        matches = []
        for m in pattern.finditer(data):
            try:
                value = m.group().decode("utf-16-le")
                matches.append(StringMatch(
                    offset=m.start(), value=value, encoding="utf16le",
                ))
            except UnicodeDecodeError:
                continue
            if len(matches) >= limit:
                break
        return matches

    def _extract_utf8(data: bytes) -> list[StringMatch]:
        # Look for multi-byte UTF-8 sequences (non-ASCII)
        pattern = re.compile(rb"(?:[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|"
                             rb"[\xf0-\xf7][\x80-\xbf]{3}|[\x20-\x7e]){%d,}" % min_len)
        matches = []
        for m in pattern.finditer(data):
            try:
                value = m.group().decode("utf-8")
                if any(ord(c) > 127 for c in value):  # Only if it has non-ASCII
                    matches.append(StringMatch(
                        offset=m.start(), value=value, encoding="utf8",
                    ))
            except UnicodeDecodeError:
                continue
            if len(matches) >= limit:
                break
        return matches

    if encoding in ("ascii", "all"):
        results.extend(_extract_ascii(data))
    if encoding in ("utf16le", "all"):
        results.extend(_extract_utf16le(data))
    if encoding in ("utf8", "all"):
        results.extend(_extract_utf8(data))

    results.sort(key=lambda s: s.offset)
    return results[:limit]


def search_bytes(
    binary_path: str | Path,
    pattern: str,
    limit: int = 100,
) -> list[ByteMatch]:
    """Search for a byte pattern in a binary file.

    Supports wildcard bytes with '??' notation.
    Example patterns: "4883ec20", "48 8b ?? 48 89", "ff15????0000"

    Args:
        binary_path: Path to the binary file.
        pattern: Hex string pattern, optionally with '??' wildcards.
        limit: Maximum number of matches to return.

    Returns:
        List of ByteMatch with offset and matched bytes.
    """
    data = Path(binary_path).read_bytes()

    # Normalize pattern: remove spaces, lowercase
    pattern = pattern.replace(" ", "").lower()
    if len(pattern) % 2 != 0:
        raise ValueError("Pattern must have even number of hex characters")

    # Build regex from pattern with ?? wildcards
    regex_parts = []
    for i in range(0, len(pattern), 2):
        byte_str = pattern[i:i + 2]
        if byte_str == "??":
            regex_parts.append(b".")
        else:
            byte_val = int(byte_str, 16)
            regex_parts.append(re.escape(bytes([byte_val])))

    byte_regex = b"".join(regex_parts)
    compiled = re.compile(byte_regex, re.DOTALL)

    results: list[ByteMatch] = []
    for m in compiled.finditer(data):
        results.append(ByteMatch(
            offset=m.start(),
            matched_bytes=m.group().hex(),
        ))
        if len(results) >= limit:
            break

    return results


# ── Cross-References ──────────────────────────────────────────


def xrefs_to(
    binary_path: str | Path,
    target_address: int,
    search_range: tuple[int, int] | None = None,
) -> list[XrefResult]:
    """Find cross-references to a target address in a binary.

    Scans for CALL and JMP instructions that reference the target address.
    Works with x86/x64 relative addressing.

    Args:
        binary_path: Path to the binary file.
        target_address: The target address (file offset) to find references to.
        search_range: Optional (start, end) range to search within.

    Returns:
        List of XrefResult with source addresses and instruction types.
    """
    import capstone

    binary_path = Path(binary_path)
    data = binary_path.read_bytes()

    # Auto-detect architecture
    is_64 = False
    if data[:2] == b"MZ":
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 < len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            is_64 = machine == 0x8664
    elif data[:4] == b"\x7fELF":
        is_64 = data[4] == 2

    if is_64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = False

    start = search_range[0] if search_range else 0
    end = search_range[1] if search_range else len(data)
    chunk = data[start:end]

    results: list[XrefResult] = []
    for insn in md.disasm(chunk, start):
        if insn.mnemonic in ("call", "jmp", "je", "jne", "jz", "jnz", "ja", "jb",
                              "jae", "jbe", "jg", "jl", "jge", "jle"):
            # Try to parse the operand as an address
            try:
                op_addr = int(insn.op_str, 0) if insn.op_str.startswith("0x") else None
                if op_addr is None and insn.op_str.isdigit():
                    op_addr = int(insn.op_str)
            except (ValueError, TypeError):
                op_addr = None

            if op_addr == target_address:
                xref_type = "call" if insn.mnemonic == "call" else "jump"
                results.append(XrefResult(
                    from_address=insn.address,
                    instruction=f"{insn.mnemonic} {insn.op_str}",
                    xref_type=xref_type,
                ))

    return results


# ── Go Binary Analysis ────────────────────────────────────────

def analyze_go_binary(filepath: str | Path) -> GoAnalysis:
    """Analyze a Go-compiled binary for version, packages, functions, and source paths.

    Go binaries embed rich metadata: build info, package paths, function names,
    and source file paths. This is invaluable for reverse engineering Go IPC
    servers and service binaries.

    Args:
        filepath: Path to the Go binary (PE or ELF).

    Returns:
        GoAnalysis with extracted Go-specific metadata.
    """
    filepath = Path(filepath)
    data = filepath.read_bytes()
    result = GoAnalysis(filepath=str(filepath))

    # ── Go version detection ──
    # Go embeds "go1.XX.YY" in the binary
    go_ver_pattern = re.compile(rb"go1\.\d+(?:\.\d+)?")
    versions = set()
    for m in go_ver_pattern.finditer(data):
        versions.add(m.group().decode("ascii"))
    if versions:
        # Pick the most specific version string
        result.go_version = sorted(versions, key=len, reverse=True)[0]

    # ── Go build info (go1.18+) ──
    # Build info starts with "\xff Go buildinf:"
    buildinfo_marker = b"\xff Go buildinf:"
    idx = data.find(buildinfo_marker)
    if idx != -1:
        # Read up to 512 bytes for build info summary
        snippet = data[idx:idx + 512]
        try:
            result.build_info = snippet.split(b"\x00")[0].decode("utf-8", errors="replace")
        except Exception:
            pass

    # ── Package & function name extraction ──
    # Go function names follow the pattern: package.FuncName or package.(*Type).Method
    func_pattern = re.compile(
        rb"(?:[\w./]+\.(?:\(\*\w+\)\.)?[A-Z]\w*)"
    )
    seen_funcs: set[str] = set()
    seen_packages: set[str] = set()
    for m in func_pattern.finditer(data):
        try:
            name = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Filter: must contain at least one dot and look like a Go symbol
        if "." not in name or len(name) > 200:
            continue
        # Skip common non-Go patterns
        if name.startswith("http") or name.startswith("www"):
            continue
        seen_funcs.add(name)
        # Extract package path (everything before the last component)
        parts = name.rsplit(".", 1)
        if len(parts) == 2 and "/" in parts[0]:
            seen_packages.add(parts[0].lstrip("(").rstrip(")"))

    result.functions = sorted(seen_funcs)[:500]
    result.packages = sorted(seen_packages)[:200]

    # ── Source file paths ──
    # Go embeds source paths like /home/user/project/internal/pkg/foo.go
    src_pattern = re.compile(rb"[\w/\\.-]+\.go(?:\x00|\s)")
    seen_sources: set[str] = set()
    for m in src_pattern.finditer(data):
        try:
            path = m.group().rstrip(b"\x00\r\n\t ").decode("utf-8")
            if "/" in path or "\\" in path:
                seen_sources.add(path)
        except UnicodeDecodeError:
            continue
    result.source_files = sorted(seen_sources)[:200]

    # ── Interesting strings (Go-specific) ──
    # Extract strings that look like Go module paths, URLs, error messages
    interesting = re.compile(
        rb"(?:github\.com|golang\.org|google\.golang\.org|"
        rb"internal/|cmd/|runtime/|net/http|crypto/|"
        rb"encoding/|fmt\.|os\.|io\.)"
        rb"[\x20-\x7e]{4,200}"
    )
    seen_strings: set[str] = set()
    for m in interesting.finditer(data):
        try:
            s = m.group().decode("utf-8")
            seen_strings.add(s)
        except UnicodeDecodeError:
            continue
    result.strings_sample = sorted(seen_strings)[:100]

    return result


# ── Mach-O Analysis ───────────────────────────────────────────

# Mach-O magic numbers
_MH_MAGIC_64 = 0xFEEDFACF
_MH_MAGIC = 0xFEEDFACE
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF

_LC_NAMES = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64",
    0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB",
    0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER", 0x21: "LC_ENCRYPTION_INFO",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x22: "LC_DYLD_INFO", 0x80000022: "LC_DYLD_INFO_ONLY",
    0x26: "LC_FUNCTION_STARTS", 0x28: "LC_MAIN",
    0x32: "LC_BUILD_VERSION", 0x24: "LC_VERSION_MIN_MACOSX",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x1D: "LC_CODE_SIGNATURE", 0x27: "LC_DATA_IN_CODE",
}

_CPU_TYPES = {
    7: "x86", 0x01000007: "x86_64",
    12: "ARM", 0x0100000C: "ARM64",
}


@dataclass
class MachOSegment:
    """A Mach-O segment."""
    name: str
    vmaddr: int = 0
    vmsize: int = 0
    fileoff: int = 0
    filesize: int = 0
    sections: list[dict] = field(default_factory=list)


@dataclass
class MachOAnalysis:
    """Result of Mach-O binary analysis."""
    filepath: str
    is_fat: bool = False
    architectures: list[str] = field(default_factory=list)
    cpu_type: str = ""
    is_64bit: bool = False
    encrypted: bool = False
    cryptid: int = 0
    segments: list[MachOSegment] = field(default_factory=list)
    load_commands: list[dict] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)
    min_os: str = ""


def analyze_macho(filepath: str | Path) -> MachOAnalysis:
    """Analyze a Mach-O binary: header, segments, load commands, encryption, dylibs.

    Pure Python parser — no external dependencies.

    Args:
        filepath: Path to the Mach-O binary.

    Returns:
        MachOAnalysis with all extracted metadata.
    """
    filepath = Path(filepath)
    data = filepath.read_bytes()
    result = MachOAnalysis(filepath=str(filepath))

    if len(data) < 4:
        return result

    magic = struct.unpack_from("<I", data, 0)[0]

    # Fat binary detection
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (_FAT_MAGIC, _FAT_MAGIC_64):
        result.is_fat = True
        nfat = struct.unpack_from(">I", data, 4)[0]
        for i in range(min(nfat, 10)):
            off = 8 + i * 20
            cpu = struct.unpack_from(">I", data, off)[0]
            result.architectures.append(_CPU_TYPES.get(cpu, f"0x{cpu:x}"))
        if nfat > 0:
            slice_off = struct.unpack_from(">I", data, 8 + 8)[0]
            data = data[slice_off:]
            magic = struct.unpack_from("<I", data, 0)[0]

    if magic == _MH_MAGIC_64:
        result.is_64bit = True
        hdr_size = 32
    elif magic == _MH_MAGIC:
        result.is_64bit = False
        hdr_size = 28
    else:
        return result

    cpu = struct.unpack_from("<I", data, 4)[0]
    result.cpu_type = _CPU_TYPES.get(cpu, f"0x{cpu:x}")
    ncmds = struct.unpack_from("<I", data, 16)[0]

    offset = hdr_size
    for _ in range(min(ncmds, 200)):
        if offset + 8 > len(data):
            break
        cmd_type = struct.unpack_from("<I", data, offset)[0]
        cmd_size = struct.unpack_from("<I", data, offset + 4)[0]
        if cmd_size < 8:
            break

        cmd_name = _LC_NAMES.get(cmd_type, f"0x{cmd_type:x}")
        lc: dict[str, Any] = {"cmd": cmd_name, "offset": offset, "size": cmd_size}

        if cmd_type in (0x1, 0x19):
            is_64 = cmd_type == 0x19
            segname = data[offset + 8:offset + 24].rstrip(b"\x00").decode("ascii", errors="replace")
            if is_64:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
                nsects = struct.unpack_from("<I", data, offset + 64)[0]
                sec_off = offset + 72
                sec_sz = 80
            else:
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", data, offset + 24)
                nsects = struct.unpack_from("<I", data, offset + 48)[0]
                sec_off = offset + 56
                sec_sz = 68

            seg = MachOSegment(name=segname, vmaddr=vmaddr, vmsize=vmsize,
                               fileoff=fileoff, filesize=filesize)
            for s in range(min(nsects, 50)):
                soff = sec_off + s * sec_sz
                if soff + 32 > len(data):
                    break
                secname = data[soff:soff + 16].rstrip(b"\x00").decode("ascii", errors="replace")
                seg.sections.append({"name": secname})
            result.segments.append(seg)
            lc["segment"] = segname

        elif cmd_type in (0x21, 0x2C):
            cryptid = struct.unpack_from("<I", data, offset + 16)[0]
            result.cryptid = cryptid
            result.encrypted = cryptid != 0
            lc["cryptid"] = cryptid

        elif cmd_type == 0xC:
            name_off = struct.unpack_from("<I", data, offset + 8)[0]
            dylib_name = data[offset + name_off:offset + cmd_size].split(b"\x00")[0].decode("utf-8", errors="replace")
            result.dylibs.append(dylib_name)
            lc["dylib"] = dylib_name

        elif cmd_type in (0x24, 0x25, 0x32):
            ver_off = 12 if cmd_type == 0x32 else 8
            ver = struct.unpack_from("<I", data, offset + ver_off)[0]
            major, minor, patch = (ver >> 16) & 0xFF, (ver >> 8) & 0xFF, ver & 0xFF
            result.min_os = f"{major}.{minor}.{patch}"

        result.load_commands.append(lc)
        offset += cmd_size

    return result
