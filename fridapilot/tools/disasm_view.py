"""Symbol- and section-annotated disassembly view over PE / ELF / Mach-O.

Every other disassembler in this tree answers a narrow question: ``binary_analysis.
disassemble`` decodes N instructions at a *file offset* and knows nothing about the
image layout, and ``pe_rva.disassemble_rva`` is RVA-correct but PE-only and reference
oriented. Neither can answer "show me this section / this function with the address,
the section and the owning function on every line", which is the one view a reader
actually navigates by.

This module adds the missing middle layer: a format-independent ``ImageView`` that
maps a virtual address to (section, function) and can read bytes at it, plus a
listing builder on top. Three properties are deliberate:

* **A VA is the only address the caller handles.** RVA / file-offset conversion is a
  documented source of real bugs here (see AGENTS.md), so the listing carries both
  and takes only VAs.
* **Nothing is guessed.** Function attribution comes from ``.pdata`` (exact), a
  sized ELF symbol (exact), or a preceding symbol whose end is *implied* by the next
  symbol - and the implied case is flagged ``exact=False`` instead of being presented
  as fact. The classic ``push rbp`` prologue scan is not used at all: it is unreliable
  on optimised code, and a wrong function name is worse than none.
* **Data is not disassembled.** A non-executable section is rendered as bytes and
  strings. Feeding ``.rdata`` to capstone produces plausible-looking instructions that
  never execute, which is the single most misleading thing a listing can do.
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# A listing is read by a human or pasted into a model context; both stop being served
# by more than a few hundred lines. The byte cap is the real guard: a whole-.text
# request on a Chromium-sized DLL is 100+ MB of decode, and capstone costs ~2.7 s/MB.
DEFAULT_COUNT = 200
MAX_DECODE_BYTES = 512 * 1024
DATA_ROW_WIDTH = 16
MIN_STRING_LEN = 4
MAX_STRING_LEN = 200


@dataclass
class ViewSection:
    """One section/segment of the image, in virtual-address terms."""

    name: str
    va: int
    size: int                 # virtual size: what the address space contains
    file_offset: int = -1     # -1 when the section has no file backing (BSS)
    file_size: int = 0
    perms: str = "---"
    executable: bool = False

    @property
    def end_va(self) -> int:
        return self.va + self.size

    def contains(self, va: int) -> bool:
        return self.va <= va < self.end_va


@dataclass
class ViewSymbol:
    """A function symbol. ``size == 0`` means the source did not record one."""

    name: str
    va: int
    size: int = 0
    source: str = ""          # symtab | dynsym | export | coff | macho-symtab
    aliases: list[str] = field(default_factory=list)


@dataclass
class Attribution:
    """Which function an address belongs to, and how confidently."""

    name: str
    va: int
    size: int
    offset: int
    source: str
    exact: bool               # False when the end was implied, not recorded


_PE_MACHINES = {0x14C: ("x86", 32), 0x8664: ("x64", 64), 0x1C0: ("arm", 32),
                0xAA64: ("arm64", 64)}
_MACHO_CPUS = {7: ("x86", 32), 0x01000007: ("x64", 64), 12: ("arm", 32),
               0x0100000C: ("arm64", 64)}

_MH_MAGIC = 0xFEEDFACE
_MH_MAGIC_64 = 0xFEEDFACF
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF


def _perm_string(read: bool, write: bool, execute: bool) -> str:
    return ("r" if read else "-") + ("w" if write else "-") + ("x" if execute else "-")


class ImageView:
    """Address-indexed view of an executable: sections, function symbols, bytes.

    Example:
        view = ImageView("a.out")
        view.section_at(0x401000).name          # '.text'
        view.attribution(0x401004).name         # 'main'
        view.read(0x401000, 16)                 # bytes at a VA

    One instance per file: the PE path reuses the cached ``PEImage`` (which holds the
    whole file), and the ELF / Mach-O paths read the file once into ``self._data``.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.format = ""
        self.arch = ""
        self.bits = 0
        self.image_base = 0
        self.entry_va: int | None = None
        self.notes: list[str] = []
        self.sections: list[ViewSection] = []

        self._named: list[ViewSymbol] = []
        self._pe = None                      # PEImage, for the PE path only
        self._data = b""                     # raw file bytes, for ELF / Mach-O

        with open(self.path, "rb") as f:
            head = f.read(8)
        if len(head) < 4:
            raise ValueError(f"{self.path}: too small to be an executable")

        if head[:2] == b"MZ":
            self._load_pe()
        elif head[:4] == b"\x7fELF":
            self._load_elf()
        elif struct.unpack_from("<I", head, 0)[0] in (_MH_MAGIC, _MH_MAGIC_64) or \
                struct.unpack_from(">I", head, 0)[0] in (_FAT_MAGIC, _FAT_MAGIC_64):
            self._load_macho()
        else:
            raise ValueError(
                f"{self.path}: not a PE, ELF or Mach-O image (magic {head[:4].hex()})")

        self.sections.sort(key=lambda s: s.va)
        self._merge_named()
        self._sym_vas = [s.va for s in self._named]

    # ── loaders ──────────────────────────────────────────────

    def _load_pe(self) -> None:
        from fridapilot.tools.pe_rva import PEImage

        self.format = "pe"
        img = PEImage(self.path)
        self._pe = img
        pe = img._pe
        self.image_base = img.image_base
        machine = pe.FILE_HEADER.Machine
        self.arch, self.bits = _PE_MACHINES.get(machine, ("x64", 64))
        # A DLL without a DllMain has AddressOfEntryPoint == 0 (ntdll.dll is one).
        # Reporting ImageBase+0 there would name the DOS header as the entry point and
        # send the default listing to an address in no section at all.
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.entry_va = self.image_base + entry_rva if entry_rva else None

        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin1")
            chars = s.Characteristics
            self.sections.append(ViewSection(
                name=name,
                va=self.image_base + s.VirtualAddress,
                # A section's address space is VirtualSize; SizeOfRawData is
                # file-aligned and can be larger (alignment padding) or 0 (BSS).
                size=max(s.Misc_VirtualSize, s.SizeOfRawData),
                file_offset=s.PointerToRawData if s.SizeOfRawData else -1,
                # SizeOfRawData, not min(VirtualSize, SizeOfRawData): this is what the
                # file holds and therefore what read() can return. Table *parsing* must
                # use the min (alignment padding decodes as bogus entries), but a
                # listing showing the padding is at least telling the truth about the
                # bytes on disk.
                file_size=s.SizeOfRawData,
                perms=_perm_string(bool(chars & 0x40000000), bool(chars & 0x80000000),
                                   bool(chars & 0x20000000)),
                executable=bool(chars & 0x20000000),
            ))

        self._pe_exports(pe)
        self._pe_coff_symbols(pe, img)
        if img.exception_table():
            # Named symbols are sparse in a PE; .pdata covers every non-leaf function
            # exactly, which is why attribution() consults it before the name index.
            self.notes.append(
                ".pdata gives exact bounds for non-leaf functions; unnamed ones are "
                "reported as sub_<rva>")
        elif not self._named:
            self.notes.append(
                "no exports, no COFF symbols and no .pdata: function attribution is "
                "unavailable for this image")

    def _pe_exports(self, pe) -> None:
        """Export-table names. The one symbol source a stripped release DLL keeps."""
        import pefile

        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            # PEImage loads with fast_load=True, so the directory is not parsed yet.
            # Parsing on the cached instance is additive and avoids re-reading the file
            # - re-opening a 250 MB DLL just to read its exports is the cost this
            # module exists to keep off the hot path.
            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            except Exception:
                return
        for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            if not exp.address:
                continue
            name = (exp.name.decode("utf-8", "replace") if exp.name
                    else f"ordinal_{exp.ordinal}")
            self._named.append(ViewSymbol(name=name, va=self.image_base + exp.address,
                                          source="export"))

    def _pe_coff_symbols(self, pe, img) -> None:
        """COFF symbol table, when the linker kept it (MinGW / gcc routinely do).

        Unlike ``pe_metadata._coff_symbols``, which only lists names, this needs the
        address: value is section-relative, so it is only meaningful together with
        the symbol's section number.
        """
        count = pe.FILE_HEADER.NumberOfSymbols
        table = pe.FILE_HEADER.PointerToSymbolTable
        if not count or not table or count > 200_000:
            return
        data = img._data
        strtab = table + count * 18
        if strtab > len(data):
            return
        sections = pe.sections
        i = 0
        while i < count:
            off = table + i * 18
            if off + 18 > len(data):
                break
            raw_name = data[off:off + 8]
            value, sec_num, sym_type, storage, naux = struct.unpack_from(
                "<IhHBB", data, off + 8)
            if raw_name[:4] == b"\x00\x00\x00\x00":
                str_off = strtab + struct.unpack_from("<I", raw_name, 4)[0]
                end = data.find(b"\x00", str_off)
                name = data[str_off:end if end >= 0 else str_off].decode("utf-8", "replace")
            else:
                name = raw_name.rstrip(b"\x00").decode("utf-8", "replace")
            # MSB of the complex type is DT_FUNCTION; storage class 2/3 are
            # EXTERNAL/STATIC. Anything else is a file/section/debug record.
            if name and sec_num > 0 and storage in (2, 3) and (sym_type >> 4) == 0x2:
                if sec_num <= len(sections):
                    sec_va = sections[sec_num - 1].VirtualAddress
                    self._named.append(ViewSymbol(
                        name=name, va=self.image_base + sec_va + value, source="coff"))
            # Auxiliary records occupy whole 18-byte slots after their symbol and are
            # not symbols: decoding one as a symbol invents a name out of raw bytes.
            i += 1 + naux

    def _load_elf(self) -> None:
        import io

        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection

        self.format = "elf"
        # One read, reused as pyelftools' stream and as the byte source for read():
        # opening the file twice would double the cost on a large .so.
        self._data = Path(self.path).read_bytes()
        with io.BytesIO(self._data) as f:
            elf = ELFFile(f)
            self.bits = elf.elfclass
            e_machine = elf.header["e_machine"]
            self.arch = {
                "EM_386": "x86", "EM_X86_64": "x64",
                "EM_ARM": "arm", "EM_AARCH64": "arm64",
            }.get(e_machine, "x64" if self.bits == 64 else "x86")
            self.entry_va = elf.header["e_entry"]
            # ET_DYN is loaded at an arbitrary base; sh_addr values are link-time
            # addresses, so the listing shows link-time VAs and says so.
            if elf.header["e_type"] == "ET_DYN":
                self.notes.append(
                    "ET_DYN (PIE/shared object): addresses are link-time, add the "
                    "runtime load base to compare with a live process")

            for s in elf.iter_sections():
                flags = s["sh_flags"]
                if not flags & 0x2:          # SHF_ALLOC: not part of the image
                    continue
                nobits = s["sh_type"] == "SHT_NOBITS"
                self.sections.append(ViewSection(
                    name=s.name,
                    va=s["sh_addr"],
                    size=s["sh_size"],
                    file_offset=-1 if nobits else s["sh_offset"],
                    file_size=0 if nobits else s["sh_size"],
                    perms=_perm_string(True, bool(flags & 0x1), bool(flags & 0x4)),
                    executable=bool(flags & 0x4),
                ))

            for s in elf.iter_sections():
                if not isinstance(s, SymbolTableSection):
                    continue
                source = "dynsym" if s.name == ".dynsym" else "symtab"
                for sym in s.iter_symbols():
                    if (sym.name and sym["st_info"]["type"] == "STT_FUNC"
                            and sym["st_value"]):
                        self._named.append(ViewSymbol(
                            name=sym.name, va=sym["st_value"],
                            size=sym["st_size"], source=source))
        if not self._named:
            self.notes.append("stripped: no STT_FUNC symbols in .symtab or .dynsym")

    def _load_macho(self) -> None:
        self.format = "macho"
        data = Path(self.path).read_bytes()
        if struct.unpack_from(">I", data, 0)[0] in (_FAT_MAGIC, _FAT_MAGIC_64):
            nfat = struct.unpack_from(">I", data, 4)[0]
            if not nfat:
                raise ValueError(f"{self.path}: fat header declares 0 architectures")
            slice_off = struct.unpack_from(">I", data, 16)[0]
            data = data[slice_off:]
            self.notes.append(
                f"fat binary with {nfat} slices: showing the first one only")
        self._data = data

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == _MH_MAGIC_64:
            self.bits, hdr_size = 64, 32
        elif magic == _MH_MAGIC:
            self.bits, hdr_size = 32, 28
        else:
            raise ValueError(f"{self.path}: unsupported Mach-O magic 0x{magic:x}")
        cpu = struct.unpack_from("<I", data, 4)[0]
        self.arch, self.bits = _MACHO_CPUS.get(cpu, (self.arch or "x64", self.bits))
        ncmds = struct.unpack_from("<I", data, 16)[0]

        offset = hdr_size
        for _ in range(min(ncmds, 500)):
            if offset + 8 > len(data):
                break
            cmd, cmd_size = struct.unpack_from("<II", data, offset)
            if cmd_size < 8:
                break
            if cmd in (0x1, 0x19):
                self._macho_segment(data, offset, is_64=cmd == 0x19)
            elif cmd == 0x2:
                self._macho_symtab(data, offset)
            offset += cmd_size
        if not self._named:
            self.notes.append("no LC_SYMTAB entries: function attribution unavailable")

    def _macho_segment(self, data: bytes, offset: int, is_64: bool) -> None:
        segname = data[offset + 8:offset + 24].rstrip(b"\x00").decode("ascii", "replace")
        if is_64:
            initprot = struct.unpack_from("<i", data, offset + 56)[0]
            nsects = struct.unpack_from("<I", data, offset + 64)[0]
            sec_off, sec_size = offset + 72, 80
        else:
            initprot = struct.unpack_from("<i", data, offset + 44)[0]
            nsects = struct.unpack_from("<I", data, offset + 48)[0]
            sec_off, sec_size = offset + 56, 68
        # Segment protection alone is the wrong test on Mach-O: __TEXT is r-x and
        # contains __cstring, so trusting VM_PROT_EXECUTE would feed string literals
        # to the disassembler. A code section additionally carries
        # S_ATTR_PURE_INSTRUCTIONS / S_ATTR_SOME_INSTRUCTIONS, which literal sections
        # never do; if neither is set the section is treated as data, which is the
        # harmless direction to be wrong in.
        segment_exec = bool(initprot & 0x4)
        for i in range(min(nsects, 100)):
            base = sec_off + i * sec_size
            if base + sec_size > len(data):
                break
            secname = data[base:base + 16].rstrip(b"\x00").decode("ascii", "replace")
            if is_64:
                addr, size = struct.unpack_from("<QQ", data, base + 32)
                file_off, _align, _reloff, _nreloc, flags = struct.unpack_from(
                    "<IIIII", data, base + 48)
            else:
                addr, size = struct.unpack_from("<II", data, base + 32)
                file_off, _align, _reloff, _nreloc, flags = struct.unpack_from(
                    "<IIIII", data, base + 40)
            executable = segment_exec and bool(flags & 0x80000400)
            self.sections.append(ViewSection(
                name=f"{segname},{secname}",
                va=addr, size=size,
                file_offset=file_off if file_off else -1,
                file_size=size if file_off else 0,
                perms=_perm_string(bool(initprot & 0x1), bool(initprot & 0x2), segment_exec),
                executable=executable,
            ))

    def _macho_symtab(self, data: bytes, offset: int) -> None:
        symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, offset + 8)
        ent = 16 if self.bits == 64 else 12
        for i in range(min(nsyms, 500_000)):
            base = symoff + i * ent
            if base + ent > len(data):
                break
            n_strx, n_type, _n_sect, _n_desc = struct.unpack_from("<IBBH", data, base)
            value = (struct.unpack_from("<Q", data, base + 8)[0] if ent == 16
                     else struct.unpack_from("<I", data, base + 8)[0])
            # N_STAB entries are debug records, not addresses; N_TYPE == N_SECT (0xe)
            # is the only kind that names something in a section.
            if n_type & 0xE0 or (n_type & 0x0E) != 0x0E or not value:
                continue
            str_at = stroff + n_strx
            if n_strx == 0 or str_at >= stroff + strsize or str_at >= len(data):
                continue
            end = data.find(b"\x00", str_at)
            name = data[str_at:end if end >= 0 else str_at].decode("utf-8", "replace")
            if name:
                self._named.append(ViewSymbol(name=name, va=value, source="macho-symtab"))

    def _merge_named(self) -> None:
        """Sort symbols by VA and fold aliases (several names at one address) together.

        Two symbols at the same address is normal - an export and a COFF name, a weak
        alias, a C name next to its mangled twin. Keeping both as separate entries
        would make the implied-end calculation produce zero-length functions.
        """
        self._named.sort(key=lambda s: (s.va, s.source != "symtab", s.name))
        merged: list[ViewSymbol] = []
        for sym in self._named:
            if merged and merged[-1].va == sym.va:
                prev = merged[-1]
                if sym.name != prev.name and sym.name not in prev.aliases:
                    prev.aliases.append(sym.name)
                prev.size = prev.size or sym.size
                continue
            merged.append(sym)
        self._named = merged

    # ── lookups ──────────────────────────────────────────────

    def section_at(self, va: int) -> ViewSection | None:
        for sec in self.sections:
            if sec.contains(va):
                return sec
        return None

    def find_section(self, name: str) -> ViewSection | None:
        """Section by name; a Mach-O section also matches its bare ``__text`` form."""
        for sec in self.sections:
            if sec.name == name or sec.name.endswith("," + name):
                return sec
        return None

    def find_function(self, name: str) -> ViewSymbol | None:
        for sym in self._named:
            if sym.name == name or name in sym.aliases:
                return sym
        # A leading underscore is a Mach-O / MinGW convention, not part of the name
        # the reader knows the function by.
        for sym in self._named:
            if sym.name.lstrip("_") == name.lstrip("_"):
                return sym
        return None

    def symbols(self) -> list[ViewSymbol]:
        return list(self._named)

    def attribution(self, va: int) -> Attribution | None:
        """Owning function of a VA, or None when nothing covers it.

        Order matters: an exact source wins over an implied one. On PE that is
        ``.pdata`` (a RUNTIME_FUNCTION records the real end); on ELF it is a sized
        ``STT_FUNC``. Only if neither applies does the preceding symbol get used, with
        its end implied by the next symbol and ``exact=False`` on the result.
        """
        if self._pe is not None:
            found = self._pe.function_at(va - self.image_base)
            if found is not None:
                begin, end, _unwind = found
                begin_va = self.image_base + begin
                named = self._exact_named(begin_va)
                return Attribution(
                    name=named.name if named else f"sub_{begin:x}",
                    va=begin_va, size=end - begin, offset=va - begin_va,
                    source=named.source if named else "pdata", exact=True)

        idx = bisect.bisect_right(self._sym_vas, va) - 1
        if idx < 0:
            return None
        sym = self._named[idx]
        if sym.size and va < sym.va + sym.size:
            return Attribution(name=sym.name, va=sym.va, size=sym.size,
                               offset=va - sym.va, source=sym.source, exact=True)
        if sym.size:
            return None          # past a symbol whose real end is known: a gap
        implied_end = self._implied_end(idx)
        if implied_end is None or va >= implied_end:
            return None
        return Attribution(name=sym.name, va=sym.va, size=implied_end - sym.va,
                           offset=va - sym.va, source=sym.source, exact=False)

    def _exact_named(self, va: int) -> ViewSymbol | None:
        idx = bisect.bisect_left(self._sym_vas, va)
        if idx < len(self._named) and self._named[idx].va == va:
            return self._named[idx]
        return None

    def _implied_end(self, idx: int) -> int | None:
        """End of a size-less symbol: the next symbol, clamped to its own section."""
        sym = self._named[idx]
        sec = self.section_at(sym.va)
        end = sec.end_va if sec else None
        if idx + 1 < len(self._named):
            nxt = self._named[idx + 1].va
            if end is None or nxt < end:
                end = nxt
        return end

    def function_range(self, sym: ViewSymbol) -> tuple[int, int]:
        """(start_va, end_va) for a symbol, using the best available end."""
        if self._pe is not None:
            found = self._pe.function_at(sym.va - self.image_base)
            if found is not None:
                return self.image_base + found[0], self.image_base + found[1]
        if sym.size:
            return sym.va, sym.va + sym.size
        idx = bisect.bisect_left(self._sym_vas, sym.va)
        implied = self._implied_end(idx) if idx < len(self._named) else None
        sec = self.section_at(sym.va)
        fallback = sec.end_va if sec else sym.va + 0x100
        return sym.va, implied or fallback

    def read(self, va: int, n: int) -> bytes:
        """Bytes at a VA, clamped to the containing section's file-backed part."""
        if self._pe is not None:
            return self._pe.read_rva(va - self.image_base, n) or b""
        sec = self.section_at(va)
        if sec is None or sec.file_offset < 0:
            return b""
        delta = va - sec.va
        if delta >= sec.file_size:
            return b""
        start = sec.file_offset + delta
        avail = min(n, sec.file_size - delta, max(len(self._data) - start, 0))
        return self._data[start:start + avail]

    def file_offset(self, va: int) -> int | None:
        if self._pe is not None:
            return self._pe.rva_to_off(va - self.image_base)
        sec = self.section_at(va)
        if sec is None or sec.file_offset < 0 or va - sec.va >= sec.file_size:
            return None
        return sec.file_offset + (va - sec.va)


# ── disassembly ──────────────────────────────────────────────


def _capstone_for(arch: str):
    import capstone

    table = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    cs_arch, cs_mode = table.get(arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return md


def _printable(raw: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in raw)


def _ascii_run(raw: bytes) -> str:
    """Leading NUL-terminated printable run of ``raw``, or "" if there is none."""
    run = raw.split(b"\x00")[0][:MAX_STRING_LEN]
    if len(run) >= MIN_STRING_LEN and all(0x20 <= b < 0x7F for b in run):
        return run.decode("ascii")
    return ""


def _branch_target(insn, arch: str) -> int | None:
    """Absolute target of a direct call/jmp, or None when it is indirect."""
    if arch in ("x86", "x64"):
        if insn.mnemonic not in ("call", "jmp") and not insn.mnemonic.startswith("j"):
            return None
    elif insn.mnemonic not in ("bl", "b", "blx", "bx"):
        return None
    op = insn.op_str.strip()
    if op.startswith("#"):          # ARM immediate branch
        op = op[1:]
    try:
        return int(op, 16) if op.startswith("0x") else None
    except ValueError:
        return None


def _rip_target(insn, arch: str) -> int | None:
    """Target of an x86-64 rip-relative memory operand, or None."""
    if arch != "x64" or "rip" not in insn.op_str:
        return None
    from capstone import x86 as cx86

    for op in insn.operands:
        if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
            return insn.address + insn.size + op.mem.disp
    return None


def _annotate(view: ImageView, target_va: int) -> str:
    """Human-readable label for a resolved target: section, name, string content."""
    parts: list[str] = [f"-> 0x{target_va:x}"]
    sec = view.section_at(target_va)
    if sec:
        parts.append(f"[{sec.name}]")
    attr = view.attribution(target_va)
    if attr:
        label = attr.name if attr.offset == 0 else f"{attr.name}+0x{attr.offset:x}"
        parts.append(label if attr.exact else label + "?")
    elif sec and not sec.executable:
        text = _ascii_run(view.read(target_va, 64))
        if text:
            parts.append(f'"{text[:60]}"')
    return " ".join(parts)


def _code_lines(view: ImageView, md, start: int, end: int, count: int) -> list[dict]:
    """Decode [start, end) as instructions, resyncing over embedded data.

    A single ``md.disasm`` pass stops at the first byte it cannot decode and the
    generator simply ends - a jump table or alignment junk mid-function silently
    truncates the listing (the same trap ``pe_rva._decode_body`` resyncs around).
    Here the undecodable byte is *reported* as a ``bad`` line instead of being
    skipped quietly, because in a listing the reader needs to see the gap.
    """
    lines: list[dict] = []
    data = view.read(start, min(end - start, MAX_DECODE_BYTES))
    pos = 0
    while pos < len(data) and len(lines) < count:
        progressed = False
        for insn in md.disasm(data[pos:], start + pos):
            progressed = True
            pos = insn.address - start + insn.size
            target = _branch_target(insn, view.arch)
            if target is None:
                target = _rip_target(insn, view.arch)
            lines.append(_line(view, insn.address, insn.bytes, "insn",
                               mnemonic=insn.mnemonic, op_str=insn.op_str,
                               target_va=target))
            if len(lines) >= count:
                break
        if not progressed:
            lines.append(_line(view, start + pos, data[pos:pos + 1], "bad"))
            pos += 1
    return lines


def _data_lines(view: ImageView, start: int, end: int, count: int) -> list[dict]:
    """Render [start, end) as strings and hex rows - never as instructions."""
    lines: list[dict] = []
    va = start
    while va < end and len(lines) < count:
        chunk = view.read(va, min(MAX_STRING_LEN + 1, end - va))
        if not chunk:
            break
        text = _ascii_run(chunk)
        if text:
            raw = chunk[:len(text) + 1]
            lines.append(_line(view, va, raw, "string", text=text))
            va += len(raw)
            continue
        width = min(DATA_ROW_WIDTH - (va % DATA_ROW_WIDTH), end - va)
        raw = chunk[:width]
        lines.append(_line(view, va, raw, "data", text=_printable(raw)))
        va += len(raw)
    return lines


def _line(view: ImageView, va: int, raw: bytes, kind: str, mnemonic: str = "",
          op_str: str = "", text: str = "", target_va: int | None = None) -> dict:
    sec = view.section_at(va)
    attr = view.attribution(va)
    row: dict[str, Any] = {
        "va": va,
        "file_offset": view.file_offset(va),
        "section": sec.name if sec else "",
        "function": attr.name if attr else "",
        "func_offset": attr.offset if attr else None,
        "function_exact": attr.exact if attr else None,
        "kind": kind,
        "bytes_hex": raw.hex(),
        "mnemonic": mnemonic,
        "op_str": op_str,
        "text": text,
        "target_va": target_va,
        "target": _annotate(view, target_va) if target_va is not None else "",
    }
    if view.format == "pe":
        row["rva"] = va - view.image_base
    return row


def disasm_listing(
    binary_path: str | Path,
    section: str | None = None,
    function: str | None = None,
    start: int | None = None,
    end: int | None = None,
    count: int = DEFAULT_COUNT,
    view: ImageView | None = None,
) -> dict[str, Any]:
    """Annotated listing of a range, function or section.

    Every line carries the address, the raw bytes, the decoded instruction, the
    section it lives in and the function that owns it. Non-executable sections are
    rendered as strings and hex rows rather than decoded, and a range that crosses a
    section boundary is split so each part is treated according to its own flags.

    Args:
        section: section name (``.text``, ``__text``) - lists that section.
        function: symbol name - lists exactly that function's bounds.
        start/end: explicit VA range. ``start`` alone uses ``count`` to stop.
        count: maximum number of lines.
        view: reuse an existing ``ImageView`` instead of re-parsing the file.

    Returns:
        {path, format, arch, bits, image_base, entry_va, start_va, end_va,
         scope, truncated, notes, lines}
    """
    view = view or ImageView(binary_path)
    scope = ""
    if function:
        sym = view.find_function(function)
        if sym is None:
            return _empty(view, error=f"no symbol named {function!r} in {view.path}")
        start, end = view.function_range(sym)
        scope = f"function {sym.name}"
    elif section:
        sec = view.find_section(section)
        if sec is None:
            names = ", ".join(s.name for s in view.sections)
            return _empty(view, error=f"no section named {section!r} (have: {names})")
        start, end = sec.va, sec.end_va
        scope = f"section {sec.name}"
    elif start is None:
        # Default scope. An entry point only helps if it is inside a section: a DLL
        # without one (AddressOfEntryPoint == 0) would otherwise produce an empty
        # listing that looks like a broken image rather than a missing argument.
        if view.entry_va is not None and view.section_at(view.entry_va):
            start = view.entry_va
            scope = "entry point"
        else:
            first = next((s for s in view.sections if s.executable), None)
            if first is None:
                return _empty(view, error="no entry point and no executable section: "
                                          "pass --section, --function or --start")
            start, end = first.va, first.end_va
            scope = f"section {first.name} (no entry point in this image)"
    if end is None:
        # 16 bytes is the longest x86 instruction; ARM is fixed-width and shorter.
        end = start + count * 16
    if end <= start:
        return _empty(view, error=f"empty range 0x{start:x}..0x{end:x}")

    lines: list[dict] = []
    va = start
    truncated = False
    while va < end and len(lines) < count:
        sec = view.section_at(va)
        if sec is None:
            nxt = next((s.va for s in view.sections if s.va > va), None)
            if nxt is None or nxt >= end:
                break
            va = nxt                     # skip an inter-section hole
            continue
        stop = min(sec.end_va, end)
        room = count - len(lines)
        if sec.executable:
            md = _capstone_for(view.arch)
            chunk = _code_lines(view, md, va, stop, room)
        else:
            chunk = _data_lines(view, va, stop, room)
        if not chunk:
            # No file backing (BSS) - report it rather than looping forever.
            lines.append({"va": va, "section": sec.name, "kind": "nodata",
                          "bytes_hex": "", "mnemonic": "", "op_str": "",
                          "text": "no file data (uninitialized)", "function": "",
                          "file_offset": None, "func_offset": None,
                          "function_exact": None, "target_va": None, "target": ""})
            va = stop
            continue
        lines.extend(chunk)
        last = chunk[-1]
        va = last["va"] + max(len(last["bytes_hex"]) // 2, 1)
    if va < end:
        truncated = True

    out = _empty(view)
    out.update({
        "start_va": start, "end_va": end, "scope": scope,
        "truncated": truncated, "lines": lines,
    })
    if truncated:
        out["notes"] = out["notes"] + [
            f"stopped at 0x{va:x} of 0x{end:x}: line cap {count} or byte cap "
            f"{MAX_DECODE_BYTES} reached - raise --count or narrow the range"]
    return out


def _empty(view: ImageView, error: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "path": view.path, "format": view.format, "arch": view.arch,
        "bits": view.bits, "image_base": view.image_base, "entry_va": view.entry_va,
        "start_va": None, "end_va": None, "scope": "", "truncated": False,
        "notes": list(view.notes), "lines": [],
    }
    if error:
        out["error"] = error
    return out


def sections_view(binary_path: str | Path, view: ImageView | None = None) -> dict[str, Any]:
    """Section table with VA range, file offset, permissions and symbol count."""
    view = view or ImageView(binary_path)
    rows = []
    for sec in view.sections:
        rows.append({
            "name": sec.name, "va": sec.va, "end_va": sec.end_va, "size": sec.size,
            "file_offset": sec.file_offset, "file_size": sec.file_size,
            "perms": sec.perms, "executable": sec.executable,
            "symbols": sum(1 for s in view.symbols() if sec.contains(s.va)),
        })
    return {"path": view.path, "format": view.format, "arch": view.arch,
            "bits": view.bits, "image_base": view.image_base,
            "entry_va": view.entry_va, "notes": list(view.notes), "sections": rows}


def symbols_view(
    binary_path: str | Path,
    pattern: str | None = None,
    limit: int = 200,
    view: ImageView | None = None,
) -> dict[str, Any]:
    """Function symbols with their section and size.

    ``size`` is 0 when the symbol source did not record one (PE exports, Mach-O
    ``nlist``); that is reported as-is rather than filled in with the distance to the
    next symbol, which would look like a measurement.
    """
    view = view or ImageView(binary_path)
    needle = pattern.lower() if pattern else None
    rows = []
    for sym in view.symbols():
        if needle and needle not in sym.name.lower():
            continue
        sec = view.section_at(sym.va)
        rows.append({
            "name": sym.name, "va": sym.va, "size": sym.size, "source": sym.source,
            "section": sec.name if sec else "", "aliases": list(sym.aliases),
        })
        if len(rows) >= limit:
            break
    total = sum(1 for s in view.symbols()
                if not needle or needle in s.name.lower())
    return {"path": view.path, "format": view.format, "arch": view.arch,
            "notes": list(view.notes), "total": total, "shown": len(rows),
            "symbols": rows}
