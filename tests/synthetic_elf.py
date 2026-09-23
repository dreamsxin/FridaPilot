"""Synthetic x86-64 ELF image used by the disassembly-view tests.

Assembled field by field from the ELF64 layout: section headers, a real ``.symtab``
with two sized ``STT_FUNC`` symbols, an executable ``.text``, a read-only ``.rodata``
holding a C string, and a ``SHT_NOBITS`` ``.bss`` that has no file bytes at all.
Nothing here is derived from ``disasm_view``'s behaviour, so a test using it can tell
"the tool is wrong" from "the expectation is wrong"; ``pyelftools`` and ``capstone``
act as independent oracles that the fixture itself is well-formed.

The interesting shapes for the view under test:

* ``main`` and ``helper`` are adjacent and **sized**, so attribution is exact and the
  byte after ``helper`` belongs to no function at all (a real inter-function gap).
* ``.rodata`` is allocated and non-executable - disassembling it would be wrong.
* ``.bss`` occupies address space with no file backing, so a reader has nothing to
  show there and must say so rather than printing zeros.
"""

from __future__ import annotations

import struct

TEXT_VA = 0x401000
RODATA_VA = 0x402000
BSS_VA = 0x403000

MAIN_VA = TEXT_VA           # sized STT_FUNC, contains the call
MAIN_SIZE = 0x0B
HELPER_VA = TEXT_VA + 0x10  # sized STT_FUNC, the call target
HELPER_SIZE = 0x03
GAP_VA = TEXT_VA + 0x20     # inside .text, covered by no symbol
RODATA_TEXT = "Hello, ELF"

# main:
#   0x401000  55              push rbp
#   0x401001  48 89 e5        mov rbp, rsp
#   0x401004  e8 07 00 00 00  call 0x401010   (disp is relative to the next insn)
#   0x401009  5d              pop rbp
#   0x40100a  c3              ret
_MAIN = (b"\x55" + b"\x48\x89\xe5"
         + b"\xe8" + struct.pack("<i", HELPER_VA - (TEXT_VA + 0x04 + 5))
         + b"\x5d" + b"\xc3")
# helper: xor eax, eax; ret
_HELPER = b"\x31\xc0\xc3"

_SHT_PROGBITS, _SHT_SYMTAB, _SHT_STRTAB, _SHT_NOBITS = 1, 2, 3, 8
_SHF_WRITE, _SHF_ALLOC, _SHF_EXECINSTR = 0x1, 0x2, 0x4
_STB_GLOBAL, _STT_FUNC = 1, 2


def _section_header(name_off: int, sh_type: int, flags: int, addr: int, offset: int,
                    size: int, link: int = 0, info: int = 0, align: int = 1,
                    entsize: int = 0) -> bytes:
    return struct.pack("<IIQQQQIIQQ", name_off, sh_type, flags, addr, offset, size,
                       link, info, align, entsize)


def _build() -> bytes:
    text = bytearray(0x30)
    text[0:len(_MAIN)] = _MAIN
    text[HELPER_VA - TEXT_VA:HELPER_VA - TEXT_VA + len(_HELPER)] = _HELPER
    # The gap: valid instructions that belong to no symbol.
    text[GAP_VA - TEXT_VA:GAP_VA - TEXT_VA + 3] = b"\x90\x90\xc3"
    rodata = RODATA_TEXT.encode("ascii") + b"\x00"

    names = [b"", b".text", b".rodata", b".bss", b".symtab", b".strtab", b".shstrtab"]
    shstrtab = b"\x00".join(names) + b"\x00"
    name_off = {}
    cursor = 0
    for n in names:
        name_off[n] = cursor
        cursor += len(n) + 1

    symnames = [b"", b"main", b"helper"]
    strtab = b"\x00".join(symnames) + b"\x00"
    sym_off = {}
    cursor = 0
    for n in symnames:
        sym_off[n] = cursor
        cursor += len(n) + 1

    info = (_STB_GLOBAL << 4) | _STT_FUNC
    symtab = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)                     # null entry
    symtab += struct.pack("<IBBHQQ", sym_off[b"main"], info, 0, 1, MAIN_VA, MAIN_SIZE)
    symtab += struct.pack("<IBBHQQ", sym_off[b"helper"], info, 0, 1, HELPER_VA, HELPER_SIZE)

    ehsize = 64
    off_text = ehsize
    off_rodata = off_text + len(text)
    off_symtab = off_rodata + len(rodata)
    off_strtab = off_symtab + len(symtab)
    off_shstrtab = off_strtab + len(strtab)
    off_shdrs = off_shstrtab + len(shstrtab)

    shdrs = b"".join([
        _section_header(0, 0, 0, 0, 0, 0),                                # SHN_UNDEF
        _section_header(name_off[b".text"], _SHT_PROGBITS,
                        _SHF_ALLOC | _SHF_EXECINSTR, TEXT_VA, off_text, len(text), align=16),
        _section_header(name_off[b".rodata"], _SHT_PROGBITS, _SHF_ALLOC,
                        RODATA_VA, off_rodata, len(rodata), align=1),
        # SHT_NOBITS: sh_offset is meaningless, the section has no file bytes.
        _section_header(name_off[b".bss"], _SHT_NOBITS, _SHF_ALLOC | _SHF_WRITE,
                        BSS_VA, off_shdrs, 0x40, align=8),
        _section_header(name_off[b".symtab"], _SHT_SYMTAB, 0, 0, off_symtab, len(symtab),
                        link=5, info=1, align=8, entsize=24),
        _section_header(name_off[b".strtab"], _SHT_STRTAB, 0, 0, off_strtab, len(strtab)),
        _section_header(name_off[b".shstrtab"], _SHT_STRTAB, 0, 0, off_shstrtab,
                        len(shstrtab)),
    ])
    shnum = 7

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type = ET_EXEC (a fixed load address, unlike ET_DYN)
        0x3E,         # e_machine = EM_X86_64
        1,            # e_version
        MAIN_VA,      # e_entry
        0,            # e_phoff: no program headers; sections carry the addresses
        off_shdrs,
        0,            # e_flags
        ehsize, 0, 0,  # e_ehsize, e_phentsize, e_phnum
        64, shnum, 6,  # e_shentsize, e_shnum, e_shstrndx
    )
    assert len(header) == ehsize, len(header)
    return (header + bytes(text) + rodata + symtab + strtab + shstrtab + shdrs)


def write_synthetic_elf(path) -> str:
    """Write the fixture ELF to ``path`` and return the path as a string."""
    path.write_bytes(_build())
    return str(path)
