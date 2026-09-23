"""Synthetic x86-64 ELF image used by the disassembly-view tests.

Assembled field by field from the ELF64 layout: section headers, a real ``.symtab``
with two sized ``STT_FUNC`` symbols, an executable ``.text``, a read-only ``.rodata``
holding a C string, a ``SHT_NOBITS`` ``.bss`` that has no file bytes at all, and a
hand-encoded DWARF 4 line program. Nothing is derived from ``disasm_view``'s
behaviour, so a test using it can tell "the tool is wrong" from "the expectation is
wrong"; ``pyelftools`` and ``capstone`` act as independent oracles that the fixture
itself is well-formed.

The interesting shapes for the view under test:

* ``main`` and ``helper`` are adjacent and **sized**, so attribution is exact and the
  byte after ``helper`` belongs to no function at all (a real inter-function gap).
* ``.rodata`` is allocated and non-executable - disassembling it would be wrong.
* ``.bss`` occupies address space with no file backing, so a reader has nothing to
  show there and must say so rather than printing zeros.
* The line program covers ``main`` only and closes with ``DW_LNE_end_sequence``.
  ``helper`` therefore has no source attribution, which is the case a plain "bisect
  for the last row at or below this address" lookup gets wrong - it hands every
  later address the final row's file and line.
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

# Ground truth for the line program encoded below: (address, file, line) rows, and
# the address where the sequence ends. Everything at or after DWARF_END has no line
# information at all.
DWARF_FILE = "hello.c"
DWARF_ROWS = [(MAIN_VA, DWARF_FILE, 10), (MAIN_VA + 4, DWARF_FILE, 11)]
DWARF_END = MAIN_VA + MAIN_SIZE


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


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _sleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)


def _debug_abbrev() -> bytes:
    """One abbreviation: DW_TAG_compile_unit with DW_AT_stmt_list and DW_AT_name."""
    return (_uleb(1) + _uleb(0x11) + b"\x00"          # code 1, TAG_compile_unit, no kids
            + _uleb(0x10) + _uleb(0x17)               # DW_AT_stmt_list, DW_FORM_sec_offset
            + _uleb(0x03) + _uleb(0x08)               # DW_AT_name,      DW_FORM_string
            + _uleb(0) + _uleb(0)                     # end of attribute list
            + _uleb(0))                               # end of abbreviation table


def _debug_info() -> bytes:
    """A single DWARF 4 compile unit pointing at line program offset 0.

    pyelftools reaches the line program through the CU's DW_AT_stmt_list, so the
    fixture needs a real (if minimal) .debug_info even though the test only cares
    about .debug_line.
    """
    die = _uleb(1) + struct.pack("<I", 0) + DWARF_FILE.encode() + b"\x00"
    body = struct.pack("<HIB", 4, 0, 8) + die      # version, abbrev offset, addr size
    return struct.pack("<I", len(body)) + body


def _debug_line() -> bytes:
    """A DWARF 4 line program covering `main` and nothing else.

    Rows are emitted with DW_LNS_copy after explicit advances rather than with
    special opcodes, so the encoding stays readable and the addresses/lines here are
    exactly DWARF_ROWS. The closing DW_LNE_end_sequence is the part that matters for
    the test: it makes DWARF_END the end of coverage, so `helper` has no line info.
    """
    prologue = bytes([
        1,    # minimum_instruction_length
        1,    # maximum_operations_per_instruction (DWARF 4)
        1,    # default_is_stmt
    ]) + struct.pack("<bB", -5, 14) + bytes([13])   # line_base, line_range, opcode_base
    prologue += bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])  # standard_opcode_lengths
    prologue += b"\x00"                                       # include_directories: none
    prologue += DWARF_FILE.encode() + b"\x00" + _uleb(0) + _uleb(0) + _uleb(0)
    prologue += b"\x00"                                       # file_names terminator

    program = b"\x00" + _uleb(9) + b"\x02" + struct.pack("<Q", MAIN_VA)  # set_address
    program += b"\x03" + _sleb(DWARF_ROWS[0][2] - 1)          # advance_line to row 0
    program += b"\x01"                                        # copy -> row 0
    program += b"\x02" + _uleb(DWARF_ROWS[1][0] - DWARF_ROWS[0][0])      # advance_pc
    program += b"\x03" + _sleb(DWARF_ROWS[1][2] - DWARF_ROWS[0][2])
    program += b"\x01"                                        # copy -> row 1
    program += b"\x02" + _uleb(DWARF_END - DWARF_ROWS[1][0])  # advance_pc to the end
    program += b"\x00" + _uleb(1) + b"\x01"                   # DW_LNE_end_sequence

    header_tail = struct.pack("<H", 4) + struct.pack("<I", len(prologue))
    body = header_tail + prologue + program
    return struct.pack("<I", len(body)) + body



def _build() -> bytes:
    text = bytearray(0x30)
    text[0:len(_MAIN)] = _MAIN
    text[HELPER_VA - TEXT_VA:HELPER_VA - TEXT_VA + len(_HELPER)] = _HELPER
    # The gap: valid instructions that belong to no symbol.
    text[GAP_VA - TEXT_VA:GAP_VA - TEXT_VA + 3] = b"\x90\x90\xc3"
    rodata = RODATA_TEXT.encode("ascii") + b"\x00"
    abbrev, info_cu, line = _debug_abbrev(), _debug_info(), _debug_line()

    names = [b"", b".text", b".rodata", b".bss", b".symtab", b".strtab", b".shstrtab",
             b".debug_abbrev", b".debug_info", b".debug_line"]
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
    off_abbrev = off_shstrtab + len(shstrtab)
    off_info = off_abbrev + len(abbrev)
    off_line = off_info + len(info_cu)
    off_shdrs = off_line + len(line)

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
        # Debug sections carry no SHF_ALLOC: they are not part of the address space,
        # so an address-indexed view must not list them as sections.
        _section_header(name_off[b".debug_abbrev"], _SHT_PROGBITS, 0, 0, off_abbrev,
                        len(abbrev)),
        _section_header(name_off[b".debug_info"], _SHT_PROGBITS, 0, 0, off_info,
                        len(info_cu)),
        _section_header(name_off[b".debug_line"], _SHT_PROGBITS, 0, 0, off_line, len(line)),
    ])
    shnum = 10

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
    return (header + bytes(text) + rodata + symtab + strtab + shstrtab
            + abbrev + info_cu + line + shdrs)


def write_synthetic_elf(path) -> str:
    """Write the fixture ELF to ``path`` and return the path as a string."""
    path.write_bytes(_build())
    return str(path)
