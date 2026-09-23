"""Synthetic x86-64 Mach-O image used by the disassembly-view tests.

Assembled from the Mach-O layout by hand: an ``MH_EXECUTE`` header, one
``LC_SEGMENT_64`` (``__TEXT``) holding both ``__text`` and ``__cstring``, and an
``LC_SYMTAB`` with two ``N_SECT`` symbols. Nothing is derived from the behaviour of
``disasm_view``.

The shape that matters here: ``__TEXT`` is r-x, and ``__cstring`` lives **inside** it.
A reader that decides "code or data" from the segment protection will disassemble the
string literals - so the fixture deliberately gives ``__text`` the
``S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`` attributes and ``__cstring``
only ``S_CSTRING_LITERALS``, which is the distinction the code has to use.

Mach-O ``nlist`` entries carry no size, so function bounds here can only be *implied*
by the next symbol - the case the view must report as inexact.
"""

from __future__ import annotations

import struct

TEXT_VA = 0x100001000
CSTRING_VA = 0x100002000
IMAGE_VA = 0x100000000

MAIN_VA = TEXT_VA
HELPER_VA = TEXT_VA + 0x10
CSTRING_TEXT = "Hello, Mach-O"

_MH_MAGIC_64 = 0xFEEDFACF
_CPU_X86_64 = 0x01000007
_MH_EXECUTE = 0x2
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2

_S_CSTRING_LITERALS = 0x2
_S_ATTR_PURE_INSTRUCTIONS = 0x80000000
_S_ATTR_SOME_INSTRUCTIONS = 0x400

_N_SECT, _N_EXT = 0x0E, 0x01

# main: push rbp; mov rbp, rsp; call helper; pop rbp; ret
_MAIN = (b"\x55" + b"\x48\x89\xe5"
         + b"\xe8" + struct.pack("<i", HELPER_VA - (MAIN_VA + 0x04 + 5))
         + b"\x5d" + b"\xc3")
_HELPER = b"\x31\xc0\xc3"          # xor eax, eax; ret


def _section_64(sectname: bytes, segname: bytes, addr: int, size: int, offset: int,
                flags: int) -> bytes:
    return (sectname.ljust(16, b"\x00") + segname.ljust(16, b"\x00")
            + struct.pack("<QQIIIIIIII", addr, size, offset, 4, 0, 0, flags, 0, 0, 0))


def _build() -> bytes:
    text = bytearray(0x20)
    text[0:len(_MAIN)] = _MAIN
    text[HELPER_VA - TEXT_VA:HELPER_VA - TEXT_VA + len(_HELPER)] = _HELPER
    cstring = CSTRING_TEXT.encode("ascii") + b"\x00"

    hdr_size = 32
    seg_size = 72 + 2 * 80
    symtab_size = 24
    sizeofcmds = seg_size + symtab_size
    off_text = hdr_size + sizeofcmds
    off_cstring = off_text + len(text)
    off_symtab = off_cstring + len(cstring)

    strtab = b"\x00_main\x00_helper\x00"
    nlists = struct.pack("<IBBHQ", 1, _N_SECT | _N_EXT, 1, 0, MAIN_VA)
    nlists += struct.pack("<IBBHQ", 7, _N_SECT | _N_EXT, 1, 0, HELPER_VA)
    off_strtab = off_symtab + len(nlists)

    header = struct.pack("<IIIIIIII", _MH_MAGIC_64, _CPU_X86_64, 3, _MH_EXECUTE,
                         2, sizeofcmds, 0x200085, 0)
    assert len(header) == hdr_size

    # maxprot / initprot = VM_PROT_READ | VM_PROT_EXECUTE (5): __TEXT is r-x and holds
    # the string literals too, which is exactly why the section attributes decide.
    segment = struct.pack("<II", _LC_SEGMENT_64, seg_size)
    segment += b"__TEXT".ljust(16, b"\x00")
    segment += struct.pack("<QQQQiiII", IMAGE_VA, 0x3000, 0, off_strtab + len(strtab),
                           5, 5, 2, 0)
    segment += _section_64(b"__text", b"__TEXT", TEXT_VA, len(text), off_text,
                           _S_ATTR_PURE_INSTRUCTIONS | _S_ATTR_SOME_INSTRUCTIONS)
    segment += _section_64(b"__cstring", b"__TEXT", CSTRING_VA, len(cstring), off_cstring,
                           _S_CSTRING_LITERALS)
    assert len(segment) == seg_size, len(segment)

    symtab = struct.pack("<IIIIII", _LC_SYMTAB, symtab_size, off_symtab, 2,
                         off_strtab, len(strtab))

    return (header + segment + symtab + bytes(text) + cstring + nlists + strtab)


def write_synthetic_macho(path) -> str:
    """Write the fixture Mach-O to ``path`` and return the path as a string."""
    path.write_bytes(_build())
    return str(path)
