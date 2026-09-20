"""Synthetic x86-64 PE image used by the pe_rva and documentation tests.

The image is assembled field by field from the PE/COFF layout, and every
rip-relative instruction is encoded by hand with its displacement computed from
the ISA rule (the displacement is relative to the *end* of the instruction).
Nothing here derives from pe_rva's behaviour, so the tests that use it can
distinguish "pe_rva is wrong" from "the expectation is wrong".

``pefile`` must accept the result and capstone must agree that each encoding
resolves to ``TARGET_RVA`` — both are asserted in tests/test_pe_rva.py.
"""

from __future__ import annotations

import struct

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
TEXT_VSIZE = 0x400
RDATA_RVA = 0x2000
PDATA_RVA = 0x3000

TARGET_RVA = RDATA_RVA           # the "global" that every reference resolves to
PTR_RVA = RDATA_RVA + 0x10       # qword holding IMAGE_BASE + TARGET_RVA
CALL_TARGET_RVA = TEXT_RVA + 0x200
LEAF_RVA = TEXT_RVA + 0x300      # deliberately outside every .pdata entry
UNWIND_RVA = 0x4000

# (label, bytes before disp32, bytes after disp32). Each entry is a real encoding
# of a rip-relative access; the ones with a prefix ahead of the opcode are
# precisely what an opcode-whitelist scan cannot reach.
RIP_FORMS: list[tuple[str, bytes, bytes]] = [
    ("lea rax, [rip+d]",          b"\x48\x8D\x05",         b""),
    ("lock cmpxchg [rip+d], rcx", b"\xF0\x48\x0F\xB1\x0D", b""),
    ("mov word [rip+d], ax",      b"\x66\x89\x05",         b""),
    ("movss xmm0, [rip+d]",       b"\xF3\x0F\x10\x05",     b""),
    ("mov byte [rip+d], 1",       b"\xC6\x05",             b"\x01"),
    ("cmp byte [rip+d], 0",       b"\x80\x3D",             b"\x00"),
    ("test byte [rip+d], al",     b"\x84\x05",             b""),
    ("movdqa xmm0, [rip+d]",      b"\x66\x0F\x6F\x05",     b""),
]

# An undecodable pair followed by generous nop padding, so the .pdata pass has to
# resync inside the function body (jump tables and alignment do this for real).
DATA_IN_CODE = b"\xFF\xFF" + b"\x90" * 16


def _rip_bytes(rva: int, head: bytes, tail: bytes, target_rva: int) -> bytes:
    """Encode one rip-relative instruction at ``rva`` pointing at ``target_rva``."""
    length = len(head) + 4 + len(tail)
    disp = target_rva - (rva + length)   # ISA: disp is relative to the next insn
    return head + struct.pack("<i", disp) + tail


def _build_text() -> tuple[bytearray, dict[str, int], int]:
    """Return (.text bytes, {label: rva}, function_end_rva)."""
    text = bytearray(TEXT_VSIZE)
    placed: dict[str, int] = {}
    cursor = TEXT_RVA

    def emit(raw: bytes) -> None:
        nonlocal cursor
        text[cursor - TEXT_RVA:cursor - TEXT_RVA + len(raw)] = raw
        cursor += len(raw)

    for i, (label, head, tail) in enumerate(RIP_FORMS):
        if i == len(RIP_FORMS) - 1:
            emit(DATA_IN_CODE)               # last form sits behind a decode gap
        placed[label] = cursor
        emit(_rip_bytes(cursor, head, tail, TARGET_RVA))
        emit(b"\x90")

    placed["call"] = cursor
    emit(b"\xE8" + struct.pack("<i", CALL_TARGET_RVA - (cursor + 5)))
    emit(b"\xC3")                            # ret
    func_end = cursor

    # leaf code: same shape, but no RUNTIME_FUNCTION will cover it
    placed["leaf mov rax, [rip+d]"] = LEAF_RVA
    text[LEAF_RVA - TEXT_RVA:] = _rip_bytes(LEAF_RVA, b"\x48\x8B\x05", b"", TARGET_RVA)

    return text, placed, func_end


def _build_image(func_end_rva: int, text: bytes) -> bytes:
    rdata = bytearray(0x200)
    rdata[0] = 0x01                                             # the target byte
    rdata[0x10:0x18] = struct.pack("<Q", IMAGE_BASE + TARGET_RVA)

    # .pdata: two RUNTIME_FUNCTIONs, VirtualSize = 24. The raw section is padded
    # to FileAlignment with 0xAA so that a parser walking SizeOfRawData (instead
    # of min(VirtualSize, SizeOfRawData)) produces bogus entries.
    entries = [(TEXT_RVA, func_end_rva, UNWIND_RVA),
               (LEAF_RVA + 0x80, LEAF_RVA + 0x90, UNWIND_RVA)]
    pdata = bytearray()
    for begin, end, unwind in entries:
        pdata += struct.pack("<III", begin, end, unwind)
    pdata_vsize = len(pdata)
    pdata += b"\xAA" * (0x200 - len(pdata))

    headers_size = 0x200
    sections = [
        (b".text\0\0\0", TEXT_VSIZE, TEXT_RVA, 0x400, 0x200, 0x60000020),
        (b".rdata\0\0", len(rdata), RDATA_RVA, 0x200, 0x600, 0x40000040),
        (b".pdata\0\0", pdata_vsize, PDATA_RVA, 0x200, 0x800, 0x40000040),
    ]

    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,            # Magic (PE32+)
        14, 0,            # linker version
        0x400,            # SizeOfCode
        0x400,            # SizeOfInitializedData
        0,                # SizeOfUninitializedData
        TEXT_RVA,         # AddressOfEntryPoint
        TEXT_RVA,         # BaseOfCode
        IMAGE_BASE,
        0x1000,           # SectionAlignment
        0x200,            # FileAlignment
        6, 0, 0, 0, 6, 0,  # OS / image / subsystem versions
        0,                # Win32VersionValue
        0x4000,           # SizeOfImage
        headers_size,     # SizeOfHeaders
        0,                # CheckSum
        3,                # Subsystem (console)
        0x160,            # DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0,                # LoaderFlags
        16,               # NumberOfRvaAndSizes
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 3 * 8, PDATA_RVA, pdata_vsize)  # EXCEPTION
    optional += bytes(directories)
    assert len(optional) == 240

    file_header = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0,
                              len(optional), 0x2022)
    section_table = b"".join(
        struct.pack("<8sIIIIIIHHI", name, vsize, vaddr, rawsize, rawptr, 0, 0, 0, 0, chars)
        for name, vsize, vaddr, rawsize, rawptr, chars in sections
    )

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    image = bytearray(dos)
    image += b"PE\0\0" + file_header + optional + section_table
    assert len(image) == headers_size, len(image)
    image += text.ljust(0x400, b"\0")
    image += bytes(rdata)
    image += bytes(pdata)
    return bytes(image)


def write_synthetic_pe(path) -> tuple[str, dict[str, int], int]:
    """Write the fixture image to ``path``; return (path, {label: rva}, func_end)."""
    text, placed, func_end = _build_text()
    path.write_bytes(_build_image(func_end, bytes(text)))
    return str(path), placed, func_end
