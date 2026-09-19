"""Tests for fridapilot.tools.pe_rva.

Accuracy strategy — these tests must not cement whatever the implementation
currently prints:

* The synthetic PE is assembled from hand-written x86-64 encodings whose
  displacement is computed from the ISA rule (rip-relative operands are relative
  to the *end* of the instruction), not from anything pe_rva does.
* ``test_fixture_decodes_to_target`` proves the fixture is right by decoding it
  with capstone — an independent oracle — before any pe_rva result is asserted.
  If that test fails, every expectation below is suspect.
* ``pefile`` (a third-party parser, and not the one under test for these fields)
  must accept the generated image, so the container is valid too.
* The ntdll.dll test derives ground truth by full disassembly of every ``.pdata``
  function and asserts pe_rva finds *at least* that set, plus that every record
  it returns re-decodes to the requested target. No hard-coded counts.
"""

from __future__ import annotations

import struct
import sys

import pytest

from fridapilot.tools.pe_rva import (
    PEImage,
    function_bounds,
    map_refs_to_functions,
    xrefs_to_rva,
)

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
TEXT_VSIZE = 0x400
RDATA_RVA = 0x2000
PDATA_RVA = 0x3000

TARGET_RVA = RDATA_RVA           # the "global" that every reference resolves to
PTR_RVA = RDATA_RVA + 0x10       # qword holding IMAGE_BASE + TARGET_RVA
CALL_TARGET_RVA = TEXT_RVA + 0x200
LEAF_RVA = TEXT_RVA + 0x300      # deliberately outside every .pdata entry

# (label, bytes before disp32, bytes after disp32). Each entry is a real
# encoding of a rip-relative access; the ones with a prefix ahead of the opcode
# are precisely what an opcode-whitelist scan cannot reach.
RIP_FORMS: list[tuple[str, bytes, bytes]] = [
    ("lea rax, [rip+d]",             b"\x48\x8D\x05",         b""),
    ("lock cmpxchg [rip+d], rcx",    b"\xF0\x48\x0F\xB1\x0D", b""),
    ("mov word [rip+d], ax",         b"\x66\x89\x05",         b""),
    ("movss xmm0, [rip+d]",          b"\xF3\x0F\x10\x05",     b""),
    ("mov byte [rip+d], 1",          b"\xC6\x05",             b"\x01"),
    ("cmp byte [rip+d], 0",          b"\x80\x3D",             b"\x00"),
    ("test byte [rip+d], al",        b"\x84\x05",             b""),
    ("movdqa xmm0, [rip+d]",         b"\x66\x0F\x6F\x05",     b""),
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


def _build_pe(func_end_rva: int, text: bytes) -> bytes:
    rdata = bytearray(0x200)
    rdata[0] = 0x01                                             # the target byte
    rdata[0x10:0x18] = struct.pack("<Q", IMAGE_BASE + TARGET_RVA)

    # .pdata: two RUNTIME_FUNCTIONs, VirtualSize = 24. The raw section is padded
    # to FileAlignment with 0xAA so that a parser walking SizeOfRawData (instead
    # of min(VirtualSize, SizeOfRawData)) produces bogus entries.
    pdata_entries = [(TEXT_RVA, func_end_rva, 0x4000),
                     (LEAF_RVA + 0x80, LEAF_RVA + 0x90, 0x4000)]
    pdata = bytearray()
    for begin, end, unwind in pdata_entries:
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


@pytest.fixture(scope="module")
def fixture_pe(tmp_path_factory) -> tuple[str, dict[str, int], int]:
    text, placed, func_end = _build_text()
    path = tmp_path_factory.mktemp("pe") / "synthetic.dll"
    path.write_bytes(_build_pe(func_end, bytes(text)))
    return str(path), placed, func_end


def _rip_target_of(path: str, rva: int) -> int | None:
    """Decode one instruction at ``rva`` with capstone and resolve its rip operand."""
    import capstone
    from capstone import x86 as cx86

    img = PEImage(path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    data = img.read_rva(rva, 16)
    insn = next(iter(md.disasm(data, img.image_base + rva)), None)
    if insn is None:
        return None
    for op in insn.operands:
        if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
            return insn.address + insn.size + op.mem.disp - img.image_base
    return None


# ── the fixture itself has to be right before anything else means something ──

def test_pefile_accepts_the_fixture(fixture_pe):
    path, _placed, _end = fixture_pe
    import pefile

    pe = pefile.PE(path, fast_load=True)
    assert pe.OPTIONAL_HEADER.ImageBase == IMAGE_BASE
    assert [s.Name.rstrip(b"\0").decode() for s in pe.sections] == [".text", ".rdata", ".pdata"]


def test_fixture_decodes_to_target(fixture_pe):
    """capstone, not pe_rva, confirms each hand-written encoding hits the target."""
    path, placed, _end = fixture_pe
    for label, _head, _tail in RIP_FORMS:
        assert _rip_target_of(path, placed[label]) == TARGET_RVA, label
    assert _rip_target_of(path, placed["leaf mov rax, [rip+d]"]) == TARGET_RVA


# ── .pdata parsing ──

def test_exception_table_ignores_file_alignment_padding(fixture_pe):
    path, _placed, func_end = fixture_pe
    table = PEImage(path).exception_table()
    assert table == [(TEXT_RVA, func_end, 0x4000),
                     (LEAF_RVA + 0x80, LEAF_RVA + 0x90, 0x4000)]


def test_function_at_bounds_are_half_open(fixture_pe):
    path, _placed, func_end = fixture_pe
    img = PEImage(path)
    assert img.function_at(TEXT_RVA)[:2] == (TEXT_RVA, func_end)
    assert img.function_at(func_end - 1)[:2] == (TEXT_RVA, func_end)
    assert img.function_at(func_end) is None
    assert img.function_at(LEAF_RVA) is None


def test_function_bounds_matches_function_at(fixture_pe):
    path, _placed, func_end = fixture_pe
    assert function_bounds(path, TEXT_RVA) == {
        "begin_rva": TEXT_RVA, "end_rva": func_end,
        "size": func_end - TEXT_RVA, "unwind_info_rva": 0x4000,
    }
    assert function_bounds(path, LEAF_RVA) is None


# ── rip cross-references ──

def test_all_prefixed_forms_are_found(fixture_pe):
    path, placed, _end = fixture_pe
    found = {r["from_rva"] for r in xrefs_to_rva(
        path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE, kinds=("rip",))}
    missing = {label: hex(placed[label]) for label, _h, _t in RIP_FORMS
               if placed[label] not in found}
    assert not missing, missing
    assert placed["leaf mov rax, [rip+d]"] in found


def test_every_returned_record_redecodes_to_the_target(fixture_pe):
    path, _placed, _end = fixture_pe
    records = xrefs_to_rva(path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE,
                           kinds=("rip",))
    assert records
    for rec in records:
        assert _rip_target_of(path, rec["from_rva"]) == TARGET_RVA, rec
        assert rec["size"] > 0, rec


def test_records_do_not_overlap(fixture_pe):
    path, _placed, _end = fixture_pe
    records = sorted(xrefs_to_rva(path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE,
                                  kinds=("rip",)), key=lambda r: r["from_rva"])
    for prev, cur in zip(records, records[1:]):
        assert cur["from_rva"] >= prev["from_rva"] + prev["size"], (prev, cur)


def test_strict_pdata_mode_drops_only_uncovered_code(fixture_pe):
    path, placed, _end = fixture_pe
    args = (path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE)
    loose = {r["from_rva"] for r in xrefs_to_rva(*args, kinds=("rip",))}
    strict = {r["from_rva"] for r in xrefs_to_rva(*args, kinds=("rip",), scan_gaps=False)}
    assert strict < loose
    assert loose - strict == {placed["leaf mov rax, [rip+d]"]}


def test_call_and_ptr_kinds(fixture_pe):
    path, placed, _end = fixture_pe
    calls = xrefs_to_rva(path, CALL_TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE,
                         kinds=("call",))
    assert [r["from_rva"] for r in calls] == [placed["call"]]

    ptrs = xrefs_to_rva(path, TARGET_RVA, RDATA_RVA, RDATA_RVA + 0x200, kinds=("ptr",))
    assert [r["from_rva"] for r in ptrs] == [PTR_RVA]


def test_map_refs_groups_by_function_and_reports_leaf_refs_as_orphans(fixture_pe):
    path, placed, func_end = fixture_pe
    res = map_refs_to_functions(path, {"g": TARGET_RVA}, TEXT_RVA, TEXT_RVA + TEXT_VSIZE)

    assert res["unreferenced"] == []
    assert [f["begin_rva"] for f in res["functions"]] == [TEXT_RVA]
    func = res["functions"][0]
    assert func["end_rva"] == func_end
    in_func = {r["from_rva"] for r in func["refs"]}
    assert in_func == {placed[label] for label, _h, _t in RIP_FORMS}
    assert [o["from_rva"] for o in res["orphans"]] == [placed["leaf mov rax, [rip+d]"]]

    # one pass over many targets must equal the sum of single-target scans
    single = {r["from_rva"] for r in xrefs_to_rva(
        path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE, kinds=("rip",))}
    assert in_func | {o["from_rva"] for o in res["orphans"]} == single


# ── real-image oracle: ground truth from full disassembly, no magic numbers ──

NTDLL = r"C:\Windows\System32\ntdll.dll"


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real x64 PE from Windows")
def test_ntdll_matches_full_disassembly_ground_truth():
    import capstone
    from capstone import x86 as cx86
    from collections import defaultdict
    from pathlib import Path

    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    img = PEImage(NTDLL)
    text = next((va, min(vs, rs)) for va, vs, _p, rs, name in img._sections
                if name == ".text")
    start, end = text[0], text[0] + text[1]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    truth: dict[int, set[int]] = defaultdict(set)
    for begin, fend, _unwind in img.exception_table()[:1200]:
        blob = img.read_rva(begin, fend - begin)
        if not blob:
            continue
        pos = begin
        while pos < fend:
            moved = False
            for insn in md.disasm(blob[pos - begin:], img.image_base + pos):
                moved = True
                pos = insn.address - img.image_base + insn.size
                for op in insn.operands:
                    if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                        tgt = insn.address + insn.size + op.mem.disp - img.image_base
                        truth[tgt].add(insn.address - img.image_base)
                        break
            if not moved:
                pos += 1

    # the busiest targets exercise the widest mix of encodings
    busiest = sorted(truth, key=lambda t: -len(truth[t]))[:3]
    assert busiest, "no rip references decoded - ground truth is broken"
    for target in busiest:
        got = {r["from_rva"] for r in xrefs_to_rva(NTDLL, target, start, end, kinds=("rip",))}
        assert truth[target] <= got, sorted(truth[target] - got)
        for from_rva in got:
            assert _rip_target_of(NTDLL, from_rva) == target, hex(from_rva)
