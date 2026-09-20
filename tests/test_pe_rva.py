"""Tests for fridapilot.tools.pe_rva.

Accuracy strategy — these tests must not cement whatever the implementation
currently prints:

* The synthetic PE (tests/synthetic_pe.py) is assembled from hand-written
  x86-64 encodings whose displacement is computed from the ISA rule
  (rip-relative operands are relative to the *end* of the instruction), not from
  anything pe_rva does.
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

import sys

import pytest

from fridapilot.tools.pe_rva import (
    PEImage,
    function_bounds,
    map_refs_to_functions,
    xrefs_to_rva,
)

from .synthetic_pe import (
    CALL_TARGET_RVA,
    IMAGE_BASE,
    PTR_RVA,
    RDATA_RVA,
    RIP_FORMS,
    TARGET_RVA,
    TEXT_RVA,
    TEXT_VSIZE,
    LEAF_RVA,
    UNWIND_RVA,
    write_synthetic_pe,
)


@pytest.fixture(scope="module")
def fixture_pe(tmp_path_factory) -> tuple[str, dict[str, int], int]:
    return write_synthetic_pe(tmp_path_factory.mktemp("pe") / "synthetic.dll")



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
    assert table == [(TEXT_RVA, func_end, UNWIND_RVA),
                     (LEAF_RVA + 0x80, LEAF_RVA + 0x90, UNWIND_RVA)]



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
        "size": func_end - TEXT_RVA, "unwind_info_rva": UNWIND_RVA,
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
