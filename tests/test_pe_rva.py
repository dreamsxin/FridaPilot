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

import logging
import struct
import sys
from pathlib import Path

import pytest

from fridapilot.tools.pe_rva import (
    PEImage,
    field_refs,
    find_inline_strings,
    find_string_rvas,
    function_bounds,
    function_xrefs,
    map_refs_to_functions,
    section_range,
    vtable_of_function,
    xrefs_to_rva,
)


from .synthetic_pe import (
    CALL_TARGET_RVA,
    CTOR_RVA,
    DISPATCH_RVA,
    IMAGE_BASE,
    INDIRECT_FN_RVA,
    INLINE_RVA,
    INLINE_TEXT,
    PTR_RVA,
    RDATA_RVA,
    RIP_FORMS,
    RTTI_CLASS_NAME,
    TARGET_RVA,
    TEXT_RVA,
    TEXT_VSIZE,
    LEAF_RVA,
    UNWIND_RVA,
    VTABLE_ENTRIES,
    VTABLE_RVA,
    VTABLE_SLOT_INDEX,
    VTABLE_SLOT_RVA,
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


# ── scan range resolution (the silent-partial-scan footgun) ─────────────────

def test_range_defaults_to_the_whole_text_section(fixture_pe):
    """Omitting the range must scan all of .text, not a guessed slice."""
    path, _placed, _end = fixture_pe
    explicit = {r["from_rva"] for r in xrefs_to_rva(
        path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE, kinds=("rip",))}
    defaulted = {r["from_rva"] for r in xrefs_to_rva(path, TARGET_RVA, kinds=("rip",))}
    assert defaulted == explicit


def test_section_argument_selects_the_section(fixture_pe):
    """`section=".rdata"` finds the pointer-table reference without any RVA maths."""
    path, _placed, _end = fixture_pe
    ptrs = xrefs_to_rva(path, TARGET_RVA, section=".rdata", kinds=("ptr",))
    assert [r["from_rva"] for r in ptrs] == [PTR_RVA]


def test_unknown_section_is_an_error_not_an_empty_result(fixture_pe):
    path, _placed, _end = fixture_pe
    with pytest.raises(ValueError, match="no section named"):
        xrefs_to_rva(path, TARGET_RVA, section=".nope")


def test_partial_range_is_logged_as_a_warning(fixture_pe, caplog):
    """The failure mode this guards: a third of a 240 MB .text read as 'no refs'."""
    path, _placed, _end = fixture_pe
    with caplog.at_level("WARNING", logger="fridapilot.tools.pe_rva"):
        xrefs_to_rva(path, TARGET_RVA, TEXT_RVA, TEXT_RVA + TEXT_VSIZE // 4,
                     kinds=("rip",))
    assert "covers 25.0% of .text" in caplog.text



def test_full_range_does_not_warn(fixture_pe, caplog):
    path, _placed, _end = fixture_pe
    with caplog.at_level("WARNING", logger="fridapilot.tools.pe_rva"):
        xrefs_to_rva(path, TARGET_RVA, kinds=("rip",))
    assert not caplog.records


def test_section_range_helper(fixture_pe):
    path, _placed, _end = fixture_pe
    assert section_range(path, ".text") == {
        "section": ".text", "start_rva": TEXT_RVA,
        "end_rva": TEXT_RVA + TEXT_VSIZE, "size": TEXT_VSIZE,
    }
    assert section_range(path, ".nope") is None


def test_map_refs_reports_what_it_scanned(fixture_pe):
    path, _placed, _end = fixture_pe
    full = map_refs_to_functions(path, {"g": TARGET_RVA})
    assert full["section"] == ".text"
    assert full["section_coverage"] == 1.0
    assert (full["scan_start_rva"], full["scan_end_rva"]) == (TEXT_RVA, TEXT_RVA + TEXT_VSIZE)

    partial = map_refs_to_functions(path, {"g": TARGET_RVA}, TEXT_RVA,
                                    TEXT_RVA + TEXT_VSIZE // 2)
    assert partial["section_coverage"] == 0.5
    # a label can be "unreferenced" purely because the scan stopped early
    assert partial["section_coverage"] < full["section_coverage"]


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


# ── inline (immediate-encoded) strings ──────────────────────────────────────
#
# These pin the blind spot that motivated find_inline_strings: a string the
# compiler builds in registers has no .rdata copy and its characters are split by
# the opcode bytes carrying them, so every contiguous-bytes locator misses it and
# xrefs_to_rva has no target RVA to look for. Asserting the *absence* first is the
# point - without it a passing find_inline_strings proves nothing new.


def test_inline_string_is_invisible_to_contiguous_search(fixture_pe):
    """The failure being fixed: nothing in the image holds the string in one piece."""
    path, _placed, _end = fixture_pe
    raw = INLINE_TEXT.encode("utf-8")
    data = PEImage(path)._data

    assert raw not in data, (
        f"fixture is wrong: {INLINE_TEXT!r} must never appear contiguously, "
        "otherwise this test cannot distinguish inline construction from a "
        "plain .rdata string")
    assert raw[:8] in data, "the first 8 bytes must be a contiguous imm64 operand"

    # ...and therefore the byte-level locators report nothing.
    assert all(r["rva"] is None for r in find_string_rvas(path, [INLINE_TEXT]))


def test_find_inline_strings_locates_the_construction_site(fixture_pe):
    path, _placed, _end = fixture_pe
    hits = find_inline_strings(path, INLINE_TEXT)

    assert hits, f"{INLINE_TEXT!r} is built at INLINE_RVA but was not found"
    best = hits[0]
    assert best["from_rva"] == INLINE_RVA
    # The anchor must be the operand of a real MOV r64, imm64, not a chance match.
    assert best["opcode"] == "movabs"
    # "AudioBuf" + "fer" = both groups accounted for.
    assert best["chunks_found"] == best["chunks_total"] == 2
    assert best["coverage"] == 1.0
    assert best["section"] == ".text"


def test_find_inline_strings_reports_no_pdata_function_for_a_leaf_site(fixture_pe):
    """INLINE_RVA sits outside every RUNTIME_FUNCTION, as leaf code does."""
    path, _placed, _end = fixture_pe
    best = find_inline_strings(path, INLINE_TEXT)[0]
    assert best["func_begin_rva"] is None
    assert function_bounds(path, INLINE_RVA) is None


def test_find_inline_strings_finds_nothing_for_absent_text(fixture_pe):
    path, _placed, _end = fixture_pe
    assert find_inline_strings(path, "NoSuchStringHere") == []


def test_find_inline_strings_rejects_text_too_short_to_identify(fixture_pe):
    """Under 4 bytes the anchor is not specific enough to mean anything."""
    path, _placed, _end = fixture_pe
    with pytest.raises(ValueError, match="too short"):
        find_inline_strings(path, "abc")


# ── indirectly dispatched functions ─────────────────────────────────────────
#
# The failure these pin: asking "who calls this function" about a callee that is only
# ever reached through a pointer table returns 0, and 0 looks exactly like dead code.
# This is the shape of every C++ virtual method, every IDL/binding-table entry that a
# script engine dispatches, and every import thunk.


def test_call_jmp_scan_cannot_see_an_indirect_only_callee(fixture_pe):
    """Scanning for direct branches is structurally incapable here — assert the 0."""
    path, _placed, _end = fixture_pe

    direct = xrefs_to_rva(path, INDIRECT_FN_RVA, kinds=("call", "jmp"), diagnose=False)
    assert direct == [], "fixture must have no direct branch to the indirect callee"

    # The address is not absent from the image, only from the code section: it sits in
    # the lone slot and in the real vtable.
    slots = xrefs_to_rva(path, INDIRECT_FN_RVA, section=".rdata", kinds=("ptr",))
    assert [s["from_rva"] for s in slots] == [
        VTABLE_SLOT_RVA, VTABLE_RVA + VTABLE_SLOT_INDEX * 8]


def test_empty_call_scan_on_a_code_target_explains_itself(fixture_pe, caplog):
    """0 hits must not be silent: it has to name the indirect-dispatch possibility."""
    path, _placed, _end = fixture_pe
    with caplog.at_level(logging.WARNING, logger="fridapilot.tools.pe_rva"):
        xrefs_to_rva(path, INDIRECT_FN_RVA, kinds=("call", "jmp"))
    assert "dispatched" in caplog.text
    assert "function_xrefs" in caplog.text


def test_function_xrefs_finds_the_pointer_slot_and_says_so(fixture_pe):
    path, _placed, _end = fixture_pe
    res = function_xrefs(path, INDIRECT_FN_RVA)

    assert res["target_is_code"] is True
    assert res["direct"] == []
    assert [r["from_rva"] for r in res["indirect"]] == [
        VTABLE_SLOT_RVA, VTABLE_RVA + VTABLE_SLOT_INDEX * 8]
    assert {r["section"] for r in res["indirect"]} == {".rdata"}
    # The verdict is the deliverable: it must distinguish this from "unreferenced".
    assert "dispatched indirectly" in res["verdict"]

    # Both section classes were actually swept, so the answer is not range-limited.
    swept = {s["section"] for s in res["scanned"]}
    assert {".text", ".rdata"} <= swept


def test_function_xrefs_follow_reaches_the_dispatch_site(fixture_pe):
    """One more hop: who loads the slot. That is the real caller."""
    path, _placed, _end = fixture_pe
    res = function_xrefs(path, INDIRECT_FN_RVA, follow=True)

    sites = {d["from_rva"] for d in res["dispatchers"]}
    assert DISPATCH_RVA in sites, sorted(hex(s) for s in sites)
    assert all(d["slot_rva"] == VTABLE_SLOT_RVA for d in res["dispatchers"])


def test_function_xrefs_finds_direct_callers_too(fixture_pe):
    """The normal case still works: CALL_TARGET_RVA is reached by a real E8."""
    path, _placed, _end = fixture_pe
    res = function_xrefs(path, CALL_TARGET_RVA)
    assert res["direct"], "the fixture has a direct call to CALL_TARGET_RVA"
    assert all(r["kind"] in ("call", "jmp") for r in res["direct"])
    assert "direct call/jmp site" in res["verdict"]


def test_function_xrefs_refuses_to_pretend_data_is_a_function(fixture_pe):
    path, _placed, _end = fixture_pe
    res = function_xrefs(path, TARGET_RVA)          # a .rdata byte, not code
    assert res["target_is_code"] is False
    assert "not executable" in res["verdict"]


def test_absolute_kind_scan_agrees_with_the_byte_walk_it_replaced(fixture_pe):
    """bytes.find must find exactly what the per-byte unpack loop found."""
    path, _placed, _end = fixture_pe
    img = PEImage(path)
    lo, hi = img.section_range(".rdata")
    blob = img.read_rva(lo, hi - lo)
    needle = struct.pack("<Q", IMAGE_BASE + TARGET_RVA)

    expected = {lo + i for i in range(len(blob) - 8)
                if struct.unpack_from("<Q", blob, i)[0] == IMAGE_BASE + TARGET_RVA}
    got = {r["from_rva"] for r in
           xrefs_to_rva(path, TARGET_RVA, section=".rdata", kinds=("ptr",))}
    assert got == expected
    assert needle in blob and PTR_RVA in got


# ── vtables ─────────────────────────────────────────────────────────────────
#
# The decidable direction. Going the other way - from a slot offset like [reg+0x1f8]
# to the class being dispatched - is not decidable statically, because the dispatch
# site carries no type information; measured, one slot offset matched 200+ sites in a
# Chromium-sized DLL. field_refs therefore warns instead of pretending the list is an
# answer.


def test_vtable_of_function_recovers_slot_index_and_extent(fixture_pe):
    path, _placed, _end = fixture_pe
    tables = vtable_of_function(path, INDIRECT_FN_RVA)

    real = [t for t in tables if t["entries"] == VTABLE_ENTRIES]
    assert len(real) == 1, [(hex(t["vtable_rva"]), t["entries"]) for t in tables]
    t = real[0]
    assert t["vtable_rva"] == VTABLE_RVA
    assert t["slot_index"] == VTABLE_SLOT_INDEX
    assert t["slot_rva"] == VTABLE_RVA + VTABLE_SLOT_INDEX * 8
    assert t["section"] == ".rdata"


def test_vtable_of_function_reads_the_msvc_rtti_class_name(fixture_pe):
    path, _placed, _end = fixture_pe
    t = [x for x in vtable_of_function(path, INDIRECT_FN_RVA)
         if x["vtable_rva"] == VTABLE_RVA][0]
    assert t["rtti"] is not None, "RTTI locator sits at vtable-8 in the fixture"
    assert t["rtti"]["mangled"] == RTTI_CLASS_NAME


def test_vtable_of_function_reports_the_constructor_that_installs_the_table(fixture_pe):
    """With RTTI stripped these refs are the only route back to the owning class."""
    path, _placed, _end = fixture_pe
    t = [x for x in vtable_of_function(path, INDIRECT_FN_RVA)
         if x["vtable_rva"] == VTABLE_RVA][0]
    assert CTOR_RVA in t["vtable_refs"], [hex(r) for r in t["vtable_refs"]]


def test_vtable_of_function_separates_a_lone_pointer_from_a_real_table(fixture_pe):
    """The same address also sits in an isolated slot; entries tells them apart."""
    path, _placed, _end = fixture_pe
    lone = [t for t in vtable_of_function(path, INDIRECT_FN_RVA)
            if t["slot_rva"] == VTABLE_SLOT_RVA]
    assert len(lone) == 1
    assert lone[0]["entries"] == 1
    assert lone[0]["rtti"] is None


def test_vtable_of_function_rejects_a_data_address(fixture_pe):
    path, _placed, _end = fixture_pe
    with pytest.raises(ValueError, match="not in an executable section"):
        vtable_of_function(path, TARGET_RVA)


def test_field_refs_warns_when_the_offset_cannot_discriminate(fixture_pe, caplog):
    """Hundreds of hits is not an answer; the tool has to say so."""
    path, _placed, _end = fixture_pe
    img = PEImage(path)
    lo, hi = img.section_range(".text")

    # 150 copies of `mov rax, [rcx+0x1f8]` — the shape that produced 200+ unrelated
    # hits on a real Chromium-sized DLL. Written to a scratch image so the shared
    # fixture is intact.
    insn = b"\x48\x8B\x81" + struct.pack("<i", 0x1F8)
    data = bytearray(Path(path).read_bytes())
    off = img.rva_to_off(lo + 0x100)
    data[off:off + len(insn) * 150] = insn * 150
    noisy = Path(path).with_name("noisy.dll")
    noisy.write_bytes(bytes(data))

    with caplog.at_level(logging.WARNING, logger="fridapilot.tools.pe_rva"):
        hits = field_refs(str(noisy), 0x1F8, lo, hi, kind="read")
    assert len(hits) > 100
    assert "not discriminating" in caplog.text
    assert "vtable_of_function" in caplog.text


# ── the displacement prefilter: it must save work without losing references ──

def test_a_function_without_a_candidate_displacement_is_never_decoded(fixture_pe):
    """Decoding is driven by the prefilter, not by the function list.

    A rip operand is always ModRM mod=00/rm=101 + disp32, so a function holding no
    displacement that resolves to the target cannot reference it. Decoding every
    function regardless is what made one full ``.text`` query on a 251 MB image take
    ≈11 minutes (measured: 2.7 s/MB of linear capstone decode) and read as a hang.
    """
    import capstone

    from fridapilot.tools.pe_rva import _iter_rip_refs

    path, _placed, _end = fixture_pe
    img = PEImage(path)
    lo, hi = img.section_range(".text")
    data = img.read_rva(lo, hi - lo)

    class CountingCs:
        """Passes disassembly through and records how often it was asked for."""

        def __init__(self, inner):
            self.inner, self.calls = inner, 0

        def disasm(self, *args, **kwargs):
            self.calls += 1
            return self.inner.disasm(*args, **kwargs)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    unused = RDATA_RVA + 0x300
    assert xrefs_to_rva(path, unused, kinds=("rip",), use_index=False, diagnose=False) == []
    absent = CountingCs(md)
    assert list(_iter_rip_refs(img, absent, data, lo, hi, lambda t: t == unused)) == []
    assert absent.calls == 0

    present = CountingCs(md)
    found = list(_iter_rip_refs(img, present, data, lo, hi, lambda t: t == TARGET_RVA))
    assert found, "the target that IS referenced must still be found"
    assert present.calls, "and the function referencing it must still be decoded"


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real x64 PE from Windows")
def test_ntdll_targets_referenced_exactly_once_survive_the_prefilter():
    """Recall for single-reference targets — what a prefilter breaks first.

    The busiest targets are reached through many encodings, so they stay findable even
    if one form is missed. A global touched once does not, which is why ground truth
    here is filtered down to exactly those.
    """
    import capstone
    from collections import defaultdict
    from pathlib import Path

    from capstone import x86 as cx86

    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    img = PEImage(NTDLL)
    start, end = img.section_range(".text")

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

    lonely = sorted(t for t in truth if len(truth[t]) == 1)
    assert len(lonely) > 20, "ground truth has too few single-reference targets to judge"
    for target in lonely[::len(lonely) // 12]:
        got = {r["from_rva"] for r in xrefs_to_rva(NTDLL, target, start, end,
                                                  kinds=("rip",), use_index=False)}
        assert truth[target] <= got, "lost 0x%x: %s" % (target, sorted(truth[target] - got))



