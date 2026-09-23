"""Tests for the symbol/section-annotated disassembly view.

Expectations come from the hand-assembled fixtures (``synthetic_pe``,
``synthetic_elf``, ``synthetic_macho``) and from independent oracles - ``pefile``,
``pyelftools`` and ``capstone`` - never from running ``disasm_view`` and recording
what it printed. Several cases pin a specific way this kind of tool is wrong in
practice: decoding data as code, stopping at the first undecodable byte, and
presenting an implied function boundary as a measured one.
"""

from __future__ import annotations

import sys

import capstone
import pytest

from fridapilot.tools.disasm_view import (
    ImageView,
    disasm_listing,
    sections_view,
    symbols_view,
)
from tests import synthetic_elf as se
from tests import synthetic_macho as sm
from tests import synthetic_pe as sp


@pytest.fixture
def pe_image(tmp_path):
    path, placed, func_end = sp.write_synthetic_pe(tmp_path / "synth.exe")
    return path, placed, func_end


@pytest.fixture
def elf_image(tmp_path):
    return se.write_synthetic_elf(tmp_path / "a.out")


@pytest.fixture
def macho_image(tmp_path):
    return sm.write_synthetic_macho(tmp_path / "a.macho")


# ── the view agrees with the image headers ───────────────────


def test_pe_sections_match_pefile(pe_image):
    """Section VA/size/flags come from the image, not from a hard-coded table."""
    import pefile

    path, _placed, _end = pe_image
    pe = pefile.PE(path, fast_load=True)
    expected = {
        s.Name.rstrip(b"\x00").decode(): (
            pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress,
            bool(s.Characteristics & 0x20000000),
        )
        for s in pe.sections
    }
    result = sections_view(path)
    got = {row["name"]: (row["va"], row["executable"]) for row in result["sections"]}
    assert got == expected
    assert result["image_base"] == pe.OPTIONAL_HEADER.ImageBase
    assert result["entry_va"] == (pe.OPTIONAL_HEADER.ImageBase
                                 + pe.OPTIONAL_HEADER.AddressOfEntryPoint)


def test_elf_symbols_match_pyelftools(elf_image):
    """Every STT_FUNC in the fixture's .symtab is listed with its recorded size."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    with open(elf_image, "rb") as f:
        elf = ELFFile(f)
        expected = {
            sym.name: (sym["st_value"], sym["st_size"])
            for s in elf.iter_sections() if isinstance(s, SymbolTableSection)
            for sym in s.iter_symbols()
            if sym.name and sym["st_info"]["type"] == "STT_FUNC"
        }
    got = {row["name"]: (row["va"], row["size"])
           for row in symbols_view(elf_image)["symbols"]}
    assert got == expected


def test_every_line_decodes_the_same_as_a_plain_capstone_pass(elf_image):
    """capstone as the oracle: the listing must not invent or shift instructions."""
    result = disasm_listing(elf_image, function="main")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    view = ImageView(elf_image)
    body = view.read(se.MAIN_VA, se.MAIN_SIZE)
    expected = [(i.address, i.mnemonic, i.op_str) for i in md.disasm(body, se.MAIN_VA)]
    got = [(ln["va"], ln["mnemonic"], ln["op_str"]) for ln in result["lines"]]
    assert got == expected


# ── address -> section -> function attribution ───────────────


def test_pe_function_attribution_uses_pdata_bounds(pe_image):
    """A PE without symbols still attributes code: .pdata records exact bounds."""
    path, _placed, func_end = pe_image
    result = disasm_listing(path, section=".text", count=400)
    text_lines = [ln for ln in result["lines"] if ln["section"] == ".text"]
    assert text_lines
    inside = [ln for ln in text_lines
              if sp.TEXT_RVA <= ln["va"] - sp.IMAGE_BASE < func_end]
    assert inside
    for ln in inside:
        assert ln["function"] == f"sub_{sp.TEXT_RVA:x}"
        # .pdata gives a real end, so the attribution is a measurement.
        assert ln["function_exact"] is True
        assert ln["func_offset"] == ln["va"] - sp.IMAGE_BASE - sp.TEXT_RVA


def test_a_sized_elf_symbol_gives_exact_bounds_and_a_gap_gives_none(elf_image):
    """An address between two sized functions belongs to neither.

    The tempting shortcut - attribute every address to the nearest preceding symbol -
    would label the padding after ``main`` as ``main`` and the unowned code at
    ``GAP_VA`` as ``helper``. Both are wrong, and a wrong function name is worse than
    no name because nothing downstream can tell it from a real one.
    """
    view = ImageView(elf_image)
    assert view.attribution(se.MAIN_VA).exact is True
    assert view.attribution(se.MAIN_VA + se.MAIN_SIZE - 1).name == "main"
    assert view.attribution(se.MAIN_VA + se.MAIN_SIZE) is None
    assert view.attribution(se.HELPER_VA).name == "helper"
    assert view.attribution(se.GAP_VA) is None

    gap = disasm_listing(elf_image, start=se.GAP_VA, count=1)
    assert gap["lines"][0]["function"] == ""
    assert gap["lines"][0]["section"] == ".text"


def test_macho_bounds_are_reported_as_implied_not_measured(macho_image):
    """A Mach-O nlist carries no size, so the end can only be inferred.

    The view is allowed to attribute the address - objdump does the same - but it must
    flag it: ``exact=False``. Presenting an inferred boundary as a measured one is how
    a listing ends up claiming a byte belongs to a function it does not.
    """
    view = ImageView(macho_image)
    attr = view.attribution(sm.MAIN_VA + 1)
    assert attr.name == "_main"
    assert attr.exact is False
    assert attr.size == sm.HELPER_VA - sm.MAIN_VA      # implied by the next symbol
    assert all(row["size"] == 0 for row in symbols_view(macho_image)["symbols"])


def test_call_target_is_resolved_to_the_callee_name(elf_image):
    """The whole point of a symbolised listing: `call 0x401010` says `helper`."""
    result = disasm_listing(elf_image, function="main")
    calls = [ln for ln in result["lines"] if ln["mnemonic"] == "call"]
    assert len(calls) == 1
    assert calls[0]["target_va"] == se.HELPER_VA
    assert "helper" in calls[0]["target"]


# ── source lines (DWARF) ─────────────────────────────────────


def test_dwarf_rows_are_what_the_fixture_encoded(elf_image):
    """pyelftools first as the oracle on the fixture, then the view against it."""
    from elftools.elf.elffile import ELFFile

    with open(elf_image, "rb") as f:
        dwarf = ELFFile(f).get_dwarf_info()
        seen = []
        for cu in dwarf.iter_CUs():
            prog = dwarf.line_program_for_CU(cu)
            files = prog.header["file_entry"]
            for entry in prog.get_entries():
                state = entry.state
                if state is None or state.end_sequence:
                    continue
                name = files[state.file - 1].name.decode()
                seen.append((state.address, name, state.line))
    assert seen == se.DWARF_ROWS, "the fixture's line program is not what it claims"

    view = ImageView(elf_image)
    assert view.has_debug_lines is True
    for address, name, line in se.DWARF_ROWS:
        assert view.source_at(address) == (name, line)

    result = disasm_listing(elf_image, function="main", source=True, view=view)
    for ln in result["lines"]:
        assert ln["source_file"] == se.DWARF_FILE
        assert ln["source_line"] in (10, 11)


def test_line_info_stops_where_the_sequence_ends(elf_image):
    """Past DW_LNE_end_sequence there is no line information, and none is invented.

    A DWARF line program is a set of sequences; the rows of one say nothing about
    addresses beyond its end. The obvious lookup - bisect for the last row at or below
    the address - hands every later address the final row's file and line, so `helper`
    and the unowned code at GAP_VA would be reported as living in the last line of
    `main`.
    """
    view = ImageView(elf_image)
    assert view.source_at(se.DWARF_END - 1) is not None
    assert view.source_at(se.DWARF_END) is None
    assert view.source_at(se.HELPER_VA) is None
    assert view.source_at(se.GAP_VA) is None

    result = disasm_listing(elf_image, function="helper", source=True, view=view)
    assert result["lines"]
    assert all(ln["source_file"] is None and ln["source_line"] is None
               for ln in result["lines"])


def test_source_lookup_is_opt_in(elf_image):
    """The keys exist either way; resolving them costs a DWARF parse, so it is asked for."""
    off = disasm_listing(elf_image, function="main")
    assert all(ln["source_file"] is None for ln in off["lines"])
    on = disasm_listing(elf_image, function="main", source=True)
    assert any(ln["source_file"] for ln in on["lines"])


def test_pe_has_no_in_image_line_table(pe_image):
    """Windows line numbers live in the PDB, so the image alone cannot answer."""
    path, _placed, _end = pe_image
    view = ImageView(path)
    assert view.has_debug_lines is False
    assert view.source_at(view.entry_va) is None
    result = disasm_listing(path, section=".text", count=3, source=True, view=view)
    assert all(ln["source_file"] is None for ln in result["lines"])


# ── the failures this module exists to avoid ─────────────────



def test_data_in_code_does_not_truncate_the_listing(pe_image):
    """An undecodable byte mid-function must not end the listing silently.

    A single ``md.disasm`` pass stops at the first byte it cannot decode and the
    generator just finishes, dropping everything after it - the fixture's
    ``DATA_IN_CODE`` sits immediately before the last rip form for exactly this
    reason. The listing has to resync and keep going, and report the gap.
    """
    path, placed, _end = pe_image
    hidden_va = sp.IMAGE_BASE + placed["movdqa xmm0, [rip+d]"]
    result = disasm_listing(path, section=".text", count=400)
    addresses = {ln["va"] for ln in result["lines"]}
    assert hidden_va in addresses, "instruction behind the decode gap was dropped"
    assert any(ln["kind"] == "bad" for ln in result["lines"]), \
        "the undecodable byte was skipped instead of being reported"


def test_a_data_section_is_never_disassembled(pe_image):
    """.rdata must come back as bytes and strings, not as invented instructions."""
    path, _placed, _end = pe_image
    result = disasm_listing(path, section=".rdata", count=80)
    assert result["lines"]
    for ln in result["lines"]:
        assert ln["kind"] in ("data", "string", "nodata")
        assert ln["mnemonic"] == ""
    strings = [ln["text"] for ln in result["lines"] if ln["kind"] == "string"]
    assert sp.MARKER_TEXT in strings


def test_macho_cstring_is_data_even_though_its_segment_is_executable(macho_image):
    """__TEXT is r-x and contains __cstring: segment protection is the wrong test.

    Deciding code-vs-data from VM_PROT_EXECUTE would disassemble every string literal
    in every Mach-O binary. The section attributes are what distinguish them.
    """
    view = ImageView(macho_image)
    text = view.find_section("__text")
    cstring = view.find_section("__cstring")
    assert text.executable is True
    assert cstring.perms == "r-x"          # the segment really is executable
    assert cstring.executable is False     # ...the section is not code
    lines = disasm_listing(macho_image, section="__cstring")["lines"]
    assert [ln["kind"] for ln in lines] == ["string"]
    assert lines[0]["text"] == sm.CSTRING_TEXT


def test_a_bss_range_reports_missing_data_instead_of_zeros(elf_image):
    """SHT_NOBITS has no file bytes; printing zeros would fabricate content."""
    view = ImageView(elf_image)
    bss = view.find_section(".bss")
    assert bss.file_offset == -1
    assert view.read(bss.va, 16) == b""
    lines = disasm_listing(elf_image, section=".bss")["lines"]
    assert [ln["kind"] for ln in lines] == ["nodata"]


# ── range handling ───────────────────────────────────────────


def test_lines_stay_inside_the_requested_scope(pe_image, elf_image):
    """Structural invariant: no line outside the section/function that was asked for."""
    path, _placed, _end = pe_image
    view = ImageView(path)
    rdata = view.find_section(".rdata")
    for ln in disasm_listing(path, section=".rdata", count=50)["lines"]:
        assert rdata.va <= ln["va"] < rdata.end_va
        assert ln["section"] == ".rdata"

    for ln in disasm_listing(elf_image, function="helper")["lines"]:
        assert se.HELPER_VA <= ln["va"] < se.HELPER_VA + se.HELPER_SIZE


def test_count_is_a_cap_and_truncation_is_reported(pe_image):
    path, _placed, _end = pe_image
    result = disasm_listing(path, section=".text", count=5)
    assert len(result["lines"]) == 5
    assert result["truncated"] is True
    assert any("stopped at" in note for note in result["notes"])


def test_a_range_spanning_sections_switches_rendering_and_skips_the_hole(pe_image):
    """A range from .text into .rdata is code, then nothing, then data.

    Sections are page-aligned in the address space, so the bytes between .text's end
    and .rdata's start belong to no section and have no file backing. Reading straight
    through would either decode alignment padding or emit rows for addresses that do
    not exist in the image - the hole has to be skipped, not rendered.
    """
    path, _placed, _end = pe_image
    view = ImageView(path)
    text = view.find_section(".text")
    rdata = view.find_section(".rdata")
    assert rdata.va > text.end_va, "fixture no longer has a hole between the sections"

    result = disasm_listing(path, start=text.end_va - 8, end=rdata.va + 0x30, count=40)
    kinds: dict[str, set[str]] = {}
    for ln in result["lines"]:
        assert ln["section"], "a line was emitted for an address in no section"
        kinds.setdefault(ln["section"], set()).add(ln["kind"])
    assert set(kinds) == {".text", ".rdata"}
    assert kinds[".text"] <= {"insn", "bad"}
    assert kinds[".rdata"] <= {"data", "string"}


def test_unknown_names_and_formats_are_reported_not_raised(pe_image, tmp_path):
    path, _placed, _end = pe_image
    assert "no section named" in disasm_listing(path, section=".nope")["error"]
    assert "no symbol named" in disasm_listing(path, function="nope")["error"]

    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable at all")
    with pytest.raises(ValueError):
        ImageView(junk)


def test_pe_lines_carry_both_the_rva_and_the_file_offset(pe_image):
    """RVA / VA / file offset are three different numbers; the row keeps them apart."""
    import pefile

    path, _placed, _end = pe_image
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.startswith(b".text"))
    for ln in disasm_listing(path, section=".text", count=10)["lines"]:
        assert ln["rva"] == ln["va"] - base
        assert ln["file_offset"] == text.PointerToRawData + (ln["rva"] - text.VirtualAddress)


# ── CLI wiring ───────────────────────────────────────────────


def test_cli_commands_are_registered_and_run(pe_image, elf_image):
    """`fp disasm` must be reachable from the root app, not just importable."""
    import json

    from typer.testing import CliRunner

    from fridapilot.cli.main import app

    path, _placed, _end = pe_image
    runner = CliRunner()
    for args in (["disasm", "view", path, "--section", ".text", "--count", "5"],
                 ["disasm", "view", path, "--format", "table", "--count", "5"],
                 ["disasm", "view", elf_image, "--function", "main", "--source"],
                 ["disasm", "view", elf_image, "--source", "--format", "table"],
                 ["disasm", "sections", path],
                 ["disasm", "symbols", path]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output)

    result = runner.invoke(app, ["disasm", "view", path, "--section", ".text",
                                 "--count", "3", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload["lines"]) == 3

    sourced = runner.invoke(app, ["disasm", "view", elf_image, "--function", "main",
                                  "--source", "--format", "json"])
    assert sourced.exit_code == 0
    assert json.loads(sourced.stdout)["lines"][0]["source_file"] == se.DWARF_FILE

    missing = runner.invoke(app, ["disasm", "sections", "no-such-file.exe"])
    assert missing.exit_code == 1


# ── a real image: export names + no entry point ──────────────

NTDLL = r"C:\Windows\System32\ntdll.dll"


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real x64 PE from Windows")
def test_ntdll_export_bounds_agree_with_pdata():
    """On a stripped DLL the name comes from the export table, the size from .pdata.

    Cross-checks the two sources against ``pe_rva.function_bounds``, the existing tool
    for the same question: if the listing's range disagreed with it, one of them would
    be attributing instructions to the wrong function.
    """
    from pathlib import Path

    from fridapilot.tools.pe_rva import function_bounds

    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    view = ImageView(NTDLL)
    sym = view.find_function("NtCreateFile")
    assert sym is not None and sym.source == "export"
    assert sym.size == 0, "an export table records no size; it must not claim one"

    bounds = function_bounds(NTDLL, sym.va - view.image_base)
    assert bounds is not None
    result = disasm_listing(NTDLL, function="NtCreateFile", view=view)
    assert result["start_va"] == view.image_base + bounds["begin_rva"]
    assert result["end_va"] == view.image_base + bounds["end_rva"]
    assert result["lines"]
    for ln in result["lines"]:
        assert ln["function"] == "NtCreateFile"
        assert ln["function_exact"] is True     # .pdata supplied the end
        assert ln["section"] == ".text"


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real x64 PE from Windows")
def test_an_image_without_an_entry_point_still_produces_a_default_listing():
    """AddressOfEntryPoint == 0 must not be reported as an entry point at ImageBase.

    ntdll.dll has no DllMain. Taking ImageBase+0 as the entry point points the default
    scope at the DOS header - an address inside no section - and the listing comes back
    empty, which reads as a broken image rather than a missing argument.
    """
    from pathlib import Path

    import pefile

    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    pe = pefile.PE(NTDLL, fast_load=True)
    view = ImageView(NTDLL)
    result = disasm_listing(NTDLL, count=4, view=view)
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
        assert view.entry_va is None
        assert "section" in result["scope"]
    else:
        assert view.entry_va == (pe.OPTIONAL_HEADER.ImageBase
                                 + pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    assert len(result["lines"]) == 4
    assert all(ln["section"] for ln in result["lines"])
