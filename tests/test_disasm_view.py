"""Tests for the symbol/section-annotated disassembly view.

Expectations come from the hand-assembled fixtures (``synthetic_pe``,
``synthetic_elf``, ``synthetic_macho``) and from independent oracles - ``pefile``,
``pyelftools`` and ``capstone`` - never from running ``disasm_view`` and recording
what it printed. Several cases pin a specific way this kind of tool is wrong in
practice: decoding data as code, stopping at the first undecodable byte, and
presenting an implied function boundary as a measured one.
"""

from __future__ import annotations

import struct
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


# ── linear vs recursive ──────────────────────────────────────


def test_a_linear_sweep_decodes_data_that_control_flow_never_reaches(elf_image):
    """The cost of linear mode, stated as a test so recursive mode has a baseline.

    `jumpy` jumps over two data bytes. A linear pass cannot know that: it reports the
    first byte as undecodable, resyncs one byte later and produces instructions that
    exist nowhere in the program (`ff 31` decodes cleanly). This is the behaviour
    recursive mode exists to avoid - and it is still the right default, because it is
    the only mode that shows every byte.
    """
    result = disasm_listing(elf_image, function="jumpy", mode="linear")
    addresses = [ln["va"] for ln in result["lines"]]
    assert se.JUMPY_VA in addresses
    assert any(ln["kind"] == "bad" for ln in result["lines"])
    # An instruction starting inside the data, i.e. at an address that is not an
    # instruction boundary in the real program.
    assert any(se.JUMPY_DATA_VA < ln["va"] < se.JUMPY_RESUME_VA
               and ln["kind"] == "insn" for ln in result["lines"])


def test_recursive_mode_follows_the_jump_over_the_data(elf_image):
    """Only reachable instructions are decoded, and the skipped bytes are declared."""
    result = disasm_listing(elf_image, function="jumpy", mode="recursive")
    assert result["mode"] == "recursive"
    decoded = [ln for ln in result["lines"] if ln["kind"] == "insn"]
    assert [ln["va"] for ln in decoded] == [
        se.JUMPY_VA, se.JUMPY_RESUME_VA, se.JUMPY_RESUME_VA + 2]
    assert decoded[0]["mnemonic"] == "jmp"
    assert decoded[0]["target_va"] == se.JUMPY_RESUME_VA
    assert decoded[-1]["mnemonic"] == "ret"

    skipped = [ln for ln in result["lines"] if ln["kind"] == "unreached"]
    gap = next(ln for ln in skipped if ln["va"] == se.JUMPY_DATA_VA)
    assert gap["span"] == se.JUMPY_RESUME_VA - se.JUMPY_DATA_VA
    assert "not reached" in gap["text"]


def test_recursive_mode_accounts_for_every_byte_of_the_range(elf_image):
    """Structural invariant: decoded + unreached covers the request, with no overlap.

    Skipping bytes silently would make a function look shorter than it is, which is
    the failure mode that makes a recursive listing dangerous rather than merely
    incomplete.
    """
    view = ImageView(elf_image)
    text = view.find_section(".text")
    result = disasm_listing(elf_image, section=".text", mode="recursive", count=500,
                            view=view)
    cursor = text.va
    for ln in result["lines"]:
        assert ln["va"] == cursor, f"gap or overlap at 0x{cursor:x}"
        cursor += ln["span"] if ln["kind"] == "unreached" else len(ln["bytes_hex"]) // 2
    assert cursor == text.end_va


def test_recursive_mode_seeds_every_function_symbol_not_only_the_entry(elf_image):
    """A function nothing branches to is still listed, because symbols seed the walk.

    Reachability alone is not enough: a virtual method, a binding-table entry or a
    stored callback is only ever reached through a pointer, so an entry-only recursive
    pass omits all of them (the same blind spot `pe_rva.function_xrefs` exists for).
    `jumpy` is the fixture's case - no call or jmp anywhere targets it.
    """
    result = disasm_listing(elf_image, section=".text", mode="recursive", count=500)
    assert all(ln["target_va"] != se.JUMPY_VA for ln in result["lines"]), \
        "fixture changed: something now branches to jumpy, so seeding is not tested"
    reached = {ln["va"] for ln in result["lines"] if ln["kind"] == "insn"}
    assert se.JUMPY_VA in reached
    assert se.HELPER_VA in reached


def test_an_unknown_mode_is_reported(elf_image):
    assert "unknown mode" in disasm_listing(elf_image, section=".text",
                                            mode="descent")["error"]


# ── several sections, filtering, CSV ─────────────────────────


def test_several_sections_are_listed_in_the_order_requested(pe_image):
    """One call covers a comma-separated list, and keeps the caller's order.

    Requesting `.pdata,.rdata` lists .pdata first even though it sits at a higher
    address: the order is the question that was asked, not the address layout.
    """
    path, _placed, _end = pe_image
    forward = disasm_listing(path, section=".pdata,.rdata", count=60)
    assert {ln["section"] for ln in forward["lines"]} == {".pdata", ".rdata"}
    assert forward["lines"][0]["section"] == ".pdata"

    reverse = disasm_listing(path, section=".rdata,.pdata", count=60)
    assert reverse["lines"][0]["section"] == ".rdata"
    assert forward["scope"] == "section .pdata, .rdata"


def test_an_unknown_name_in_a_section_list_is_named_in_the_error(pe_image):
    path, _placed, _end = pe_image
    error = disasm_listing(path, section=".text,.nope")["error"]
    assert ".nope" in error and ".text" in error


def test_grep_keeps_matching_lines_and_reports_what_it_scanned(pe_image):
    """A filter that hides how much it looked at invites "there are no calls" errors."""
    path, _placed, _end = pe_image
    result = disasm_listing(path, section=".text", grep="^call", count=10)
    assert result["lines"]
    assert all(ln["mnemonic"] == "call" for ln in result["lines"])
    assert result["scanned"] > len(result["lines"])
    assert any("matched" in note for note in result["notes"])
    assert result["grep"] == "^call"


def test_grep_matches_the_instruction_not_the_function_column(pe_image):
    """The haystack is the instruction, its resolved target and a data row's text.

    Matching the function or section column too would make `--grep call` fire on a
    function named `recall`, and a filter whose hits cannot be predicted from the
    pattern is worse than no filter.
    """
    path, _placed, _end = pe_image
    named = disasm_listing(path, section=".text", count=20)
    assert named["lines"][0]["function"].startswith("sub_")

    result = disasm_listing(path, section=".text", grep="sub_1000", count=20)
    assert result["lines"] == []


def test_a_bad_grep_pattern_is_reported_not_raised(pe_image):
    path, _placed, _end = pe_image
    assert "bad --grep pattern" in disasm_listing(path, section=".text",
                                                  grep="(")["error"]


def test_csv_export_has_a_fixed_header_and_hex_addresses(pe_image, tmp_path):
    """A CSV whose columns move with the data is not something a script can read."""
    import csv

    from typer.testing import CliRunner

    from fridapilot.cli.disasm import CSV_COLUMNS
    from fridapilot.cli.main import app

    path, _placed, _end = pe_image
    out = tmp_path / "listing.csv"
    result = CliRunner().invoke(app, ["disasm", "view", path, "--section", ".text",
                                      "--count", "6", "--format", "csv",
                                      "--output", str(out)])
    assert result.exit_code == 0, result.output
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert len(rows) == 7                       # header plus six lines
    expected = disasm_listing(path, section=".text", count=6)["lines"]
    for row, line in zip(rows[1:], expected):
        record = dict(zip(CSV_COLUMNS, row))
        assert int(record["va"], 16) == line["va"]
        assert record["section"] == line["section"]
        assert record["mnemonic"] == line["mnemonic"]


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
    """Bad arguments and non-executable input give a message, never a traceback."""
    path, _placed, _end = pe_image
    assert "no section named" in disasm_listing(path, section=".nope")["error"]
    assert "no symbol named" in disasm_listing(path, function="nope")["error"]
    # A section list that is all separators used to reach `start + count * 16` with
    # start still None, i.e. a TypeError out of the tool layer.
    assert "no section name" in disasm_listing(path, section=",")["error"]
    assert "no section name" in disasm_listing(path, section="  ")["error"]

    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable at all")
    with pytest.raises(ValueError):
        ImageView(junk)


def test_a_damaged_image_raises_valueerror_not_the_parser_s_own_type(tmp_path):
    """Truncated or hand-edited files are normal input, so one error type covers them.

    pefile raises PEFormatError, pyelftools raises ELFError and hand-rolled struct
    parsing raises struct.error; none is a ValueError, so a CLI that catches ValueError
    printed a traceback for exactly the files a reverse engineer feeds it most.
    """
    cases = {
        "trunc.macho": struct.pack("<I", 0xFEEDFACF) + b"\x07\x00\x00\x01",
        "trunc-fat.macho": struct.pack(">I", 0xCAFEBABE) + b"\x00\x00\x00\x01",
        "trunc.exe": b"MZ" + b"\x00" * 40,
        "trunc.elf": b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 16,
    }
    for name, blob in cases.items():
        target = tmp_path / name
        target.write_bytes(blob)
        with pytest.raises(ValueError):
            ImageView(target)


def test_a_section_name_from_the_image_cannot_break_the_renderer():
    """Section names are attacker-controlled text; Rich reads `[` as a markup tag.

    Function names and instruction text already went through the escaping helper, so
    the section column was the one place a crafted name could raise MarkupError instead
    of printing.
    """
    import io

    from rich.console import Console

    from fridapilot.cli.disasm import _render_group, _render_table

    result = {
        "path": "x", "format": "pe", "arch": "x64", "bits": 64, "image_base": 0,
        "scope": "", "mode": "linear", "notes": [], "truncated": False,
        "lines": [{
            "va": 0x1000, "rva": 0x1000, "file_offset": 0x400,
            "section": ".te[/x]xt", "function": "f[/y]n", "func_offset": 0,
            "function_exact": True, "kind": "insn", "bytes_hex": "90",
            "mnemonic": "nop", "op_str": "", "text": "", "span": None,
            "target_va": None, "target": "", "source_file": None, "source_line": None,
        }],
    }
    for render in (_render_group, lambda out, res: _render_table(out, res, True, False)):
        out = Console(file=io.StringIO(), no_color=True, width=200)
        render(out, result)                      # must not raise MarkupError
        assert ".te[/x]xt" in out.file.getvalue()



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
                 ["disasm", "view", elf_image, "--section", ".text", "--mode", "recursive"],
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
