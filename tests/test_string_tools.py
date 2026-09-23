"""Tests for the string-extraction tools and named targets.

Both exist because of a real session: a Chromium DLL at a 90-character path, analysed by
abandoning the CLI for three hardcoded scripts because the shell line kept getting
truncated and no command could answer "what strings does this function reference" or
"dump this .rdata neighbourhood" with addresses attached.

Expectations come from the hand-assembled fixture and from re-reading the image
independently, never from recording what the code printed.
"""

from __future__ import annotations

import sys

import pytest

from fridapilot.tools.pe_rva import (
    MAX_FUNCTION_SPAN,
    PEImage,
    find_string_rvas,
    function_strings,
    strings_in_range,
)
from fridapilot.tools.targets import add_target, list_targets, remove_target, resolve_target
from tests import synthetic_pe as sp

NTDLL = r"C:\Windows\System32\ntdll.dll"


@pytest.fixture
def pe_image(tmp_path):
    path, placed, func_end = sp.write_synthetic_pe(tmp_path / "synth.exe")
    return path, placed, func_end


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the alias store at a temp file so the user's real one is untouched."""
    path = tmp_path / "targets.json"
    monkeypatch.setattr("fridapilot.tools.targets.TARGETS_PATH", path)
    return path


# ── function_strings ─────────────────────────────────────────


def test_a_range_with_no_end_takes_its_bounds_from_pdata(pe_image):
    """`0xRVA` alone must mean the function there, not an arbitrary window."""
    path, _placed, func_end = pe_image
    result = function_strings(path, [(sp.TEXT_RVA, None)])
    entry = result["ranges"][0]
    assert entry["begin_rva"] == sp.TEXT_RVA
    assert entry["end_rva"] == func_end
    assert entry["has_bounds"] is True
    assert entry["complete"] is True


def test_a_budget_that_cuts_the_range_short_says_so(pe_image):
    """The failure this replaces: `describe_function` reports the function's full size
    while having decoded at most 8192 bytes of it, so a large function looks examined.
    """
    path, _placed, func_end = pe_image
    span = func_end - sp.TEXT_RVA
    result = function_strings(path, [(sp.TEXT_RVA, func_end)], budget=8)
    entry = result["ranges"][0]
    assert entry["size"] == span
    assert entry["decoded_bytes"] == 8
    assert entry["complete"] is False
    assert any(f"0x{sp.TEXT_RVA:x}" in note and "decoded 8" in note
               for note in result["notes"])

    whole = function_strings(path, [(sp.TEXT_RVA, func_end)])
    assert whole["ranges"][0]["complete"] is True
    assert whole["ranges"][0]["decoded_bytes"] == span
    assert whole["notes"] == ["every range decoded end to end"]


def test_the_default_budget_is_the_whole_range_up_to_the_cap(pe_image):
    """A range larger than the safety cap is clamped, and the clamp is reported."""
    path, _placed, _end = pe_image
    huge = sp.TEXT_RVA + MAX_FUNCTION_SPAN + 0x1000
    entry = function_strings(path, [(sp.TEXT_RVA, huge)])["ranges"][0]
    assert entry["decoded_bytes"] == MAX_FUNCTION_SPAN
    assert entry["complete"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="needs a real x64 PE from Windows")
def test_every_reported_string_really_lives_at_its_target_rva():
    """The addresses are the point, so they are checked against the image itself.

    Text alone cannot be trusted: a rip displacement landing next to an unrelated literal
    (a Dawn/Skia shader, a V8 error table) reads exactly like a real hit, and only
    target_rva plus its section lets the reader throw it out. So every row must re-read.
    """
    from pathlib import Path

    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    img = PEImage(NTDLL)
    result = function_strings(NTDLL, [(0x1000, 0x4000)])
    rows = [r for row in result["ranges"] for r in row["strings"]]
    assert rows, "ntdll's first .text pages reference no strings at all?"
    for row in rows:
        if row["encoding"] == "inline":
            # Characters live in the opcode bytes; there is no address to re-read.
            assert row["target_rva"] is None
            continue
        raw = img.read_rva(row["target_rva"], 512) or b""
        expected = (row["text"].encode("ascii") if row["encoding"] == "ascii"
                    else row["text"].encode("utf-16-le"))
        assert raw.startswith(expected), f"0x{row['target_rva']:x} does not hold its text"
        assert row["section"] == img.section_of(row["target_rva"])
        assert row["kind"] in ("source_path", "symbol", "text")


# ── strings_in_range ─────────────────────────────────────────


def test_a_section_scan_finds_the_fixture_marker_with_its_rva(pe_image):
    path, _placed, _end = pe_image
    result = strings_in_range(path, section=".rdata")
    hit = next(r for r in result["strings"] if r["text"] == sp.MARKER_TEXT)
    assert hit["rva"] == sp.RDATA_RVA + 0x20
    assert hit["offset"] == PEImage(path).rva_to_off(hit["rva"])
    assert hit["terminated"] is True
    assert hit["encoding"] == "ascii"
    assert result["complete"] is True
    assert result["start_rva"] <= hit["rva"] < result["end_rva"]


def test_an_explicit_range_is_honoured_and_rows_stay_inside_it(pe_image):
    path, _placed, _end = pe_image
    lo = sp.RDATA_RVA + 0x20
    result = strings_in_range(path, start_rva=lo, end_rva=lo + 0x18)
    assert result["scanned_bytes"] == 0x18
    for row in result["strings"]:
        assert lo <= row["rva"] < lo + 0x18


def test_min_len_and_a_bad_section_name(pe_image):
    path, _placed, _end = pe_image
    long_only = strings_in_range(path, section=".rdata", min_len=17)
    assert all(row["length"] >= 17 for row in long_only["strings"])
    assert len(long_only["strings"]) < len(strings_in_range(path, section=".rdata")["strings"])

    with pytest.raises(ValueError, match="no section named"):
        strings_in_range(path, section=".nope")
    with pytest.raises(ValueError, match="pass a section name"):
        strings_in_range(path)


# ── find_string_rvas: the address code actually references ────


def test_a_substring_hit_reports_the_enclosing_string_s_own_rva(pe_image):
    """`string_rva` is what `map_refs_to_functions` needs; `rva` is not.

    Recovering it as ``rva - enclosing.index(needle)`` - the arithmetic this field
    replaces - is wrong as soon as the needle appears twice in the string, which is
    routine when matching a keyword against a source path.
    """
    path, _placed, _end = pe_image
    needle = sp.MARKER_TEXT[4:]                      # a suffix, so the hit is not the start
    row = next(r for r in find_string_rvas(path, [needle]) if r["rva"] is not None)
    assert row["whole"] is False
    assert row["enclosing"] == sp.MARKER_TEXT
    assert row["rva"] == sp.RDATA_RVA + 0x20 + 4
    assert row["string_rva"] == sp.RDATA_RVA + 0x20

    absent = find_string_rvas(path, ["no-such-string-anywhere"])[0]
    assert absent["rva"] is None and absent["string_rva"] is None


# ── named targets ────────────────────────────────────────────


def test_an_alias_resolves_to_the_stored_path_and_a_plain_path_is_untouched(pe_image, store):
    path, _placed, _end = pe_image
    stored = add_target("synth", path)
    assert list_targets() == {"synth": stored}
    assert resolve_target("@synth") == stored
    assert resolve_target(path) == path
    assert resolve_target("relative/plain.dll") == "relative/plain.dll"

    assert remove_target("synth") is True
    assert remove_target("synth") is False


def test_an_unknown_alias_is_an_error_not_a_filename(store, tmp_path, pe_image):
    """`@anty` reaching the filesystem reads as a broken path, not a missing alias."""
    path, _placed, _end = pe_image
    add_target("known", path)
    with pytest.raises(ValueError, match="unknown target alias"):
        resolve_target("@typo")
    with pytest.raises(ValueError, match="invalid target name"):
        add_target("bad/name", path)
    with pytest.raises(ValueError, match="not a file"):
        add_target("ghost", tmp_path / "missing.dll")


def test_the_tool_layer_accepts_an_alias_wherever_it_takes_a_path(pe_image, store):
    """Resolution lives in PEImage/ImageView, so SDK and MCP callers get it too."""
    from fridapilot.tools.disasm_view import ImageView

    path, _placed, _end = pe_image
    add_target("synth", path)
    assert PEImage("@synth").path == PEImage(path).path
    assert ImageView("@synth").path == ImageView(path).path
    assert strings_in_range("@synth", section=".rdata")["count"] > 0


def test_argv_expansion_only_touches_defined_aliases(pe_image, store):
    """The CLI rewrite must not eat an argument that merely starts with '@'."""
    from fridapilot.cli.main import expand_target_aliases

    path, _placed, _end = pe_image
    stored = add_target("synth", path)
    argv = ["binary", "func-strings", "@synth", "--grep", "@dolphin", "0x1000"]
    assert expand_target_aliases(argv) == [
        "binary", "func-strings", stored, "--grep", "@dolphin", "0x1000"]


# ── CLI wiring ───────────────────────────────────────────────


def test_cli_commands_are_registered_and_run(pe_image, store):
    import json

    from typer.testing import CliRunner

    from fridapilot.cli.main import app

    path, _placed, func_end = pe_image
    runner = CliRunner()
    for args in (["binary", "func-strings", path, f"0x{sp.TEXT_RVA:x}"],
                 ["binary", "func-strings", path,
                  f"0x{sp.TEXT_RVA:x}-0x{func_end:x}", "--kind", "text"],
                 ["binary", "strings-rva", path, "--section", ".rdata"],
                 ["binary", "strings-rva", path, "--start", f"0x{sp.RDATA_RVA:x}",
                  "--end", f"0x{sp.RDATA_RVA + 0x100:x}", "--contains", "Marker"],
                 ["target", "list"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0, (args, result.output)

    listed = runner.invoke(app, ["binary", "strings-rva", path, "--section", ".rdata",
                                 "--json"])
    assert listed.exit_code == 0
    assert any(row["text"] == sp.MARKER_TEXT
               for row in json.loads(listed.stdout)["strings"])

    for bad in (["binary", "func-strings", "no-such.exe", "0x1000"],
                ["binary", "strings-rva", path, "--section", ".nope"],
                ["binary", "func-strings", path, "zzz"],
                ["target", "remove", "never-defined"]):
        assert runner.invoke(app, bad).exit_code == 1
