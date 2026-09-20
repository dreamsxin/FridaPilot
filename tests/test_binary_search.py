"""Tests for the string / byte / text search layer in binary_analysis.

The fixture writes known text at known RVAs (tests/synthetic_pe.py), so every
expectation here comes from the fixture rather than from what the scanner happens
to return. The RVA and section on each hit are the point: a file offset cannot be
handed to the *-rva tools.
"""

from __future__ import annotations

import pytest

from fridapilot.tools.binary_analysis import find_strings, find_text, search_bytes

from .synthetic_pe import (
    GBK_RVA,
    GBK_TEXT,
    MARKER_RVA,
    MARKER_TEXT,
    RDATA_RVA,
    write_synthetic_pe,
)


@pytest.fixture(scope="module")
def pe_path(tmp_path_factory) -> str:
    path, _placed, _end = write_synthetic_pe(
        tmp_path_factory.mktemp("search_pe") / "synthetic.dll")
    return path


# ── strings carry RVA and section ───────────────────────────────────────────

def test_ascii_string_reports_rva_and_section(pe_path):
    hits = [s for s in find_strings(pe_path, min_len=8, encoding="ascii", limit=500)
            if s.value == MARKER_TEXT]
    assert hits, "marker string not found"
    assert hits[0].rva == MARKER_RVA
    assert hits[0].section == ".rdata"


def test_header_offsets_map_to_themselves(pe_path):
    """Below SizeOfHeaders the file offset *is* the RVA; the section is the headers."""
    hits = search_bytes(pe_path, "4d5a", limit=1)      # "MZ"
    assert hits[0].offset == 0
    assert hits[0].rva == 0
    assert hits[0].section == "(headers)"


def test_byte_search_reports_rva_and_section(pe_path):
    pattern = MARKER_TEXT.encode("ascii").hex()
    hits = search_bytes(pe_path, pattern, limit=5)
    assert [h.rva for h in hits] == [MARKER_RVA]
    assert hits[0].section == ".rdata"


def test_non_pe_input_leaves_rva_unset(tmp_path):
    blob = tmp_path / "plain.bin"
    blob.write_bytes(b"\x00" * 8 + MARKER_TEXT.encode("ascii") + b"\x00" * 8)
    hits = find_strings(blob, min_len=8, encoding="ascii")
    assert hits and hits[0].rva is None and hits[0].section == ""


# ── legacy code pages ───────────────────────────────────────────────────────

def test_ascii_scan_cannot_see_a_gbk_string(pe_path):
    """The ASCII extractor only accepts 0x20-0x7e, which is why --codepage exists."""
    values = {s.value for s in find_strings(pe_path, min_len=4, encoding="all", limit=500)}
    assert GBK_TEXT not in values


def test_codepage_scan_finds_it(pe_path):
    hits = [s for s in find_strings(pe_path, min_len=4, encoding="ascii",
                                    codepage="gbk", limit=500)
            if s.value == GBK_TEXT]
    assert hits, "GBK string not recovered"
    assert hits[0].rva == GBK_RVA
    assert hits[0].section == ".rdata"
    assert hits[0].encoding == "gbk"


def test_codepage_scan_rejects_random_high_bytes(tmp_path):
    """Nearly any high-byte pair decodes in GBK, so plausibility has to be checked."""
    blob = tmp_path / "junk.bin"
    blob.write_bytes(bytes(range(0x81, 0xFF)) * 4)
    assert find_strings(blob, min_len=4, encoding="ascii", codepage="gbk") == []


# ── one text, several encodings ─────────────────────────────────────────────

def test_find_text_locates_the_ascii_marker(pe_path):
    hits = find_text(pe_path, MARKER_TEXT, encodings=("ascii", "utf16le"))
    assert [h.rva for h in hits] == [MARKER_RVA]
    assert "ascii" in hits[0].encoding
    assert hits[0].section == ".rdata"


def test_find_text_locates_the_gbk_string_only_under_gbk(pe_path):
    hits = find_text(pe_path, GBK_TEXT, encodings=("ascii", "utf8", "utf16le", "gbk"))
    assert [h.rva for h in hits] == [GBK_RVA]
    assert hits[0].encoding == "gbk"          # utf8/utf16le encode to different bytes


def test_find_text_merges_codecs_that_produce_identical_bytes(pe_path):
    """ascii and gbk agree on ASCII text; the hit is reported once, labelled with both."""
    hits = find_text(pe_path, MARKER_TEXT, encodings=("ascii", "gbk", "latin1"))
    assert len(hits) == 1
    assert set(hits[0].encoding.split("/")) == {"ascii", "gbk", "latin1"}


def test_find_text_skips_codecs_that_cannot_represent_the_text(pe_path):
    """ascii cannot encode Chinese - that codec is skipped, not an error."""
    hits = find_text(pe_path, GBK_TEXT, encodings=("ascii",))
    assert hits == []


def test_find_text_reports_nothing_for_absent_text(pe_path):
    assert find_text(pe_path, "no such string here", encodings=("ascii", "utf16le")) == []


def test_utf16le_text_is_found_when_present(tmp_path):
    blob = tmp_path / "wide.bin"
    blob.write_bytes(b"\x00" * 4 + "Enabled".encode("utf-16-le"))
    hits = find_text(blob, "Enabled", encodings=("ascii", "utf16le"))
    assert [h.encoding for h in hits] == ["utf16le"]
    assert hits[0].offset == 4


def test_rdata_marker_offsets_are_distinct_from_rvas(pe_path):
    """Sanity check on the fixture itself: the two are not accidentally equal."""
    hit = find_text(pe_path, MARKER_TEXT, encodings=("ascii",))[0]
    assert hit.rva == MARKER_RVA
    assert hit.offset != hit.rva
    assert MARKER_RVA - RDATA_RVA == 0x20
