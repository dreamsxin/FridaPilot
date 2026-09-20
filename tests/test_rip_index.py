"""Tests for the persistent rip-reference index.

The property that matters is not speed but honesty: an index must return exactly
what a fresh scan returns, and must refuse any question it does not cover. A cache
that answers outside its coverage recreates the failure this area already produced
once — a partial scan read as "nothing references this".

Every test points the index at a temporary database; none of them touch
~/.fridapilot.
"""

from __future__ import annotations

import pytest

from fridapilot.tools import rip_index
from fridapilot.tools.pe_rva import xrefs_to_rva

from .synthetic_pe import RDATA_RVA, TARGET_RVA, TEXT_RVA, TEXT_VSIZE, write_synthetic_pe


@pytest.fixture
def pe_and_db(tmp_path, monkeypatch) -> tuple[str, str]:
    path, _placed, _end = write_synthetic_pe(tmp_path / "synthetic.dll")
    db = tmp_path / "rip_index.db"
    monkeypatch.setattr(rip_index, "DEFAULT_DB_PATH", db)
    return path, str(db)


def test_build_records_refs_and_targets(pe_and_db):
    path, db = pe_and_db
    stats = rip_index.build_rip_index(path, db_path=db)

    assert stats["refs"] >= 8            # the fixture plants 8 rip forms + a leaf one
    assert stats["targets"] >= 1
    assert stats["section"] == ".text"
    assert (stats["scan_start_rva"], stats["scan_end_rva"]) == (TEXT_RVA, TEXT_RVA + TEXT_VSIZE)
    assert any(name == ".rdata" for _lo, _hi, name in stats["target_ranges"])


def test_index_matches_a_fresh_scan(pe_and_db):
    """The whole point: identical results, different cost."""
    path, db = pe_and_db
    scanned = xrefs_to_rva(path, TARGET_RVA, kinds=("rip",), use_index=False)
    rip_index.build_rip_index(path, db_path=db)
    indexed = xrefs_to_rva(path, TARGET_RVA, kinds=("rip",), use_index=True)

    assert [r["from_rva"] for r in indexed] == [r["from_rva"] for r in scanned]
    assert [r["mnemonic"] for r in indexed] == [r["mnemonic"] for r in scanned]
    assert all(r["kind"] == "rip" for r in indexed)


def test_lookup_returns_none_without_an_index(pe_and_db):
    path, db = pe_and_db
    assert rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db) is None
    assert rip_index.index_info(path, db_path=db) is None


def test_lookup_refuses_a_target_outside_the_indexed_sections(pe_and_db):
    """Code-to-code references are deliberately not indexed, so ask the scanner."""
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)
    assert rip_index.lookup_rip_refs(path, TEXT_RVA, db_path=db) is None


def test_lookup_refuses_a_range_wider_than_the_index(pe_and_db):
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)

    inside = rip_index.lookup_rip_refs(path, TARGET_RVA, TEXT_RVA,
                                       TEXT_RVA + TEXT_VSIZE, db_path=db)
    assert inside is not None
    wider = rip_index.lookup_rip_refs(path, TARGET_RVA, TEXT_RVA,
                                      TEXT_RVA + TEXT_VSIZE + 0x1000, db_path=db)
    assert wider is None


def test_lookup_narrows_to_the_requested_range(pe_and_db):
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)

    everything = rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db)
    half = rip_index.lookup_rip_refs(path, TARGET_RVA, TEXT_RVA,
                                     TEXT_RVA + TEXT_VSIZE // 2, db_path=db)
    assert len(half) < len(everything)
    assert all(r["from_rva"] < TEXT_RVA + TEXT_VSIZE // 2 for r in half)


def test_index_is_keyed_by_content_so_a_patched_file_has_none(pe_and_db):
    """Path and mtime lie; the hash does not. A modified file gets no index at all."""
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)
    assert rip_index.index_info(path, db_path=db) is not None

    with open(path, "ab") as handle:            # append a byte: same path, new content
        handle.write(b"\x00")

    assert rip_index.index_info(path, db_path=db) is None
    assert rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db) is None
    # and the scanner still answers correctly
    assert xrefs_to_rva(path, TARGET_RVA, kinds=("rip",)) != []


def test_stale_index_version_is_ignored(pe_and_db, monkeypatch):
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)
    assert rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db) is not None

    monkeypatch.setattr(rip_index, "INDEX_VERSION", rip_index.INDEX_VERSION + 1)
    assert rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db) is None


def test_target_sections_filter(pe_and_db):
    path, db = pe_and_db
    stats = rip_index.build_rip_index(path, target_sections=[".rdata"], db_path=db)
    assert [name for _lo, _hi, name in stats["target_ranges"]] == [".rdata"]
    assert rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db) is not None

    with pytest.raises(ValueError, match="no such non-executable section"):
        rip_index.build_rip_index(path, target_sections=[".nope"], db_path=db)


def test_rebuild_replaces_instead_of_duplicating(pe_and_db):
    path, db = pe_and_db
    first = rip_index.build_rip_index(path, db_path=db)
    second = rip_index.build_rip_index(path, db_path=db)
    assert first["refs"] == second["refs"]
    assert len(rip_index.list_indexes(db_path=db)) == 1
    refs = rip_index.lookup_rip_refs(path, TARGET_RVA, db_path=db)
    assert len(refs) == len(xrefs_to_rva(path, TARGET_RVA, kinds=("rip",), use_index=False))


def test_drop_index(pe_and_db):
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)
    assert rip_index.drop_index(path, db_path=db) is True
    assert rip_index.drop_index(path, db_path=db) is False
    assert rip_index.index_info(path, db_path=db) is None


def test_unknown_section_is_an_error(pe_and_db):
    path, db = pe_and_db
    with pytest.raises(ValueError, match="no section named"):
        rip_index.build_rip_index(path, section=".nope", db_path=db)


def test_indexed_targets_are_data_rvas(pe_and_db):
    path, db = pe_and_db
    rip_index.build_rip_index(path, db_path=db)
    info = rip_index.index_info(path, db_path=db)
    assert all(lo >= RDATA_RVA or name != ".text"
               for lo, _hi, name in info["target_ranges"])
