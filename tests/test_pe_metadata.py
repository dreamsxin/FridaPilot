"""Tests for pe_metadata.

The CodeView test is the load-bearing one: the symbol-server key is only useful if
the GUID is byte-ordered and formatted exactly the way the server expects, so the
record is built here by hand from the documented layout and the expected key is
written out literally. The ntdll case then confirms the same code against a real
Microsoft build (Windows only).
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from fridapilot.tools.pe_metadata import _parse_codeview, pe_metadata

from .synthetic_pe import write_synthetic_pe

NTDLL = r"C:\Windows\System32\ntdll.dll"


@pytest.fixture(scope="module")
def pe_path(tmp_path_factory) -> str:
    path, _placed, _end = write_synthetic_pe(
        tmp_path_factory.mktemp("meta_pe") / "synthetic.dll")
    return path


# ── CodeView / symbol-server key ────────────────────────────────────────────

def test_codeview_guid_byte_order_and_symbol_key():
    """RSDS: Data1/2/3 are little-endian, Data4 is 8 verbatim bytes, then age."""
    blob = (b"RSDS"
            + struct.pack("<IHH", 0x11223344, 0x5566, 0x7788)
            + bytes.fromhex("99AABBCCDDEEFF00")
            + struct.pack("<I", 0x1F)
            + b"D:\\build\\app.pdb\x00")
    cv = _parse_codeview(blob)

    assert cv["pdb_path"] == "D:\\build\\app.pdb"
    assert cv["pdb_guid"] == "112233445566778899AABBCCDDEEFF00"
    assert cv["pdb_age"] == 0x1F
    assert cv["symbol_server_key"] == "app.pdb/112233445566778899AABBCCDDEEFF001F/app.pdb"



def test_codeview_rejects_a_non_rsds_record():
    assert _parse_codeview(b"NB10" + b"\x00" * 32) == {}
    assert _parse_codeview(b"") == {}


# ── graceful behaviour on a minimal image ───────────────────────────────────

def test_minimal_pe_yields_empty_sections_not_errors(pe_path):
    meta = pe_metadata(pe_path)

    assert meta["machine"] == "0x8664"
    assert meta["is_dll"] is True                  # fixture sets IMAGE_FILE_DLL
    assert meta["is_dotnet"] is False
    assert meta["debug"]["entries"] == []          # no debug directory in the fixture
    assert "pdb_guid" not in meta["debug"]
    assert meta["version_info"] == {}
    assert meta["manifest"] == {}
    assert meta["coff_symbols"] == []
    assert meta["toolchain"]["guesses"] == ["unknown"]
    assert "rust" not in meta


def test_sections_and_entropy(pe_path):
    meta = pe_metadata(pe_path)
    names = [s["name"] for s in meta["sections"]]
    assert names == [".text", ".rdata", ".pdata"]
    text = meta["sections"][0]
    assert text["executable"] is True and text["writable"] is False
    assert 0.0 <= text["entropy"] <= 8.0


def test_security_flags_follow_the_fixture_header(pe_path):
    sec = pe_metadata(pe_path)["security"]
    # the fixture sets DllCharacteristics = 0x160
    # = HIGH_ENTROPY_VA (0x20) | DYNAMIC_BASE (0x40) | NX_COMPAT (0x100)
    assert sec["aslr"] is True
    assert sec["high_entropy_va"] is True
    assert sec["dep"] is True
    assert sec["no_seh"] is False          # 0x400 is not set
    assert sec["cfg"] is False
    assert sec["relocs_stripped"] is False



def test_toolchain_detects_rust_markers(tmp_path):
    """Rust panic metadata survives symbol stripping, so it is the reliable tell."""
    blob = tmp_path / "rusty.bin"
    blob.write_bytes(b"\x00" * 16
                     + b"core::panicking::panic_fmt"
                     + b"\x00" + rb"D:\work\launcher\src\main.rs"
                     + b"\x00" + rb"C:\Users\dev\.cargo\registry\src\index.crates.io-x\serde-1.0.203\src\lib.rs"
                     + b"\x00")
    from fridapilot.tools.pe_metadata import _rust_details, _toolchain

    tc = _toolchain(blob.read_bytes(), False)
    assert "rust" in tc["guesses"]

    rust = _rust_details(blob.read_bytes())
    assert any(p.endswith("main.rs") for p in rust["own_source_paths"])
    assert not any(".cargo" in p for p in rust["own_source_paths"])
    assert {"name": "serde", "version": "1.0.203"} in rust["crates"]


# ── real Microsoft build ────────────────────────────────────────────────────

@pytest.mark.skipif(sys.platform != "win32", reason="needs a real Windows PE")
def test_ntdll_metadata():
    if not Path(NTDLL).is_file():
        pytest.skip("ntdll.dll not available")

    meta = pe_metadata(NTDLL)
    dbg = meta["debug"]

    assert dbg["pdb_path"] == "ntdll.pdb"
    assert len(dbg["pdb_guid"]) == 32 and set(dbg["pdb_guid"]) <= set("0123456789ABCDEF")
    assert dbg["pdb_age"] >= 1
    assert dbg["symbol_server_key"] == \
        f"ntdll.pdb/{dbg['pdb_guid']}{dbg['pdb_age']:X}/ntdll.pdb"
    assert {e["type_name"] for e in dbg["entries"]} >= {"CODEVIEW"}

    assert meta["version_info"]["CompanyName"] == "Microsoft Corporation"
    assert meta["version_info"]["OriginalFilename"].lower() == "ntdll.dll"
    assert meta["security"]["aslr"] and meta["security"]["dep"]
    assert ".text" in [s["name"] for s in meta["sections"]]
    assert meta["resources"]
