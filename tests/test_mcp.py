"""Tests for the MCP server surface.

The MCP tool list, the dispatch chain and the underlying functions are three
hand-maintained things that must agree. They have drifted before: the module did
not even import (it pulled a name the SDK does not export), and the APK tools
existed in the Python API while MCP clients could not see them.

What is asserted:
  * the module imports and every declared tool name is dispatched (and vice versa);
  * schemas are well-formed: required ⊆ properties, every property typed and
    described;
  * the file-based tools actually run end to end through ``_handle_tool`` against
    the synthetic PE / APK fixtures;
  * every path argument is filtered through the FRIDAPILOT_ALLOWED_DIRS whitelist.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from .synthetic_apk import DEX_INDICATOR, PACKAGE, dex_bytes, write_apk
from .synthetic_pe import TARGET_RVA, TEXT_RVA, TEXT_VSIZE, write_synthetic_pe

server = pytest.importorskip("fridapilot.mcp.server",
                             reason="the mcp SDK is an optional extra")


@pytest.fixture(scope="module")
def pe_path(tmp_path_factory) -> str:
    path, _placed, _end = write_synthetic_pe(
        tmp_path_factory.mktemp("mcp_pe") / "synthetic.dll")
    return path


@pytest.fixture(scope="module")
def apk_path(tmp_path_factory) -> str:
    return write_apk(tmp_path_factory.mktemp("mcp_apk"))


def _dispatched_names() -> set[str]:
    """Tool names compared against in _handle_tool, read from its source."""
    tree = ast.parse(inspect.getsource(server._handle_tool))
    names: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                and node.left.id == "name" and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)):
            names.add(node.comparators[0].value)
    return names


# ── declaration / dispatch parity ───────────────────────────────────────────

def test_declared_and_dispatched_tools_match():
    declared = {t.name for t in server.TOOLS}
    dispatched = _dispatched_names()
    assert declared - dispatched == set(), \
        "declared but never dispatched (calls would raise 'Unknown tool')"
    assert dispatched - declared == set(), \
        "dispatched but not declared (invisible to MCP clients)"


def test_tool_names_are_unique():
    names = [t.name for t in server.TOOLS]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("tool", server.TOOLS, ids=[t.name for t in server.TOOLS])
def test_schema_is_well_formed(tool):
    schema = tool.inputSchema
    assert schema["type"] == "object"
    properties = schema.get("properties", {})
    assert properties, f"{tool.name} declares no properties"
    for key, spec in properties.items():
        assert "type" in spec, f"{tool.name}.{key} has no type"
    for key in schema.get("required", []):
        assert key in properties, f"{tool.name} requires undeclared property {key}"
    assert tool.description and len(tool.description) > 20


def test_unknown_tool_is_rejected():
    with pytest.raises(ValueError, match="Unknown tool"):
        server._handle_tool("frida_does_not_exist", {})


# ── the static-analysis tools run end to end ────────────────────────────────

def test_pe_rva_tools_round_trip(pe_path):
    end = TEXT_RVA + TEXT_VSIZE

    bounds = server._handle_tool("binary_func_bounds",
                                 {"binary_path": pe_path, "rva": TEXT_RVA})
    assert bounds["begin_rva"] == TEXT_RVA and bounds["end_rva"] > TEXT_RVA

    refs = server._handle_tool("binary_xrefs_rva", {
        "binary_path": pe_path, "target_rva": TARGET_RVA,
        "scan_start_rva": TEXT_RVA, "scan_end_rva": end, "kinds": ["rip"]})
    assert refs and all(r["target_rva"] == TARGET_RVA for r in refs)

    strict = server._handle_tool("binary_xrefs_rva", {
        "binary_path": pe_path, "target_rva": TARGET_RVA,
        "scan_start_rva": TEXT_RVA, "scan_end_rva": end, "kinds": ["rip"],
        "pdata_only": True})
    assert {r["from_rva"] for r in strict} < {r["from_rva"] for r in refs}

    lines = server._handle_tool("binary_disasm_rva",
                                {"binary_path": pe_path, "rva": TEXT_RVA, "count": 3})
    assert lines["lines"] and lines["lines"][0]["rva"] == TEXT_RVA

    found = server._handle_tool("binary_find_string_rva",
                                {"binary_path": pe_path, "needles": ["MZ"]})
    assert found[0]["needle"] == "MZ"

    fields = server._handle_tool("binary_field_refs",
                                 {"binary_path": pe_path, "offset": 0x78})
    assert isinstance(fields, list)


def test_unpack_detect_runs_on_the_fixture(pe_path):
    info = server._handle_tool("unpack_detect", {"binary_path": pe_path})
    assert info["filepath"] == pe_path
    assert isinstance(info["packed"], bool)
    assert isinstance(info["section_entropy"], list)


def test_apk_tools_are_reachable(apk_path, tmp_path):
    info = server._handle_tool("apk_analyze", {"apk_path": apk_path})
    assert info["package_name"] == PACKAGE
    assert info["dex_count"] == 2

    hits = server._handle_tool("apk_protections", {"apk_path": apk_path})
    assert DEX_INDICATOR in {h["indicator"] for h in hits}

    dex = tmp_path / "classes.dex"
    dex.write_bytes(dex_bytes())
    parsed = server._handle_tool("apk_analyze_dex", {"dex_path": str(dex)})
    assert parsed["version"] == "035"


# ── path whitelist ──────────────────────────────────────────────────────────

def test_every_path_argument_is_whitelisted():
    """A tool taking a path must use a name the whitelist checks."""
    declared_path_args = set()
    for tool in server.TOOLS:
        for key in tool.inputSchema.get("properties", {}):
            if key.endswith("_path") or key == "filepath":
                declared_path_args.add(key)
    assert declared_path_args <= set(server.PATH_ARGUMENTS), \
        sorted(declared_path_args - set(server.PATH_ARGUMENTS))


@pytest.mark.parametrize("key", ["binary_path", "apk_path", "dex_path"])
def test_paths_outside_the_whitelist_are_rejected(monkeypatch, key, tmp_path):
    monkeypatch.setenv("FRIDAPILOT_ALLOWED_DIRS", str(tmp_path))
    with pytest.raises(ValueError, match="outside allowed directories"):
        server._check_path_allowed(str(Path(tmp_path).parent / "elsewhere" / "x.bin"))
    server._check_path_allowed(str(tmp_path / "inside.bin"))       # must not raise
    assert key in server.PATH_ARGUMENTS
