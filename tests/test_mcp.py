"""Tests for the MCP server surface.

The tool list and the dispatch chain are two things that must agree, and they have
drifted before: the module did not even import (it pulled a name the SDK does not
export), and the APK tools existed in the Python API while MCP clients could not
see them. Since the port to the mcp 2.x MCPServer API the schemas come from the
wrapper signatures, so schema drift is structurally impossible — what remains
worth asserting is the wrapper/dispatch parity and that the tools actually run.

What is asserted:
  * the module imports, and every registered tool is dispatched by _handle_tool
    (and every dispatched name is registered);
  * schemas are derived and well formed: required ⊆ properties, every property
    typed, description present;
  * the file-based tools run end to end, both through _dispatch and through
    MCPServer.call_tool, against the synthetic PE / APK fixtures;
  * failures come back as the documented envelope instead of an exception;
  * every argument that carries a path is covered by the whitelist.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
from pathlib import Path

import pytest

from .synthetic_apk import DEX_INDICATOR, PACKAGE, dex_bytes, write_apk
from .synthetic_pe import TARGET_RVA, TEXT_RVA, TEXT_VSIZE, write_synthetic_pe

server = pytest.importorskip("fridapilot.mcp.server",
                             reason="the mcp SDK is an optional extra")


def _await(value):
    return asyncio.run(value) if inspect.isawaitable(value) else value


def _tools() -> dict[str, object]:
    listed = server.mcp.list_tools()
    listed = _await(listed)
    return {t.name: t for t in listed}


def _call(name: str, arguments: dict) -> dict:
    """Call through the real MCP entry point and unwrap the JSON payload."""
    async def go():
        result = server.mcp.call_tool(name, arguments)
        return await result if inspect.isawaitable(result) else result

    result = asyncio.run(go())
    structured = getattr(result, "structured_content", None)
    if structured:
        return structured
    return json.loads(result.content[0].text)


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


# ── registration / dispatch parity ──────────────────────────────────────────

def test_registered_and_dispatched_tools_match():
    registered = set(_tools())
    dispatched = _dispatched_names()
    assert registered - dispatched == set(), \
        "registered but never dispatched (calls would return 'Unknown tool')"
    assert dispatched - registered == set(), \
        "dispatched but not registered (invisible to MCP clients)"


def test_tools_are_registered_at_all():
    assert len(_tools()) > 30


@pytest.mark.parametrize("name", sorted(_tools()))
def test_schema_is_well_formed(name):
    tool = _tools()[name]
    schema = tool.input_schema
    assert schema["type"] == "object"
    properties = schema.get("properties", {})
    for key, spec in properties.items():
        assert "type" in spec or "anyOf" in spec, f"{name}.{key} has no type"
    for key in schema.get("required", []):
        assert key in properties, f"{name} requires undeclared property {key}"
    assert tool.description and len(tool.description) > 20


def test_unknown_tool_is_rejected_by_the_dispatcher():
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


# ── the MCP entry point itself ──────────────────────────────────────────────

def test_call_tool_returns_the_success_envelope(apk_path):
    payload = _call("apk_analyze", {"apk_path": apk_path})
    assert payload["success"] is True
    assert payload["data"]["package_name"] == PACKAGE
    assert payload["duration"] >= 0


def test_call_tool_reports_failure_as_data_not_an_exception(tmp_path):
    payload = _call("unpack_detect", {"binary_path": str(tmp_path / "missing.dll")})
    assert payload["success"] is False
    assert payload["tool"] == "unpack_detect"
    assert "missing.dll" in payload["error"]


def test_schema_defaults_survive_the_round_trip(pe_path):
    """kinds/pdata_only have defaults, so a minimal call must still work."""
    payload = _call("binary_xrefs_rva", {
        "binary_path": pe_path, "target_rva": TARGET_RVA,
        "scan_start_rva": TEXT_RVA, "scan_end_rva": TEXT_RVA + TEXT_VSIZE})
    assert payload["success"] is True


# ── path whitelist ──────────────────────────────────────────────────────────

def test_every_path_argument_is_whitelisted():
    """A tool taking a path must use a name the whitelist checks."""
    declared = set()
    for tool in _tools().values():
        for key in tool.input_schema.get("properties", {}):
            if key.endswith("_path") or key == "filepath":
                declared.add(key)
    assert declared <= set(server.PATH_ARGUMENTS), \
        sorted(declared - set(server.PATH_ARGUMENTS))


def test_paths_outside_the_whitelist_are_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("FRIDAPILOT_ALLOWED_DIRS", str(tmp_path))
    with pytest.raises(ValueError, match="outside allowed directories"):
        server._check_path_allowed(str(Path(tmp_path).parent / "elsewhere" / "x.bin"))
    server._check_path_allowed(str(tmp_path / "inside.bin"))       # must not raise

    outside = Path(tmp_path).parent / "outside.apk"
    payload = server._dispatch("apk_analyze", {"apk_path": str(outside)})
    assert payload["success"] is False
    assert "outside allowed directories" in payload["error"]
