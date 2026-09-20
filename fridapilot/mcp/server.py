"""FridaPilot MCP Server - Expose Frida tools as MCP (Model Context Protocol) tools.

Allows Claude Desktop, Cursor, and other MCP-compatible agents to call
FridaPilot's Tool Layer directly.

Shape of this module: each tool is a thin typed wrapper decorated with
`@mcp.tool()`, so MCPServer derives the JSON schema from the annotations and the
description from the docstring — there is no hand-written schema to drift. The
wrappers all funnel into `_dispatch`, which enforces the path whitelist, writes
the audit entry and wraps the outcome; the actual work lives in `_handle_tool`.

Features:
- Path whitelist (FRIDAPILOT_ALLOWED_DIRS env var) on every path argument
- Audit logging of all tool calls
- Standardized response: {success, data | error, tool, duration}
- Pagination for enumeration tools
"""

from __future__ import annotations

import json
import logging
import os
import time as _time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from fridapilot import __version__
from fridapilot.models.schemas import DeviceType



logger = logging.getLogger("fridapilot.mcp")
_audit_logger = logging.getLogger("fridapilot.audit")


# ── Security: Path Whitelist ──────────────────────────────────

def _get_allowed_dirs() -> list[Path] | None:
    """Get allowed directories from FRIDAPILOT_ALLOWED_DIRS env var.

    Returns None if no whitelist is configured (all paths allowed).
    Format: semicolon-separated paths, e.g. "C:\\work;D:\\binaries"
    """
    env = os.environ.get("FRIDAPILOT_ALLOWED_DIRS", "")
    if not env.strip():
        return None
    return [Path(p.strip()).resolve() for p in env.split(";") if p.strip()]


def _check_path_allowed(filepath: str) -> None:
    """Validate that a file path is within the allowed directories.

    Raises ValueError if the path is outside the whitelist.
    """
    allowed = _get_allowed_dirs()
    if allowed is None:
        return  # No whitelist configured
    resolved = Path(filepath).resolve()
    for allowed_dir in allowed:
        try:
            resolved.relative_to(allowed_dir)
            return
        except ValueError:
            continue
    raise ValueError(
        f"Path '{filepath}' is outside allowed directories. "
        f"Set FRIDAPILOT_ALLOWED_DIRS to include this path."
    )


def _audit_log(tool_name: str, arguments: dict[str, Any], result: Any = None, error: str = "") -> None:
    """Log tool invocation for audit trail."""
    entry = {
        "tool": tool_name,
        "args": {k: (v if k != "script" else f"<script:{len(str(v))}chars>") for k, v in arguments.items()},
        "success": not error,
    }
    if error:
        entry["error"] = error[:200]
    _audit_logger.info(json.dumps(entry, default=str))

mcp = MCPServer(name="fridapilot", version=__version__)

# Argument names that carry a filesystem path; every one of them goes through the
# FRIDAPILOT_ALLOWED_DIRS whitelist before the tool runs.
PATH_ARGUMENTS = ("binary_path", "apk_path", "dex_path", "filepath", "output_path")


def _dispatch(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Validate paths, run the tool, wrap the outcome and write the audit entry.

    Every tool below is a thin typed wrapper around this: the MCP schema comes from
    the wrapper's annotations (no hand-written JSON), and the work happens in
    _handle_tool. Errors are returned as data rather than raised, because an
    exception escaping a tool surfaces to the client as an opaque
    UnexpectedToolError with the cause stripped.
    """
    start = _time.time()
    try:
        for key in PATH_ARGUMENTS:
            value = arguments.get(key)
            if isinstance(value, str) and value:
                _check_path_allowed(value)
        result = _handle_tool(name, arguments)
        _audit_log(name, arguments)
        return {"success": True, "data": result,
                "duration": round(_time.time() - start, 3)}
    except Exception as exc:
        # A missing file or a bad RVA is routine here; log it without a traceback
        # and keep the detail in the returned envelope.
        logger.warning("Tool %s failed: %s", name, exc)
        logger.debug("Tool %s traceback", name, exc_info=True)
        _audit_log(name, arguments, error=str(exc))
        return {"success": False, "error": str(exc), "tool": name,
                "duration": round(_time.time() - start, 3)}



# ── Tools ─────────────────────────────────────────────────────
# Signatures are the schema: MCPServer derives inputSchema from the annotations and
# the description from the docstring, so a tool cannot drift from its declaration.

@mcp.tool()
def frida_list_processes(
    device: str = 'local', host: str = '',
) -> dict[str, Any]:
    """List running processes on the target device."""
    return _dispatch("frida_list_processes", {"device": device, "host": host})


@mcp.tool()
def frida_attach(
    target: str, device: str = 'local', host: str = '',
) -> dict[str, Any]:
    """Attach to a running process by name or PID. Returns session info."""
    return _dispatch("frida_attach", {"target": target, "device": device, "host": host})


@mcp.tool()
def frida_spawn(
    package: str, device: str = 'local', host: str = '',
) -> dict[str, Any]:
    """Spawn an application and attach. Returns session info. Call frida_inject_script
    next."""
    return _dispatch("frida_spawn", {"package": package, "device": device, "host": host})


@mcp.tool()
def frida_detach(
    target: str, device: str = 'local',
) -> dict[str, Any]:
    """Detach from the current session and unload all scripts."""
    return _dispatch("frida_detach", {"target": target, "device": device})


@mcp.tool()
def frida_enumerate_modules(
    target: str, device: str = 'local', offset: int = 0, limit: int = 100,
) -> dict[str, Any]:
    """Enumerate loaded modules in a target process. Supports pagination."""
    return _dispatch("frida_enumerate_modules", {
        "target": target, "device": device, "offset": offset, "limit": limit,
    })


@mcp.tool()
def frida_enumerate_classes(
    target: str, filter_prefix: str = '', device: str = 'local', offset: int = 0,
    limit: int = 100,
) -> dict[str, Any]:
    """Enumerate Java/ObjC classes in a target process. Supports pagination."""
    return _dispatch("frida_enumerate_classes", {
        "target": target, "filter_prefix": filter_prefix, "device": device,
        "offset": offset, "limit": limit,
    })


@mcp.tool()
def frida_enumerate_methods(
    target: str, class_name: str, device: str = 'local', offset: int = 0, limit: int = 100,
) -> dict[str, Any]:
    """Enumerate methods of a class in a target process. Supports pagination."""
    return _dispatch("frida_enumerate_methods", {
        "target": target, "class_name": class_name, "device": device, "offset": offset,
        "limit": limit,
    })


@mcp.tool()
def frida_enumerate_exports(
    target: str, module_name: str, device: str = 'local', offset: int = 0, limit: int = 100,
) -> dict[str, Any]:
    """Enumerate exports of a module in a target process. Supports pagination."""
    return _dispatch("frida_enumerate_exports", {
        "target": target, "module_name": module_name, "device": device, "offset": offset,
        "limit": limit,
    })


@mcp.tool()
def frida_inject_script(
    target: str, script: str, timeout: int = 5, device: str = 'local',
) -> dict[str, Any]:
    """Inject a Frida script into a target process and collect messages."""
    return _dispatch("frida_inject_script", {
        "target": target, "script": script, "timeout": timeout, "device": device,
    })


@mcp.tool()
def frida_generate_script(
    template: str, class_name: str = '', method_name: str = '', module_name: str = '',
) -> dict[str, Any]:
    """Generate a Frida script from a built-in template."""
    return _dispatch("frida_generate_script", {
        "template": template, "class_name": class_name, "method_name": method_name,
        "module_name": module_name,
    })


@mcp.tool()
def frida_bypass_ssl(
    target: str, device: str = 'local',
) -> dict[str, Any]:
    """Inject SSL pinning bypass into a target process."""
    return _dispatch("frida_bypass_ssl", {"target": target, "device": device})


@mcp.tool()
def frida_crypto_scan(
    binary_path: str,
) -> dict[str, Any]:
    """Scan a PE/ELF binary for crypto indicators (S-Box, imports, protection level
    L0-L5)."""
    return _dispatch("frida_crypto_scan", {"binary_path": binary_path})


@mcp.tool()
def frida_crypto_hook_bcrypt(
    target: str, timeout: int = 10, device: str = 'local',
) -> dict[str, Any]:
    """Hook Windows BCrypt APIs in a target process to capture encryption keys at
    runtime."""
    return _dispatch("frida_crypto_hook_bcrypt", {
        "target": target, "timeout": timeout, "device": device,
    })


@mcp.tool()
def binary_analyze_pe(
    binary_path: str,
) -> dict[str, Any]:
    """Analyze a PE binary (.exe/.dll/.sys): headers, sections, imports, exports, debug
    info."""
    return _dispatch("binary_analyze_pe", {"binary_path": binary_path})


@mcp.tool()
def binary_analyze_elf(
    binary_path: str,
) -> dict[str, Any]:
    """Analyze an ELF binary: headers, sections, symbols, dynamic libraries."""
    return _dispatch("binary_analyze_elf", {"binary_path": binary_path})


@mcp.tool()
def binary_disassemble(
    binary_path: str, address: int, count: int = 20, arch: str = 'auto',
) -> dict[str, Any]:
    """Disassemble instructions at a given file offset. Auto-detects architecture."""
    return _dispatch("binary_disassemble", {
        "binary_path": binary_path, "address": address, "count": count, "arch": arch,
    })


@mcp.tool()
def binary_find_strings(
    binary_path: str, min_len: int = 4, encoding: str = 'all', limit: int = 200,
    filter: str = '',
) -> dict[str, Any]:
    """Extract strings from a binary (ASCII, UTF-16LE, UTF-8). Supports filtering."""
    return _dispatch("binary_find_strings", {
        "binary_path": binary_path, "min_len": min_len, "encoding": encoding,
        "limit": limit, "filter": filter,
    })


@mcp.tool()
def binary_search_bytes(
    binary_path: str, pattern: str, limit: int = 50,
) -> dict[str, Any]:
    """Search for a byte pattern in a binary. Supports ?? wildcards."""
    return _dispatch("binary_search_bytes", {
        "binary_path": binary_path, "pattern": pattern, "limit": limit,
    })


@mcp.tool()
def binary_xrefs(
    binary_path: str, target_address: int, start: int = 0, end: int = 0,
) -> dict[str, Any]:
    """Find cross-references (CALL/JMP) to a target address in a binary."""
    return _dispatch("binary_xrefs", {
        "binary_path": binary_path, "target_address": target_address, "start": start,
        "end": end,
    })


@mcp.tool()
def binary_analyze_go(
    binary_path: str,
) -> dict[str, Any]:
    """Analyze a Go-compiled binary: version, packages, functions, source paths."""
    return _dispatch("binary_analyze_go", {"binary_path": binary_path})


@mcp.tool()
def frida_hook_function(
    target: str, module: str, function: str, log_args: bool = True, log_retval: bool = True,
    log_backtrace: bool = False, timeout: int = 10, device: str = 'local',
) -> dict[str, Any]:
    """Hook a native function by name or address. Auto-generates Interceptor script with
    argument/return logging."""
    return _dispatch("frida_hook_function", {
        "target": target, "module": module, "function": function, "log_args": log_args,
        "log_retval": log_retval, "log_backtrace": log_backtrace, "timeout": timeout,
        "device": device,
    })


@mcp.tool()
def frida_hook_batch(
    target: str, hooks: list[Any], timeout: int = 10, device: str = 'local',
) -> dict[str, Any]:
    """Hook multiple functions at once. Returns aggregated messages from all hooks."""
    return _dispatch("frida_hook_batch", {
        "target": target, "hooks": hooks, "timeout": timeout, "device": device,
    })


@mcp.tool()
def frida_read_memory(
    target: str, address: str, size: int, device: str = 'local',
) -> dict[str, Any]:
    """Read bytes from a memory address in a target process."""
    return _dispatch("frida_read_memory", {
        "target": target, "address": address, "size": size, "device": device,
    })


@mcp.tool()
def frida_write_memory(
    target: str, address: str, data: str, device: str = 'local',
) -> dict[str, Any]:
    """Write bytes to a memory address in a target process. Use with caution."""
    return _dispatch("frida_write_memory", {
        "target": target, "address": address, "data": data, "device": device,
    })


@mcp.tool()
def frida_search_memory(
    target: str, pattern: str, module: str = '', device: str = 'local',
) -> dict[str, Any]:
    """Search for a byte pattern in a target process's memory."""
    return _dispatch("frida_search_memory", {
        "target": target, "pattern": pattern, "module": module, "device": device,
    })


@mcp.tool()
def frida_call_function(
    target: str, module: str, function: str, args: list[str] = [], device: str = 'local',
) -> dict[str, Any]:
    """Call a native function in the target process with specified arguments."""
    return _dispatch("frida_call_function", {
        "target": target, "module": module, "function": function, "args": args,
        "device": device,
    })


@mcp.tool()
def binary_metadata(
    binary_path: str,
) -> dict[str, Any]:
    """Metadata recon for a PE: PDB path + GUID/age + symbol-server key, version resource,
    manifest, Rich header, COFF symbols, toolchain guess, Rust panic source paths, section
    entropy, dynamic-API-resolution signal. Run this before any disassembly - a PDB GUID or a
    Rust source tree makes most of the later work unnecessary."""
    return _dispatch("binary_metadata", {"binary_path": binary_path})


@mcp.tool()
def binary_find_text(
    binary_path: str, text: str, encodings: list[str] | None = None, limit: int = 50,
) -> dict[str, Any]:
    """Locate one piece of text encoded several ways at once (ascii, utf8, utf16le, gbk,
    gb18030, big5, cp932, cp949, cp1251, cp1252, latin1) and report offset + RVA + section.
    Use when the encoding is unknown; the encodings that hit tell you how the binary stores
    text. Codecs that cannot represent the text are skipped."""
    return _dispatch("binary_find_text", {
        "binary_path": binary_path, "text": text, "encodings": encodings, "limit": limit,
    })


@mcp.tool()
def binary_find_string_rva(

    binary_path: str, needles: list[str], encoding: str = 'ascii',
) -> dict[str, Any]:
    """Locate exact strings in a PE and report their RVA and file offset. Start here:
    the RVA feeds binary_xrefs_rva."""
    return _dispatch("binary_find_string_rva", {
        "binary_path": binary_path, "needles": needles, "encoding": encoding,
    })


@mcp.tool()
def binary_inline_strings(
    binary_path: str, text: str, encoding: str = "utf8", section: str = ".text",
    window: int = 96, limit: int = 100,
) -> dict[str, Any]:
    """Find a string the code CONSTRUCTS in registers (movabs imm64) instead of pointing at.
    Use this when binary_find_string_rva finds nothing, or finds the string but
    binary_xrefs_rva reports no references: an inline string has no .rdata copy and its
    characters are split by the opcode bytes carrying them, so contiguous searches and xref
    scans both structurally miss it. Returns the carrying instruction RVA, how many 8-byte
    groups were confirmed, and the enclosing .pdata function."""
    return _dispatch("binary_inline_strings", {
        "binary_path": binary_path, "text": text, "encoding": encoding,
        "section": section, "window": window, "limit": limit,
    })


@mcp.tool()
def binary_index_build(
    binary_path: str, section: str = ".text", target_sections: list[str] | None = None,
) -> dict[str, Any]:
    """Scan a code section once and persist every rip reference into data sections, so
    later binary_xrefs_rva calls are database queries instead of minutes-long sweeps
    (ntdll .text: 3.9s to build, then ~0s per query vs 4.2s). Build this before asking
    about several targets in a large DLL. The index is keyed by file hash and records
    the range and target sections it covers; queries outside that fall back to a real
    scan, so it can never answer with a short list that looks complete."""
    return _dispatch("binary_index_build", {
        "binary_path": binary_path, "section": section,
        "target_sections": target_sections,
    })


@mcp.tool()
def binary_index_info(
    binary_path: str,
) -> dict[str, Any]:
    """What the stored rip index covers for this exact file content: section, scanned
    range, target sections, reference count, build time. Null when none exists (a
    patched binary has no index rather than a stale one)."""
    return _dispatch("binary_index_info", {"binary_path": binary_path})


@mcp.tool()
def binary_section_range(


    binary_path: str, section: str = ".text",
) -> dict[str, Any]:
    """Start/end RVA and size of a PE section. Call this instead of guessing scan
    bounds: a truncated range makes binary_xrefs_rva under-report, and the empty
    result is indistinguishable from 'nothing references this'."""
    return _dispatch("binary_section_range", {"binary_path": binary_path,
                                              "section": section})


@mcp.tool()
def binary_xrefs_rva(
    binary_path: str, target_rva: int, scan_start_rva: int | None = None,
    scan_end_rva: int | None = None, section: str = ".text",
    kinds: list[str] | None = None, pdata_only: bool = False,
) -> dict[str, Any]:
    """Cross-references to an RVA: rip-relative data refs plus direct call/jmp.
    The range defaults to the whole section (.text; use .rdata with kinds=["ptr"]),
    because scanning part of a section returns fewer references and looks exactly
    like having none. The result reports the range actually scanned and its coverage.
    Cost scales with the scanned bytes - narrow it with binary_func_bounds when you
    already know the region, and prefer one map-refs style pass for many targets."""
    return _dispatch("binary_xrefs_rva", {
        "binary_path": binary_path, "target_rva": target_rva,
        "scan_start_rva": scan_start_rva, "scan_end_rva": scan_end_rva,
        "section": section, "kinds": kinds, "pdata_only": pdata_only,
    })


@mcp.tool()
def binary_func_bounds(

    binary_path: str, rva: int,
) -> dict[str, Any]:
    """Exact function bounds for an RVA from the x64 .pdata table. Null when the RVA has
    no RUNTIME_FUNCTION (leaf function or 32-bit image)."""
    return _dispatch("binary_func_bounds", {"binary_path": binary_path, "rva": rva})


@mcp.tool()
def binary_disasm_rva(
    binary_path: str, rva: int, count: int = 40,
) -> dict[str, Any]:
    """RVA-aware disassembly: ImageBase-correct addressing with rip-relative and call
    targets resolved to RVAs."""
    return _dispatch("binary_disasm_rva", {
        "binary_path": binary_path, "rva": rva, "count": count,
    })


@mcp.tool()
def binary_field_refs(
    binary_path: str, offset: int, scan_start_rva: int | None = None,
    scan_end_rva: int | None = None, kind: str = 'both',
) -> dict[str, Any]:
    """Find reads/writes of a struct field at [reg+offset] - answers 'who touches
    this->field_ at +0xB0?'. Defaults to scanning .text."""
    return _dispatch("binary_field_refs", {
        "binary_path": binary_path, "offset": offset, "scan_start_rva": scan_start_rva,
        "scan_end_rva": scan_end_rva, "kind": kind,
    })


@mcp.tool()
def unpack_detect(
    binary_path: str,
) -> dict[str, Any]:
    """Detect whether a binary is packed and identify the packer
    (UPX/VMProtect/Themida/ASPack), with section entropy as evidence."""
    return _dispatch("unpack_detect", {"binary_path": binary_path})


@mcp.tool()
def unpack_auto(
    binary_path: str, output_path: str = '',
) -> dict[str, Any]:
    """Unpack pipeline: detect the packer, try UPX, report what is needed next. Non-UPX
    packers need a runtime memory dump instead."""
    return _dispatch("unpack_auto", {"binary_path": binary_path, "output_path": output_path})


@mcp.tool()
def apk_analyze(
    apk_path: str,
) -> dict[str, Any]:
    """Analyze an APK: manifest (package/version/SDK/permissions/components), native
    libs, dex count, signing info and protection indicators."""
    return _dispatch("apk_analyze", {"apk_path": apk_path})


@mcp.tool()
def apk_analyze_dex(
    dex_path: str,
) -> dict[str, Any]:
    """Analyze a DEX file: header, class/method/string counts, class names and a sample
    of strings."""
    return _dispatch("apk_analyze_dex", {"dex_path": dex_path})


@mcp.tool()
def apk_protections(
    apk_path: str,
) -> dict[str, Any]:
    """Root / SSL-pinning / Frida / emulator detection and packer indicators in an APK,
    each with the matching string as evidence. Run before spawning the app."""
    return _dispatch("apk_protections", {"apk_path": apk_path})



# ── Helpers ───────────────────────────────────────────────────

def _resolve_target(target: str) -> str | int:

    """Parse target as PID (int) or process name (str)."""
    try:
        return int(target)
    except ValueError:
        return target


def _paginate(items: list, arguments: dict[str, Any]) -> dict[str, Any]:
    """Apply offset/limit pagination to a list of items."""
    offset = arguments.get("offset", 0)
    limit = arguments.get("limit", 100)
    total = len(items)
    page = items[offset:offset + limit]
    return {"items": page, "total": total, "offset": offset, "limit": limit}


def _generate_hook_script(
    module: str,
    function: str,
    log_args: bool = True,
    log_retval: bool = True,
    log_backtrace: bool = False,
) -> str:
    """Generate a Frida Interceptor script for hooking a function."""
    # Determine if function is an address or name
    if function.startswith("0x"):
        resolve = f"ptr('{function}')"
    else:
        resolve = f"Module.findExportByName('{module}', '{function}')"

    parts = ["(function() {",
             f"  const addr = {resolve};",
             f"  if (!addr) {{ console.log('[FridaPilot] {module}!{function} not found'); return; }}",
             "  Interceptor.attach(addr, {"]

    on_enter = ["    onEnter(args) {"]
    on_enter.append(f"      const info = {{ type: 'hook', module: '{module}', function: '{function}' }};")
    if log_args:
        on_enter.append("      info.args = [args[0], args[1], args[2], args[3]].map(a => a ? a.toString() : 'null');")
    if log_backtrace:
        on_enter.append("      info.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).map(s => s.toString());")
    on_enter.append("      this._info = info;")
    on_enter.append("      send(info);")
    on_enter.append("    },")
    parts.extend(on_enter)

    if log_retval:
        parts.append("    onLeave(retval) {")
        parts.append(f"      send({{ type: 'hook_ret', module: '{module}', function: '{function}', retval: retval.toString() }});")
        parts.append("    }")
    parts.append("  });")
    parts.append(f"  console.log('[FridaPilot] Hooked {module}!{function}');")
    parts.append("})();")

    return "\n".join(parts)


def _handle_tool(name: str, arguments: dict[str, Any]) -> Any:

    """Route tool calls to the appropriate Tool Layer function."""
    device_type = DeviceType(arguments.get("device", "local"))
    host = arguments.get("host", "")

    if name == "frida_list_processes":
        from fridapilot.tools.recon import list_processes
        procs = list_processes(device_type, host)
        return [{"pid": p.pid, "name": p.name} for p in procs]

    if name == "frida_attach":
        from fridapilot.tools.injector import attach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        return {"pid": session.pid, "target": session.target, "device": session.device_type.value}

    if name == "frida_spawn":
        from fridapilot.tools.injector import spawn
        session = spawn(arguments["package"], device_type, host)
        return {"pid": session.pid, "target": session.target, "device": session.device_type.value, "note": "Process is suspended. Use frida_inject_script then resume."}

    if name == "frida_detach":
        from fridapilot.tools.injector import attach, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        detach(session)
        return {"status": "detached", "target": str(target)}

    if name == "frida_enumerate_modules":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_modules
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            modules = enumerate_modules(session.frida_session)
            items = [{"name": m.name, "base": m.base_address, "size": m.size, "path": m.path} for m in modules]
            return _paginate(items, arguments)
        finally:
            detach(session)

    if name == "frida_enumerate_classes":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_classes
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            classes = enumerate_classes(session.frida_session, arguments.get("filter_prefix", ""))
            items = [c.name for c in classes]
            return _paginate(items, arguments)
        finally:
            detach(session)

    if name == "frida_enumerate_methods":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_methods
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            methods = enumerate_methods(session.frida_session, arguments["class_name"])
            return _paginate(methods, arguments)
        finally:
            detach(session)

    if name == "frida_enumerate_exports":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_exports
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            exports = enumerate_exports(session.frida_session, arguments["module_name"])
            items = [{"name": e.name, "address": e.address, "type": e.type} for e in exports]
            return _paginate(items, arguments)
        finally:
            detach(session)

    if name == "frida_inject_script":
        import time
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            inject(session, arguments["script"])
            timeout = arguments.get("timeout", 5)
            time.sleep(timeout)
            msgs = [m.to_dict() for m in session.observer.messages]
            return {"messages": msgs, "count": len(msgs)}
        finally:
            detach(session)

    if name == "frida_generate_script":
        from fridapilot.tools.script_forge import get_template
        kwargs = {}
        for k in ("class_name", "method_name", "module_name"):
            if arguments.get(k):
                kwargs[k] = arguments[k]
        script = get_template(arguments["template"], **kwargs)
        return {"script": script}

    if name == "frida_bypass_ssl":
        import time
        from fridapilot.tools.bypass import get_ssl_bypass_script
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            inject(session, get_ssl_bypass_script())
            time.sleep(2)
            msgs = [m.to_dict() for m in session.observer.messages]
            return {"status": "injected", "messages": msgs}
        finally:
            detach(session)

    if name == "frida_crypto_scan":
        from fridapilot.tools.crypto_reverse import scan_binary
        result = scan_binary(arguments["binary_path"])
        return {
            "filepath": result.filepath,
            "is_pe": result.is_pe,
            "is_64bit": result.is_64bit,
            "is_dotnet": result.is_dotnet,
            "sbox_offsets": [f"0x{o:x}" for o in result.sbox_offsets],
            "crypto_imports": result.crypto_imports,
            "crypto_strings_count": len(result.crypto_strings),
            "hex_key_candidates": result.hex_key_candidates[:10],
            "protection_level": {
                "level": result.protection_level.level,
                "label": result.protection_level.label,
                "confidence": result.protection_level.confidence,
                "evidence": result.protection_level.evidence,
            } if result.protection_level else None,
        }

    if name == "frida_crypto_hook_bcrypt":
        import time
        from fridapilot.tools.crypto_reverse import get_bcrypt_hook_script
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            inject(session, get_bcrypt_hook_script())
            timeout = arguments.get("timeout", 10)
            time.sleep(timeout)
            msgs = [m.to_dict() for m in session.observer.messages]
            return {"messages": msgs, "count": len(msgs)}
        finally:
            detach(session)

    # ── Binary Analysis Tool Handlers ──

    if name == "binary_analyze_pe":
        from fridapilot.tools.binary_analysis import analyze_pe
        result = analyze_pe(arguments["binary_path"])
        return result.model_dump()

    if name == "binary_analyze_elf":
        from fridapilot.tools.binary_analysis import analyze_elf
        result = analyze_elf(arguments["binary_path"])
        return result.model_dump()

    if name == "binary_disassemble":
        from fridapilot.tools.binary_analysis import disassemble
        result = disassemble(
            arguments["binary_path"],
            arguments["address"],
            count=arguments.get("count", 20),
            arch=arguments.get("arch", "auto"),
        )
        return result.model_dump()

    if name == "binary_find_strings":
        from fridapilot.tools.binary_analysis import find_strings
        results = find_strings(
            arguments["binary_path"],
            min_len=arguments.get("min_len", 4),
            encoding=arguments.get("encoding", "all"),
            limit=arguments.get("limit", 200),
        )
        filter_str = arguments.get("filter", "")
        if filter_str:
            results = [s for s in results if filter_str.lower() in s.value.lower()]
        return [s.model_dump() for s in results]

    if name == "binary_search_bytes":
        from fridapilot.tools.binary_analysis import search_bytes
        results = search_bytes(
            arguments["binary_path"],
            arguments["pattern"],
            limit=arguments.get("limit", 50),
        )
        return [m.model_dump() for m in results]

    if name == "binary_xrefs":
        from fridapilot.tools.binary_analysis import xrefs_to
        search_range = None
        start = arguments.get("start", 0)
        end = arguments.get("end", 0)
        if start and end:
            search_range = (start, end)
        results = xrefs_to(arguments["binary_path"], arguments["target_address"], search_range)
        return [x.model_dump() for x in results]

    if name == "binary_analyze_go":
        from fridapilot.tools.binary_analysis import analyze_go_binary
        result = analyze_go_binary(arguments["binary_path"])
        return result.model_dump()

    # ── Advanced Frida Hook Handlers ──

    if name == "frida_hook_function":
        import time
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            script = _generate_hook_script(
                arguments["module"], arguments["function"],
                log_args=arguments.get("log_args", True),
                log_retval=arguments.get("log_retval", True),
                log_backtrace=arguments.get("log_backtrace", False),
            )
            inject(session, script)
            timeout = arguments.get("timeout", 10)
            time.sleep(timeout)
            msgs = [m.to_dict() for m in session.observer.messages]
            return {"messages": msgs, "count": len(msgs)}
        finally:
            detach(session)

    if name == "frida_hook_batch":
        import time
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            hooks = arguments["hooks"]
            script_parts = []
            for h in hooks:
                script_parts.append(_generate_hook_script(
                    h["module"], h["function"], log_args=True, log_retval=True,
                ))
            inject(session, "\n".join(script_parts))
            timeout = arguments.get("timeout", 10)
            time.sleep(timeout)
            msgs = [m.to_dict() for m in session.observer.messages]
            return {"messages": msgs, "count": len(msgs)}
        finally:
            detach(session)

    # ── Memory Tool Handlers ──

    if name == "frida_read_memory":
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            addr = arguments["address"]
            size = arguments["size"]
            script_src = f"""
                rpc.exports.readMem = () => {{
                    const addr = ptr('{addr}');
                    const buf = Memory.readByteArray(addr, {size});
                    return buf ? Array.from(new Uint8Array(buf)).map(b => ('0'+b.toString(16)).slice(-2)).join('') : '';
                }};
            """
            s = session.frida_session.create_script(script_src)
            s.load()
            hex_data = s.exports_sync.read_mem()
            s.unload()
            return {"address": addr, "size": size, "hex": hex_data}
        finally:
            detach(session)

    if name == "frida_write_memory":
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            addr = arguments["address"]
            hex_data = arguments["data"]
            byte_array = [int(hex_data[i:i+2], 16) for i in range(0, len(hex_data), 2)]
            script_src = f"""
                rpc.exports.writeMem = () => {{
                    const addr = ptr('{addr}');
                    const bytes = {byte_array};
                    Memory.protect(addr, {len(byte_array)}, 'rwx');
                    Memory.writeByteArray(addr, bytes);
                    return true;
                }};
            """
            s = session.frida_session.create_script(script_src)
            s.load()
            s.exports_sync.write_mem()
            s.unload()
            return {"address": addr, "bytes_written": len(byte_array)}
        finally:
            detach(session)

    if name == "frida_search_memory":
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            pattern = arguments["pattern"].replace(" ", "")
            module_name = arguments.get("module", "")
            if module_name:
                script_src = f"""
                    rpc.exports.searchMem = () => {{
                        const mod = Process.findModuleByName('{module_name}');
                        if (!mod) return [];
                        const matches = Memory.scanSync(mod.base, mod.size, '{pattern}');
                        return matches.map(m => ({{ address: m.address.toString(), size: m.size }})).slice(0, 100);
                    }};
                """
            else:
                script_src = f"""
                    rpc.exports.searchMem = () => {{
                        const results = [];
                        Process.enumerateRanges('r--').forEach(range => {{
                            try {{
                                const matches = Memory.scanSync(range.base, range.size, '{pattern}');
                                matches.forEach(m => results.push({{ address: m.address.toString(), size: m.size }}));
                            }} catch(e) {{}}
                        }});
                        return results.slice(0, 100);
                    }};
                """
            s = session.frida_session.create_script(script_src)
            s.load()
            matches = s.exports_sync.search_mem()
            s.unload()
            return {"matches": matches, "count": len(matches)}
        finally:
            detach(session)

    if name == "frida_call_function":
        from fridapilot.tools.injector import attach, inject, detach
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            mod = arguments["module"]
            func = arguments["function"]
            args = arguments.get("args", [])
            args_js = ", ".join(f"ptr('{a}')" if a.startswith("0x") else a for a in args)
            script_src = f"""
                rpc.exports.callFn = () => {{
                    const fn = Module.findExportByName('{mod}', '{func}');
                    if (!fn) return {{ error: 'Function not found' }};
                    const nativeFn = new NativeFunction(fn, 'pointer', [{', '.join(["'pointer'" for _ in args])}]);
                    const ret = nativeFn({args_js});
                    return {{ result: ret.toString(), function: '{func}' }};
                }};
            """
            s = session.frida_session.create_script(script_src)
            s.load()
            result = s.exports_sync.call_fn()
            s.unload()
            return result
        finally:
            detach(session)

    # ── RVA-aware PE analysis ──

    if name == "binary_metadata":
        from fridapilot.tools.pe_metadata import pe_metadata
        return pe_metadata(arguments["binary_path"])

    if name == "binary_find_text":
        from fridapilot.tools.binary_analysis import find_text
        encodings = arguments.get("encodings") or ["ascii", "utf8", "utf16le", "gbk"]
        return [m.model_dump() for m in find_text(
            arguments["binary_path"], arguments["text"],
            encodings=tuple(encodings), limit=int(arguments.get("limit", 50)))]

    if name == "binary_find_string_rva":

        from fridapilot.tools.pe_rva import find_string_rvas
        return find_string_rvas(arguments["binary_path"], list(arguments["needles"]),
                                arguments.get("encoding", "ascii"))

    if name == "binary_inline_strings":
        from fridapilot.tools.pe_rva import find_inline_strings
        return find_inline_strings(
            arguments["binary_path"], arguments["text"],
            encoding=arguments.get("encoding", "utf8"),
            section=arguments.get("section", ".text"),
            window=int(arguments.get("window", 96)),
            limit=int(arguments.get("limit", 100)))

    if name == "binary_index_build":
        from fridapilot.tools.rip_index import build_rip_index
        return build_rip_index(arguments["binary_path"],
                               section=arguments.get("section", ".text"),
                               target_sections=arguments.get("target_sections"))

    if name == "binary_index_info":
        from fridapilot.tools.rip_index import index_info
        return index_info(arguments["binary_path"])

    if name == "binary_section_range":

        from fridapilot.tools.pe_rva import section_range
        found = section_range(arguments["binary_path"], arguments.get("section", ".text"))
        if found is None:
            raise ValueError(f"no section named {arguments.get('section', '.text')!r}")
        return found

    if name == "binary_xrefs_rva":
        from fridapilot.tools.pe_rva import xrefs_to_rva
        start = arguments.get("scan_start_rva")
        end = arguments.get("scan_end_rva")
        return xrefs_to_rva(
            arguments["binary_path"],
            int(arguments["target_rva"]),
            int(start) if start is not None else None,
            int(end) if end is not None else None,
            kinds=tuple(arguments.get("kinds") or ("rip", "call", "jmp")),
            scan_gaps=not arguments.get("pdata_only", False),
            section="" if (start is not None and end is not None)
                    else arguments.get("section", ".text"),
        )


    if name == "binary_func_bounds":
        from fridapilot.tools.pe_rva import function_bounds
        return function_bounds(arguments["binary_path"], int(arguments["rva"]))

    if name == "binary_disasm_rva":
        from fridapilot.tools.pe_rva import disassemble_rva
        return disassemble_rva(arguments["binary_path"], int(arguments["rva"]),
                               count=int(arguments.get("count", 40)))

    if name == "binary_field_refs":
        from fridapilot.tools.pe_rva import field_refs
        start = arguments.get("scan_start_rva")
        end = arguments.get("scan_end_rva")
        return field_refs(
            arguments["binary_path"], int(arguments["offset"]),
            scan_start_rva=int(start) if start is not None else None,
            scan_end_rva=int(end) if end is not None else None,
            kind=arguments.get("kind", "both"),
        )

    # ── Packers ──

    if name == "unpack_detect":
        from fridapilot.tools.unpacker import detect_packer
        return asdict(detect_packer(arguments["binary_path"]))

    if name == "unpack_auto":
        from fridapilot.tools.unpacker import auto_unpack
        return asdict(auto_unpack(arguments["binary_path"],
                                  arguments.get("output_path", "")))

    # ── Android APK / DEX ──

    if name == "apk_analyze":
        from fridapilot.tools.apk_analysis import analyze_apk
        return asdict(analyze_apk(arguments["apk_path"]))

    if name == "apk_analyze_dex":
        from fridapilot.tools.apk_analysis import analyze_dex
        return asdict(analyze_dex(arguments["dex_path"]))

    if name == "apk_protections":
        from fridapilot.tools.apk_analysis import detect_protections
        return detect_protections(arguments["apk_path"])

    raise ValueError(f"Unknown tool: {name}")



# ── Entry point ───────────────────────────────────────────────

async def main() -> None:
    """Run the MCP server over stdio."""
    await mcp.run_stdio_async()




if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
