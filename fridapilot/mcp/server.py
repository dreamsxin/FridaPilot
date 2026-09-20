"""FridaPilot MCP Server - Expose Frida tools as MCP (Model Context Protocol) tools.

Allows Claude Desktop, Cursor, and other MCP-compatible agents to call
FridaPilot's Tool Layer directly.

Production-grade features:
- Path whitelist (FRIDAPILOT_ALLOWED_DIRS env var)
- Audit logging of all tool calls
- Standardized error response format
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


from mcp.server import Server
from mcp.types import Tool, TextContent


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

server = Server("fridapilot")


# ── Tool definitions ──────────────────────────────────────────

TOOLS = [
    Tool(
        name="frida_list_processes",
        description="List running processes on the target device.",
        inputSchema={
            "type": "object",
            "properties": {
                "device": {"type": "string", "enum": ["local", "usb", "remote"], "default": "local"},
                "host": {"type": "string", "default": ""},
            },
        },
    ),
    Tool(
        name="frida_attach",
        description="Attach to a running process by name or PID. Returns session info.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "device": {"type": "string", "default": "local"},
                "host": {"type": "string", "default": ""},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_spawn",
        description="Spawn an application and attach. Returns session info. Call frida_inject_script next.",
        inputSchema={
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name or executable path"},
                "device": {"type": "string", "default": "local"},
                "host": {"type": "string", "default": ""},
            },
            "required": ["package"],
        },
    ),
    Tool(
        name="frida_detach",
        description="Detach from the current session and unload all scripts.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID of active session"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_enumerate_modules",
        description="Enumerate loaded modules in a target process. Supports pagination.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "device": {"type": "string", "default": "local"},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
                "limit": {"type": "integer", "default": 100, "description": "Max results per page"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_enumerate_classes",
        description="Enumerate Java/ObjC classes in a target process. Supports pagination.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "filter_prefix": {"type": "string", "default": "", "description": "Filter by class name prefix"},
                "device": {"type": "string", "default": "local"},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
                "limit": {"type": "integer", "default": 100, "description": "Max results per page"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_enumerate_methods",
        description="Enumerate methods of a class in a target process. Supports pagination.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "class_name": {"type": "string", "description": "Fully qualified class name"},
                "device": {"type": "string", "default": "local"},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
                "limit": {"type": "integer", "default": 100, "description": "Max results per page"},
            },
            "required": ["target", "class_name"],
        },
    ),
    Tool(
        name="frida_enumerate_exports",
        description="Enumerate exports of a module in a target process. Supports pagination.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "module_name": {"type": "string", "description": "Module name"},
                "device": {"type": "string", "default": "local"},
                "offset": {"type": "integer", "default": 0, "description": "Pagination offset"},
                "limit": {"type": "integer", "default": 100, "description": "Max results per page"},
            },
            "required": ["target", "module_name"],
        },
    ),
    Tool(
        name="frida_inject_script",
        description="Inject a Frida script into a target process and collect messages.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "script": {"type": "string", "description": "Frida JavaScript source code"},
                "timeout": {"type": "integer", "default": 5, "description": "Seconds to collect messages"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "script"],
        },
    ),
    Tool(
        name="frida_generate_script",
        description="Generate a Frida script from a built-in template.",
        inputSchema={
            "type": "object",
            "properties": {
                "template": {"type": "string", "description": "Template name: java-hook, objc-hook, native-hook, ssl-bypass, crypto-monitor, electron-ipc, node-hook"},
                "class_name": {"type": "string", "default": ""},
                "method_name": {"type": "string", "default": ""},
                "module_name": {"type": "string", "default": ""},
            },
            "required": ["template"],
        },
    ),
    Tool(
        name="frida_bypass_ssl",
        description="Inject SSL pinning bypass into a target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_crypto_scan",
        description="Scan a PE/ELF binary for crypto indicators (S-Box, imports, protection level L0-L5).",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the binary file"},
            },
            "required": ["binary_path"],
        },
    ),
    Tool(
        name="frida_crypto_hook_bcrypt",
        description="Hook Windows BCrypt APIs in a target process to capture encryption keys at runtime.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "timeout": {"type": "integer", "default": 10, "description": "Seconds to monitor"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target"],
        },
    ),

    # ── Binary Analysis Tools (static, no running process needed) ──

    Tool(
        name="binary_analyze_pe",
        description="Analyze a PE binary (.exe/.dll/.sys): headers, sections, imports, exports, debug info.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to PE file"},
            },
            "required": ["binary_path"],
        },
    ),
    Tool(
        name="binary_analyze_elf",
        description="Analyze an ELF binary: headers, sections, symbols, dynamic libraries.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to ELF file"},
            },
            "required": ["binary_path"],
        },
    ),
    Tool(
        name="binary_disassemble",
        description="Disassemble instructions at a given file offset. Auto-detects architecture.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file"},
                "address": {"type": "integer", "description": "File offset to disassemble from"},
                "count": {"type": "integer", "default": 20, "description": "Number of instructions"},
                "arch": {"type": "string", "default": "auto", "description": "Architecture: auto, x86, x64, arm, arm64"},
            },
            "required": ["binary_path", "address"],
        },
    ),
    Tool(
        name="binary_find_strings",
        description="Extract strings from a binary (ASCII, UTF-16LE, UTF-8). Supports filtering.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file"},
                "min_len": {"type": "integer", "default": 4, "description": "Minimum string length"},
                "encoding": {"type": "string", "default": "all", "description": "Encoding: ascii, utf16le, utf8, all"},
                "limit": {"type": "integer", "default": 200, "description": "Max strings to return"},
                "filter": {"type": "string", "default": "", "description": "Filter strings containing this text"},
            },
            "required": ["binary_path"],
        },
    ),
    Tool(
        name="binary_search_bytes",
        description="Search for a byte pattern in a binary. Supports ?? wildcards.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file"},
                "pattern": {"type": "string", "description": "Hex pattern, e.g. '4883ec20' or '48 8b ?? 48'"},
                "limit": {"type": "integer", "default": 50, "description": "Max matches"},
            },
            "required": ["binary_path", "pattern"],
        },
    ),
    Tool(
        name="binary_xrefs",
        description="Find cross-references (CALL/JMP) to a target address in a binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to binary file"},
                "target_address": {"type": "integer", "description": "Target address (file offset)"},
                "start": {"type": "integer", "default": 0, "description": "Search range start"},
                "end": {"type": "integer", "default": 0, "description": "Search range end (0 = entire file)"},
            },
            "required": ["binary_path", "target_address"],
        },
    ),
    Tool(
        name="binary_analyze_go",
        description="Analyze a Go-compiled binary: version, packages, functions, source paths.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to Go binary"},
            },
            "required": ["binary_path"],
        },
    ),

    # ── Advanced Frida Hook Tools ──

    Tool(
        name="frida_hook_function",
        description="Hook a native function by name or address. Auto-generates Interceptor script with argument/return logging.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "module": {"type": "string", "description": "Module name (e.g. 'bcrypt.dll')"},
                "function": {"type": "string", "description": "Export name or hex address"},
                "log_args": {"type": "boolean", "default": True, "description": "Log function arguments"},
                "log_retval": {"type": "boolean", "default": True, "description": "Log return value"},
                "log_backtrace": {"type": "boolean", "default": False, "description": "Log call backtrace"},
                "timeout": {"type": "integer", "default": 10, "description": "Seconds to monitor"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "module", "function"],
        },
    ),
    Tool(
        name="frida_hook_batch",
        description="Hook multiple functions at once. Returns aggregated messages from all hooks.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "hooks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "module": {"type": "string"},
                            "function": {"type": "string"},
                        },
                        "required": ["module", "function"],
                    },
                    "description": "List of {module, function} pairs to hook",
                },
                "timeout": {"type": "integer", "default": 10},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "hooks"],
        },
    ),

    # ── Memory Tools ──

    Tool(
        name="frida_read_memory",
        description="Read bytes from a memory address in a target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "address": {"type": "string", "description": "Memory address (hex string like '0x7ff...')"},
                "size": {"type": "integer", "description": "Number of bytes to read"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "address", "size"],
        },
    ),
    Tool(
        name="frida_write_memory",
        description="Write bytes to a memory address in a target process. Use with caution.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "address": {"type": "string", "description": "Memory address (hex string)"},
                "data": {"type": "string", "description": "Hex string of bytes to write"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "address", "data"],
        },
    ),
    Tool(
        name="frida_search_memory",
        description="Search for a byte pattern in a target process's memory.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "pattern": {"type": "string", "description": "Hex pattern to search for"},
                "module": {"type": "string", "default": "", "description": "Limit search to this module"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "pattern"],
        },
    ),
    Tool(
        name="frida_call_function",
        description="Call a native function in the target process with specified arguments.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "module": {"type": "string", "description": "Module name"},
                "function": {"type": "string", "description": "Export name"},
                "args": {"type": "array", "items": {"type": "string"}, "default": [], "description": "Arguments as strings (numbers or hex)"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "module", "function"],
        },
    ),

    # ── RVA-aware PE analysis (ImageBase-correct; for large DLLs) ──
    Tool(
        name="binary_find_string_rva",
        description="Locate exact strings in a PE and report their RVA and file offset. "
                    "Start here: the RVA feeds binary_xrefs_rva.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file"},
                "needles": {"type": "array", "items": {"type": "string"},
                            "description": "Exact strings to locate"},
                "encoding": {"type": "string", "default": "ascii",
                             "description": "ascii or utf16le"},
            },
            "required": ["binary_path", "needles"],
        },
    ),
    Tool(
        name="binary_xrefs_rva",
        description="Cross-references to an RVA: rip-relative data refs plus direct call/jmp. "
                    "Cost scales with the scanned range - narrow it with binary_func_bounds.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file"},
                "target_rva": {"type": "integer", "description": "RVA to find references to"},
                "scan_start_rva": {"type": "integer", "description": "Scan range start RVA"},
                "scan_end_rva": {"type": "integer", "description": "Scan range end RVA"},
                "kinds": {"type": "array", "items": {"type": "string"},
                          "default": ["rip", "call", "jmp"],
                          "description": "rip, call, jmp, imm64, ptr, rva32. Use ptr on .rdata "
                                         "when a string lives in a const char* table."},
                "pdata_only": {"type": "boolean", "default": False,
                               "description": "Only scan .pdata-covered code (fewer false "
                                              "positives, misses leaf functions)"},
            },
            "required": ["binary_path", "target_rva", "scan_start_rva", "scan_end_rva"],
        },
    ),
    Tool(
        name="binary_func_bounds",
        description="Exact function bounds for an RVA from the x64 .pdata table. "
                    "Null when the RVA has no RUNTIME_FUNCTION (leaf function or 32-bit image).",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file"},
                "rva": {"type": "integer", "description": "Any RVA inside the function"},
            },
            "required": ["binary_path", "rva"],
        },
    ),
    Tool(
        name="binary_disasm_rva",
        description="RVA-aware disassembly: ImageBase-correct addressing with rip-relative and "
                    "call targets resolved to RVAs.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file"},
                "rva": {"type": "integer", "description": "Start RVA, not a file offset"},
                "count": {"type": "integer", "default": 40,
                          "description": "Number of instructions"},
            },
            "required": ["binary_path", "rva"],
        },
    ),
    Tool(
        name="binary_field_refs",
        description="Find reads/writes of a struct field at [reg+offset] - answers 'who touches "
                    "this->field_ at +0xB0?'. Defaults to scanning .text.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file (x64)"},
                "offset": {"type": "integer", "description": "Struct field offset, e.g. 176"},
                "scan_start_rva": {"type": "integer", "description": "Scan start RVA (optional)"},
                "scan_end_rva": {"type": "integer", "description": "Scan end RVA (optional)"},
                "kind": {"type": "string", "default": "both",
                         "description": "read, write or both"},
            },
            "required": ["binary_path", "offset"],
        },
    ),

    # ── Packers ──
    Tool(
        name="unpack_detect",
        description="Detect whether a binary is packed and identify the packer "
                    "(UPX/VMProtect/Themida/ASPack), with section entropy as evidence.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the PE file"},
            },
            "required": ["binary_path"],
        },
    ),
    Tool(
        name="unpack_auto",
        description="Unpack pipeline: detect the packer, try UPX, report what is needed next. "
                    "Non-UPX packers need a runtime memory dump instead.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Path to the packed binary"},
                "output_path": {"type": "string", "default": "",
                                "description": "Where to write the unpacked file"},
            },
            "required": ["binary_path"],
        },
    ),

    # ── Android APK / DEX (offline, no device needed) ──
    Tool(
        name="apk_analyze",
        description="Analyze an APK: manifest (package/version/SDK/permissions/components), "
                    "native libs, dex count, signing info and protection indicators.",
        inputSchema={
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Path to the .apk file"},
            },
            "required": ["apk_path"],
        },
    ),
    Tool(
        name="apk_analyze_dex",
        description="Analyze a DEX file: header, class/method/string counts, class names and a "
                    "sample of strings.",
        inputSchema={
            "type": "object",
            "properties": {
                "dex_path": {"type": "string", "description": "Path to the .dex file"},
            },
            "required": ["dex_path"],
        },
    ),
    Tool(
        name="apk_protections",
        description="Root / SSL-pinning / Frida / emulator detection and packer indicators in an "
                    "APK, each with the matching string as evidence. Run before spawning the app.",
        inputSchema={
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Path to the .apk file"},
            },
            "required": ["apk_path"],
        },
    ),
]

# Argument names that carry a filesystem path; every one of them goes through the
# FRIDAPILOT_ALLOWED_DIRS whitelist before the tool runs.
PATH_ARGUMENTS = ("binary_path", "apk_path", "dex_path", "filepath", "output_path")



# ── Tool handlers ─────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


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


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Dispatch MCP tool calls to FridaPilot Tool Layer.

    Includes audit logging, path validation, and standardized error format.
    """
    start = _time.time()
    try:
        # Every path-bearing argument goes through the whitelist. Checking only
        # one key per tool family (as this used to) leaves the other file tools
        # able to read outside FRIDAPILOT_ALLOWED_DIRS.
        for key in PATH_ARGUMENTS:
            value = arguments.get(key)
            if isinstance(value, str) and value:
                _check_path_allowed(value)

        result = _handle_tool(name, arguments)

        duration = _time.time() - start
        _audit_log(name, arguments)
        # Standardized success response
        response = {"success": True, "data": result, "duration": round(duration, 3)}
        return [TextContent(type="text", text=json.dumps(response, indent=2, default=str))]
    except Exception as e:
        duration = _time.time() - start
        logger.exception(f"Tool {name} failed")
        _audit_log(name, arguments, error=str(e))
        # Standardized error response
        response = {"success": False, "error": str(e), "tool": name, "duration": round(duration, 3)}
        return [TextContent(type="text", text=json.dumps(response, indent=2, default=str))]


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

    if name == "binary_find_string_rva":
        from fridapilot.tools.pe_rva import find_string_rvas
        return find_string_rvas(arguments["binary_path"], list(arguments["needles"]),
                                arguments.get("encoding", "ascii"))

    if name == "binary_xrefs_rva":
        from fridapilot.tools.pe_rva import xrefs_to_rva
        return xrefs_to_rva(
            arguments["binary_path"],
            int(arguments["target_rva"]),
            int(arguments["scan_start_rva"]),
            int(arguments["scan_end_rva"]),
            kinds=tuple(arguments.get("kinds") or ("rip", "call", "jmp")),
            scan_gaps=not arguments.get("pdata_only", False),
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
    """Run the MCP server via stdio transport."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())



if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
