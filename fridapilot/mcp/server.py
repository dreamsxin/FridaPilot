"""FridaPilot MCP Server - Expose Frida tools as MCP (Model Context Protocol) tools.

Allows Claude Desktop, Cursor, and other MCP-compatible agents to call
FridaPilot's Tool Layer directly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import run_server
from mcp.types import Tool, TextContent

from fridapilot.models.schemas import DeviceType

logger = logging.getLogger("fridapilot.mcp")

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
        name="frida_enumerate_modules",
        description="Enumerate loaded modules in a target process.",
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
        name="frida_enumerate_classes",
        description="Enumerate Java/ObjC classes in a target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "filter_prefix": {"type": "string", "default": "", "description": "Filter by class name prefix"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="frida_enumerate_methods",
        description="Enumerate methods of a class in a target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "class_name": {"type": "string", "description": "Fully qualified class name"},
                "device": {"type": "string", "default": "local"},
            },
            "required": ["target", "class_name"],
        },
    ),
    Tool(
        name="frida_enumerate_exports",
        description="Enumerate exports of a module in a target process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID"},
                "module_name": {"type": "string", "description": "Module name"},
                "device": {"type": "string", "default": "local"},
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
]


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


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Dispatch MCP tool calls to FridaPilot Tool Layer."""
    try:
        result = _handle_tool(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as e:
        logger.exception(f"Tool {name} failed")
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


def _handle_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Route tool calls to the appropriate Tool Layer function."""
    device_type = DeviceType(arguments.get("device", "local"))
    host = arguments.get("host", "")

    if name == "frida_list_processes":
        from fridapilot.tools.recon import list_processes
        procs = list_processes(device_type, host)
        return [{"pid": p.pid, "name": p.name} for p in procs]

    if name == "frida_enumerate_modules":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_modules
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            modules = enumerate_modules(session.frida_session)
            return [{"name": m.name, "base": m.base_address, "size": m.size, "path": m.path} for m in modules]
        finally:
            detach(session)

    if name == "frida_enumerate_classes":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_classes
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            classes = enumerate_classes(session.frida_session, arguments.get("filter_prefix", ""))
            return [c.name for c in classes]
        finally:
            detach(session)

    if name == "frida_enumerate_methods":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_methods
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            return enumerate_methods(session.frida_session, arguments["class_name"])
        finally:
            detach(session)

    if name == "frida_enumerate_exports":
        from fridapilot.tools.injector import attach, detach
        from fridapilot.tools.recon import enumerate_exports
        target = _resolve_target(arguments["target"])
        session = attach(target, device_type, host)
        try:
            exports = enumerate_exports(session.frida_session, arguments["module_name"])
            return [{"name": e.name, "address": e.address, "type": e.type} for e in exports]
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

    raise ValueError(f"Unknown tool: {name}")


# ── Entry point ───────────────────────────────────────────────

async def main() -> None:
    """Run the MCP server via stdio transport."""
    await run_server(server)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
