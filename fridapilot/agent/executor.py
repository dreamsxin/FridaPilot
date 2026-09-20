"""Executor - Execute plan steps by dispatching to Tool Layer.

Takes an ExecutionPlan and runs each step sequentially,
resolving dependencies and passing results between steps.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from fridapilot.agent.planner import ExecutionPlan, TaskStep
from fridapilot.models.schemas import DeviceType


@dataclass
class StepResult:
    """Result of executing a single plan step."""
    step_id: int
    tool: str
    success: bool
    result: Any = None
    error: str = ""
    duration: float = 0.0


@dataclass
class ExecutionContext:
    """Shared context across plan execution."""
    session: Any = None  # Current Frida session
    results: dict[int, StepResult] = field(default_factory=dict)
    messages: list[dict] = field(default_factory=list)


# Tool registry: maps tool names to callable functions
TOOL_REGISTRY: dict[str, Any] = {}


def _register_tools() -> None:
    """Lazily register all Tool Layer functions."""
    if TOOL_REGISTRY:
        return

    from fridapilot.tools import recon, injector, script_forge, bypass, crypto_reverse
    from fridapilot.tools import binary_analysis
    from fridapilot.tools import pe_rva
    from fridapilot.tools import unpacker as unpacker_mod
    from fridapilot.tools import apk_analysis
    from fridapilot.tools.lldb_bridge import LLDBBridge

    _lldb = LLDBBridge()

    TOOL_REGISTRY.update({
        "recon.list_processes": recon.list_processes,
        "recon.enumerate_modules": recon.enumerate_modules,
        "recon.enumerate_classes": recon.enumerate_classes,
        "recon.enumerate_methods": recon.enumerate_methods,
        "recon.enumerate_exports": recon.enumerate_exports,
        "injector.attach": injector.attach,
        "injector.spawn": injector.spawn,
        "injector.inject": injector.inject,
        "injector.resume": injector.resume,
        "injector.detach": injector.detach,
        "script_forge.get_template": script_forge.get_template,
        "script_forge.load_script_file": script_forge.load_script_file,
        "bypass.get_ssl_bypass_script": bypass.get_ssl_bypass_script,
        "bypass.get_anti_debug_script": bypass.get_anti_debug_script,
        "crypto_reverse.scan_binary": crypto_reverse.scan_binary,
        "crypto_reverse.get_bcrypt_hook_script": crypto_reverse.get_bcrypt_hook_script,
        # Static binary analysis tools
        "binary_analysis.analyze_pe": binary_analysis.analyze_pe,
        "binary_analysis.analyze_elf": binary_analysis.analyze_elf,
        "binary_analysis.disassemble": binary_analysis.disassemble,
        "binary_analysis.find_strings": binary_analysis.find_strings,
        "binary_analysis.search_bytes": binary_analysis.search_bytes,
        "binary_analysis.xrefs_to": binary_analysis.xrefs_to,
        "binary_analysis.analyze_go_binary": binary_analysis.analyze_go_binary,
        # PE RVA-aware analysis tools
        "pe_rva.find_string_rvas": pe_rva.find_string_rvas,
        "pe_rva.xrefs_to_rva": pe_rva.xrefs_to_rva,
        "pe_rva.field_refs": pe_rva.field_refs,
        "pe_rva.map_refs_to_functions": pe_rva.map_refs_to_functions,
        "pe_rva.disassemble_rva": pe_rva.disassemble_rva,
        "pe_rva.function_bounds": pe_rva.function_bounds,
        # LLDB / macOS tools (graceful no-op if lldb not in PATH)
        "lldb.analyze_binary": _lldb.analyze_binary,
        "lldb.get_macho_info": _lldb.get_macho_info,
        "lldb.check_codesign": _lldb.check_codesign,
        "lldb.dump_objc_classes": _lldb.dump_objc_classes,
        # Mach-O native analysis (no lldb needed)
        "binary_analysis.analyze_macho": binary_analysis.analyze_macho,
        # Unpacker tools
        "unpacker.detect_packer": unpacker_mod.detect_packer,
        "unpacker.unpack_upx": unpacker_mod.unpack_upx,
        "unpacker.dump_process_memory": unpacker_mod.dump_process_memory,
        "unpacker.auto_unpack": unpacker_mod.auto_unpack,
        # APK/DEX analysis
        "apk_analysis.analyze_apk": apk_analysis.analyze_apk,
        "apk_analysis.analyze_dex": apk_analysis.analyze_dex,
        "apk_analysis.detect_protections": apk_analysis.detect_protections,
    })


def _resolve_args(args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
    """Resolve $stepN.result references in step arguments."""
    resolved = {}
    for key, value in args.items():
        if isinstance(value, str) and value.startswith("$step"):
            # Parse $stepN.result
            parts = value.split(".")
            step_id = int(parts[0].replace("$step", ""))
            if step_id in ctx.results and ctx.results[step_id].success:
                resolved[key] = ctx.results[step_id].result
            else:
                resolved[key] = value  # Keep as-is if not resolved
        elif key == "session" or (key == "script" and isinstance(value, str) and value.startswith("$")):
            # Auto-inject session from context
            resolved[key] = value
        else:
            resolved[key] = value
    return resolved


def execute_step(step: TaskStep, ctx: ExecutionContext) -> StepResult:
    """Execute a single plan step."""
    _register_tools()

    start = time.time()
    tool_fn = TOOL_REGISTRY.get(step.tool)

    if tool_fn is None:
        return StepResult(
            step_id=step.id, tool=step.tool, success=False,
            error=f"Unknown tool: {step.tool}", duration=time.time() - start,
        )

    try:
        args = _resolve_args(step.args, ctx)

        # Auto-inject session for tools that need it
        if step.tool.startswith("recon.enumerate") or step.tool == "injector.inject":
            if "session" not in args and ctx.session is not None:
                if step.tool == "injector.inject":
                    args["session"] = ctx.session
                else:
                    args["session"] = ctx.session.frida_session

        # Handle special tools that affect context
        if step.tool in ("injector.attach", "injector.spawn"):
            if "device_type" not in args:
                args["device_type"] = DeviceType(args.pop("device", "local"))
            result = tool_fn(**{k: v for k, v in args.items() if k in ("target", "package", "device_type", "host")})
            ctx.session = result
        elif step.tool == "injector.detach":
            if ctx.session:
                tool_fn(ctx.session)
                ctx.session = None
            result = "detached"
        elif step.tool == "observer.collect":
            timeout = args.get("timeout", 5)
            time.sleep(timeout)
            if ctx.session:
                result = [m.to_dict() for m in ctx.session.observer.messages]
                ctx.messages.extend(result)
            else:
                result = []
        else:
            result = tool_fn(**args)

        return StepResult(
            step_id=step.id, tool=step.tool, success=True,
            result=result, duration=time.time() - start,
        )
    except Exception as e:
        return StepResult(
            step_id=step.id, tool=step.tool, success=False,
            error=str(e), duration=time.time() - start,
        )


def execute_plan(plan: ExecutionPlan) -> tuple[ExecutionContext, list[StepResult]]:
    """Execute all steps in a plan sequentially.

    Returns:
        Tuple of (context, results list).
    """
    ctx = ExecutionContext()
    results: list[StepResult] = []

    for step in plan.steps:
        # Check dependencies
        deps_met = all(
            dep_id in ctx.results and ctx.results[dep_id].success
            for dep_id in step.depends_on
        )
        if not deps_met:
            sr = StepResult(
                step_id=step.id, tool=step.tool, success=False,
                error="Dependencies not met",
            )
            results.append(sr)
            ctx.results[step.id] = sr
            continue

        sr = execute_step(step, ctx)
        results.append(sr)
        ctx.results[step.id] = sr

    return ctx, results
