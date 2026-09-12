"""Reflector - Analyze execution results, diagnose errors, and suggest fixes.

After the Executor runs a plan, the Reflector examines the results,
determines if the goal was achieved, and if not, generates a fix plan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from fridapilot.agent.planner import ExecutionPlan, TaskStep
from fridapilot.agent.executor import StepResult, ExecutionContext


@dataclass
class Diagnosis:
    """Diagnosis of an execution attempt."""
    success: bool
    failed_steps: list[StepResult] = field(default_factory=list)
    error_categories: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    fix_plan: ExecutionPlan | None = None


# Common Frida error patterns and suggested fixes
ERROR_PATTERNS: dict[str, dict[str, str]] = {
    "unable to find process": {
        "category": "target_not_found",
        "suggestion": "Process not found. Check process name/PID, or use --spawn.",
    },
    "failed to attach": {
        "category": "attach_failed",
        "suggestion": "Cannot attach. Is frida-server running? Check permissions.",
    },
    "script is destroyed": {
        "category": "script_crash",
        "suggestion": "Script caused crash. Add try/catch, reduce hook scope.",
    },
    "RPC": {
        "category": "rpc_error",
        "suggestion": "RPC call failed. Check script exports match expected API.",
    },
    "Java.perform": {
        "category": "runtime_mismatch",
        "suggestion": "Java runtime not available. Target may not be a Java/ART process.",
    },
    "ObjC.available": {
        "category": "runtime_mismatch",
        "suggestion": "ObjC runtime not available. Target may not be an iOS/macOS app.",
    },
    "Error: access": {
        "category": "permission_denied",
        "suggestion": "Permission denied. Run frida-server as root or check SELinux.",
    },
    "timed out": {
        "category": "timeout",
        "suggestion": "Operation timed out. Increase timeout or check target responsiveness.",
    },
    "not found": {
        "category": "symbol_not_found",
        "suggestion": "Symbol/class/method not found. Use recon to verify target exists.",
    },
}


def diagnose(
    plan: ExecutionPlan,
    results: list[StepResult],
    ctx: ExecutionContext,
) -> Diagnosis:
    """Analyze execution results and produce a diagnosis.

    Checks which steps failed, categorizes errors, and suggests fixes.
    """
    failed = [r for r in results if not r.success]
    succeeded = [r for r in results if r.success]

    if not failed:
        return Diagnosis(success=True)

    categories: list[str] = []
    suggestions: list[str] = []

    for step_result in failed:
        error_str = step_result.error.lower()
        matched = False
        for pattern, info in ERROR_PATTERNS.items():
            if pattern.lower() in error_str:
                categories.append(info["category"])
                suggestions.append(f"Step {step_result.step_id} ({step_result.tool}): {info['suggestion']}")
                matched = True
                break
        if not matched:
            categories.append("unknown")
            suggestions.append(f"Step {step_result.step_id} ({step_result.tool}): {step_result.error}")

    return Diagnosis(
        success=False,
        failed_steps=failed,
        error_categories=list(set(categories)),
        suggestions=suggestions,
    )


async def reflect_and_fix(
    plan: ExecutionPlan,
    results: list[StepResult],
    ctx: ExecutionContext,
    llm_client: Any = None,
    max_retries: int = 3,
) -> Diagnosis:
    """Analyze failures and use LLM to generate a fix plan.

    Args:
        plan: The original plan.
        results: Execution results.
        ctx: Execution context.
        llm_client: Optional LLM client.
        max_retries: Maximum fix attempts.

    Returns:
        Diagnosis with optional fix_plan.
    """
    diag = diagnose(plan, results, ctx)

    if diag.success:
        return diag

    # If LLM is available, ask it to generate a fix plan
    if llm_client is not None or _has_litellm():
        try:
            fix_plan = await _generate_fix_plan(plan, diag, llm_client)
            diag.fix_plan = fix_plan
        except Exception:
            pass  # Fall back to rule-based suggestions

    return diag


def _has_litellm() -> bool:
    try:
        import litellm
        return True
    except ImportError:
        return False


REFLECTOR_PROMPT = """\
You are FridaPilot's error reflector. A Frida automation plan failed.
Analyze the errors and generate a fixed plan.

Original plan:
{plan}

Failed steps:
{failures}

Error categories: {categories}

Generate a corrected JSON plan that addresses the failures.
Common fixes:
- target_not_found: Use recon.list_processes first, then match name
- attach_failed: Try spawn instead of attach
- script_crash: Add error handling, use simpler hook
- runtime_mismatch: Use recon to detect runtime, pick correct template
- timeout: Increase timeout, add delay before inject
- symbol_not_found: Use recon.enumerate_* to find correct name
"""


async def _generate_fix_plan(
    plan: ExecutionPlan,
    diag: Diagnosis,
    llm_client: Any = None,
) -> ExecutionPlan:
    """Use LLM to generate a fix plan based on error diagnosis."""
    failures_str = "\n".join(
        f"  Step {s.step_id} ({s.tool}): {s.error}" for s in diag.failed_steps
    )

    prompt = REFLECTOR_PROMPT.format(
        plan=plan.model_dump_json(indent=2),
        failures=failures_str,
        categories=", ".join(diag.error_categories),
    )

    if llm_client is None:
        from litellm import acompletion
        response = await acompletion(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": "Generate the fixed plan as JSON."},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        fix_json = json.loads(response.choices[0].message.content)
    else:
        fix_json = await llm_client.fix(plan, diag)

    return ExecutionPlan(**fix_json)
