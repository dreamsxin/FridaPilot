"""Tests for the Agent tool registry.

A tool is only usable if it is both *callable* (registered in
``executor.TOOL_REGISTRY``) and *discoverable* (listed in
``planner.PLANNER_SYSTEM_PROMPT``, which is the only place the model learns tool
names from). Registering without documenting produces dead code that looks fine
in review — this has already happened twice in this repo — so the parity is
asserted here rather than left to memory.
"""

from __future__ import annotations

import importlib

import pytest

from fridapilot.agent import executor
from fridapilot.agent.planner import PLANNER_SYSTEM_PROMPT


@pytest.fixture(scope="module")
def registry() -> dict:
    executor._register_tools()
    assert executor.TOOL_REGISTRY, "no tools registered"
    return executor.TOOL_REGISTRY


def test_every_registered_tool_is_documented_in_the_planner_prompt(registry):
    undocumented = sorted(name for name in registry if name not in PLANNER_SYSTEM_PROMPT)
    assert not undocumented, (
        "these tools can never be selected by the planner - add them to "
        "PLANNER_SYSTEM_PROMPT's 'Available Tools' section: %s" % undocumented)


def test_every_registered_tool_is_callable(registry):
    not_callable = sorted(name for name, fn in registry.items() if not callable(fn))
    assert not not_callable, not_callable


def test_tool_names_follow_module_dot_function(registry):
    """`module.function` must name something that actually exists under tools/."""
    aliases = {"lldb": "lldb_bridge", "unpacker": "unpacker"}
    problems = []
    for name, fn in registry.items():
        module_part, _, func_part = name.partition(".")
        assert func_part, name
        module_name = aliases.get(module_part, module_part)
        try:
            module = importlib.import_module(f"fridapilot.tools.{module_name}")
        except ModuleNotFoundError:
            problems.append(f"{name}: no fridapilot.tools.{module_name}")
            continue
        # bound methods (lldb.*) live on a class instance, not the module
        if not hasattr(module, func_part) and getattr(fn, "__self__", None) is None:
            problems.append(f"{name}: {module_name} has no {func_part}")
    assert not problems, problems
