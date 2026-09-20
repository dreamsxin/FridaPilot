# AGENTS.md — working on FridaPilot

Instructions for coding agents (and humans) changing this repository. Everything here is
verified against the code; the claims marked *(enforced)* have a test that fails when they stop
being true.

## What this is

FridaPilot is a Frida automation and static-analysis toolkit with an optional LLM agent on top.
The design rule that shapes the whole tree: **the tool layer must be usable without an LLM.**

```
fridapilot/
  tools/       pure-Python analysis and instrumentation. No LLM imports, ever.
  cli/         `fp` subcommands (Typer + Rich). Argument parsing and printing only.
  agent/       planner / executor / reflector / reporter. Needs litellm (extra: agent).
  mcp/         MCP server exposing a hand-maintained subset of tools.
  models/      pydantic schemas shared by tools and CLI.
  templates/   Frida JS templates, per platform.
  scripts/     standalone per-platform agent scripts.
  storage/     SQLite history/cache (~/.fridapilot/history.db).
tests/         pytest suite. See "Testing" — the conventions here are not the usual ones.
skills/        agent-facing skill docs; kept executable by tests/test_docs.py.
```

## Setup and commands

```bash
pip install -e .
pip install -e ".[dev]"        # pytest, ruff
pip install -e ".[agent,mcp]"  # LLM planner, MCP server

python -m pytest               # whole suite; Windows-only cases skip elsewhere
python -m pytest tests/test_pe_rva.py -q
ruff check <files you touched>  # the repo is not ruff-clean yet (~67 pre-existing
                                # findings, mostly F401/F541/E402) - just do not add more
python -m fridapilot.cli.main --help    # same as `fp --help` without installing
```


There is no CI configuration in this repo. Run the suite yourself before committing.

## Adding things — the wiring that is easy to forget

**A new tool for the Agent** must be registered *and* documented, in two places:

1. `fridapilot/agent/executor.py` → `_register_tools()` → `TOOL_REGISTRY["module.function"]`
2. `fridapilot/agent/planner.py` → `PLANNER_SYSTEM_PROMPT` → the "Available Tools" section

The prompt is the only place the model learns tool names from. Registering without documenting
produces code that looks wired up and can never be called — this has happened twice here.
*(enforced: `tests/test_agent_tools.py`)*

**A new CLI command**: create `fridapilot/cli/<name>.py` (a `typer.Typer()` for a group, or a
plain function for a single command), then register it in `fridapilot/cli/main.py` with
`app.add_typer(...)` / `app.command(...)`, and add a row to the command table in `README.md`.
Guard missing input files with a clear message instead of a traceback — see `_require_file` in
`cli/apk.py` or the `filepath.exists()` check in `cli/binary.py`.

**Return types**: `models/schemas.py` holds the pydantic models (PE/ELF/recon/disassembly);
several newer tool modules (`apk_analysis`, `unpacker`, `debugger`, `lldb_bridge`) use plain
dataclasses. Both patterns exist — match the module you are editing rather than converting it
as a side effect. CLI code that serialises a dataclass uses `dataclasses.asdict`.

**The MCP server (`mcp/server.py`) has its own hand-written `Tool(...)` list.** It is currently
behind the Python API — the APK tools are not exposed there. Adding a tool to the Agent does not
add it to MCP.

## Testing

The suite is written to pin *correct* behaviour, not current output. Keep it that way:

- Derive expectations from an independent source, not from running the code under test.
  `tests/synthetic_pe.py` hand-assembles a PE with displacements computed from the ISA rule;
  `pefile` and `capstone` then act as oracles that the fixture itself is right before any
  assertion about `pe_rva` runs.
- For real-world inputs, compute ground truth in the test (`test_ntdll_matches_full_disassembly_
  ground_truth` disassembles every `.pdata` function) instead of hard-coding counts.
- Prefer structural invariants — every returned record re-decodes to the requested target,
  records do not overlap, strict mode is a subset of loose mode — over exact numbers.
- Pin the failure that regressed. The indicator tests assert that `"su"` does **not** match
  `issue`/`consumer`/`resume`, because that is the bug that shipped.
- When a test and the code disagree, work out which one is wrong. Both outcomes have happened:
  the innermost-instruction bug in `pe_rva` was real, and a `magic == "dex"` expectation was
  wrong (DEX magic is literally `dex\n035\0`).
- Platform-dependent cases use `pytest.mark.skipif`, and optional real-world fixtures use an
  env var (`FRIDAPILOT_TEST_APK=<path>`). Never make the default run depend on a local binary.

To check that a new test actually catches the bug it targets, run it against the pre-fix commit
in a scratch worktree:

```bash
git worktree add ../_check <pre-fix-sha>
git worktree remove --force ../_check
```

## Documentation is executable

`AGENTS.md` and `skills/**/SKILL.md` are consumed by agents that copy the snippets verbatim, so
`tests/test_docs.py` validates them:

- every ```python``` block must parse, and every call to a FridaPilot function must bind against
  the real signature;
- every `fp` invocation in a ```bash``` block (and every `fp …` command written inline) must
  resolve to a registered command with real options, required options present and positional
  arity respected;

- `<!-- return-keys: <func> = <key>, <key> -->` markers must match the keys the function really
  returns.


If a signature changes, fix the docs in the same commit — the test will point at the line.

## Conventions

- Python ≥ 3.11, `from __future__ import annotations`, `ruff` with `line-length = 100`.
- Heavy imports (`capstone`, `pefile`, `frida`, `litellm`) go inside the function that needs
  them, so `fp --help` stays fast and a missing optional dependency only breaks its own command.
- Comments explain *why*, especially where a simpler approach is wrong. The non-obvious
  reasoning in `pe_rva.py` (why not a flat linear sweep, why not an opcode whitelist) is the
  house style, not an exception.
- Commits: `type(scope): imperative summary`, body stating the problem and the evidence. One
  logical change per commit — do not bundle an unrelated fix into a feature.

## Gotchas that have caused real bugs

- **RVA vs file offset vs VA.** The `disassemble` command's `--address` is a file offset; every
  `*-rva` command and every `pe_rva` function takes an RVA. The delta differs per section, so a
  single constant is wrong the moment you cross a boundary. Convert with `PEImage.rva_to_off` /
  `off_to_rva`.


- **`.pdata` is x64-only, and leaf functions may have no entry.** `function_bounds() is None`
  means "no RUNTIME_FUNCTION", not "not a function". Do not use it as a filter that silently
  drops results; `xrefs_to_rva` keeps a separate scan for exactly that reason.
- **Section sizes.** Parse tables with `min(VirtualSize, SizeOfRawData)`: `SizeOfRawData` is
  file-aligned, so walking it reads alignment padding as data.
- **`PEImage` reads the whole file and caches `.pdata`.** Reuse one instance; constructing it per
  lookup re-reads a 250 MB DLL each time.
- **Scan cost scales with the byte range.** A full `.text` rip scan of ntdll (1.5 MB) takes ≈4 s;
  a 100 MB `.text` is minutes. Narrow with `func-bounds`, and use `map_refs_to_functions` for N
  targets instead of N scans.
- **Substring matching on identifiers.** Short indicators must match on token boundaries;
  `"su" in blob` fires on `issue`, `consumer` and `resume`.
- **Frida sessions.** `fp dbg` commands act on the active session (`session switch`); state that
  is only written and never read is the bug to look for when a command "does nothing".
