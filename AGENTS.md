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
ruff check fridapilot tests    # clean as of this commit - keep it that way
python -m fridapilot.cli.main --help    # same as `fp --help` without installing
```



`.github/workflows/ci.yml` runs `ruff check` and the suite on ubuntu-latest and
windows-latest for every push and PR. The Windows job is the one that exercises the ntdll
ground-truth test; the Linux job proves the suite does not depend on a local binary. CI installs
`.[dev,mcp]` only — every litellm import is lazy, so the tests must pass without the agent extra.


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

**The MCP server (`mcp/server.py`) is a separate surface from the Agent registry.** Adding a
tool there means two things: a typed wrapper decorated with `@mcp.tool()` (MCPServer derives the
JSON schema from the annotations and the description from the docstring, so there is no schema to
hand-write and none to keep in sync), and a branch in `_handle_tool` that does the work. If an
argument carries a filesystem path, add its name to `PATH_ARGUMENTS` so `_dispatch` runs it
through the `FRIDAPILOT_ALLOWED_DIRS` whitelist. Tools must not raise: `_dispatch` converts
failures into `{success: false, error, tool, duration}`, because an exception escaping a tool
reaches the client as an opaque `UnexpectedToolError` with the cause stripped.
*(enforced: `tests/test_mcp.py` — wrapper/dispatch parity, schema shape, path coverage,
envelope on failure)*




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
- **Decode only what a displacement points into.** Linear capstone decode with `detail=True`
  costs ≈2.7 s/MB, so decoding every `.pdata` function made one full-`.text` rip query on a
  251 MB Chromium DLL take ≈11 minutes — long enough that the caller reads it as a hang and
  kills it, which is exactly what happened in real use. A rip operand is always ModRM
  mod=00/rm=101 + disp32, so `_iter_rip_refs` first locates candidate displacements with a
  compiled byte-class regex (C speed, ~2% of bytes survive) and skips every function that holds
  none: the same query now takes ≈5.6 s over the same 100% coverage. Anything added to this
  module that walks bytes in Python is suspect for the same reason. *(enforced:
  `tests/test_pe_rva.py::test_a_function_without_a_candidate_displacement_is_never_decoded`,
  `::test_ntdll_targets_referenced_exactly_once_survive_the_prefilter`)*
- **Scan cost scales with the byte range.** A full `.text` rip scan of ntdll (1.5 MB) takes ≈4 s
  when every function must be decoded. Narrow with `func-bounds`, use `map_refs_to_functions`
  for N targets instead of N scans, and `rip_index.build_rip_index` when the same binary will be
  questioned repeatedly — it turns later rip queries into SQL. The index is keyed by file hash
  and refuses queries outside its recorded coverage, which is the only reason it is safe: a cache
  that answers beyond what it scanned reproduces the partial-scan false negative. It is **not** a
  shortcut for the first question: it records refs to every data address, so the prefilter keeps
  almost everything and the build pays the full decode that a single-target query now avoids.

- **A struct or vtable offset is not an identity.** `field_refs` on a vtable slot offset matched
  200+ unrelated classes in one Chromium DLL. A dispatch site carries no type information — the
  object's dynamic type is only known at runtime — so this cannot be narrowed by filtering and no
  tool will fix it. Go the decidable direction with `pe_rva.vtable_of_function` (implementation →
  table, slot index, MSVC RTTI name, installing constructors), or settle it at runtime by
  behavioural comparison. `field_refs` warns above 100 hits instead of returning a list that looks
  like progress. *(enforced:
  `tests/test_pe_rva.py::test_field_refs_warns_when_the_offset_cannot_discriminate`)*
- **A `.pdata`-less leaf also breaks runtime caller attribution.** `Backtracer.ACCURATE` walks
  unwind info, so it yields an empty or single-frame stack there, and `Interceptor`'s trampoline
  makes `this.returnAddress` report the hooked function's own address instead of the caller
  (measured on a 2-instruction getter: it reported itself). The generated native hook falls back
  to `Backtracer.FUZZY` and labels the result with `backtracer: 'accurate' | 'fuzzy'` so the
  attribution is never trusted blindly. Run `function_bounds` on a hook target before relying on
  its stack.
- **"Who calls this function" is the wrong question for most C++ callees.** A virtual method, a
  Blink IDL / V8 binding-table entry, an import thunk and a stored callback are all reached
  through a pointer, so no `call`/`jmp` instruction anywhere in the image names them. Scanning a
  code section for direct branches returns 0 for a hot function exactly as it does for dead code.
  `pe_rva.function_xrefs` sweeps every executable section for branches *and* every data section
  for pointer slots, and returns a `verdict` sentence rather than a bare count. Do not conclude
  "unreferenced" from a call/jmp scan. *(enforced:
  `tests/test_pe_rva.py::test_call_jmp_scan_cannot_see_an_indirect_only_callee`)*
- **Absolute-pattern kinds must not use a per-byte loop.** `ptr`, `rva32` and `imm64` search for
  one fixed byte string, so they go through `bytes.find`; the old `struct.unpack_from` walk cost
  ≈0.3 s/MB (32 MB: ≈10 s vs 0.16 s), which is why a pointer-table sweep of a Chromium-sized data
  section felt unaffordable and got skipped — the direct cause of an indirect-only callee reading
  as unreferenced. `call`/`jmp` are rel32/rel8 and stay in the byte walk, which is now skipped
  entirely when no relative kind is requested.
- **Inline-constructed strings defeat every contiguous search.** A string the compiler builds in
  registers (`movabs rax, imm64` plus a narrower store for the tail) has no `.rdata` copy, and its
  characters are separated by the opcode bytes carrying them — so `find_string_rvas`, `find_text`
  and `search_bytes` all return nothing, and `xrefs_to_rva` has no target RVA to look for. A
  string of *exactly* 8 bytes is the one length a plain search happens to find, which is why the
  docs wrongly claimed `find_text` covered this case for several commits. Use
  `pe_rva.find_inline_strings`, and check its `opcode` field before trusting a hit.
  *(enforced: `tests/test_pe_rva.py::test_inline_string_is_invisible_to_contiguous_search`)*
- **Substring matching on identifiers.** Short indicators must match on token boundaries;
  `"su" in blob` fires on `issue`, `consumer` and `resume`. The same trap in `pe_rva`:
  `find_string_rvas` reports *substring* hits, and the obvious "is it a real string" check —
  read `len(needle)+1` bytes, compare to `needle + b"\0"` — only constrains the **tail**, so
  `ID3D12Device::CheckFeatureSupport` passes a test for `FeatureSupport`. Two separate analyses
  concluded a config key existed in a Chromium DLL that way; the image has 18 hits for it and
  zero standalone strings. Rows therefore carry `whole` and `enclosing` (the NUL-delimited run
  around the hit) so no caller has to re-derive it. *(enforced:
  `tests/test_pe_rva.py::test_a_suffix_hit_is_reported_as_a_substring_not_as_a_string`)*
- **One `md.disasm` pass over a function body ends at the first data byte.** A jump table,
  alignment junk or a constant pool inside the body stops capstone dead, and the generator simply
  finishes — silently dropping everything after the stall. `_iter_rip_refs` has always resynced
  one byte at a time for this reason; `_decode_body` now does it for `describe_function` /
  `function_callees`, after the synthetic fixture's data-in-code byte hid the single `call` in its
  main function and `function_callees` returned an empty list that looked like "dispatches
  indirectly". *(enforced:
  `tests/test_pe_rva.py::test_function_callees_lists_the_direct_call_target`)*
- **String extraction is encoding-blind by default.** The ASCII scanner accepts only 0x20-0x7e,
  so GBK / Shift-JIS / CP1251 text is invisible to it; pass an explicit `codepage`, or use
  `find_text` to search one string under several codecs. Legacy code pages decode almost any
  high-byte pair, so a plausibility filter is mandatory or the output is mojibake.
- **Metadata before disassembly.** `pe_metadata` is the cheapest pass in the tree: a PDB GUID
  fetches public symbols, Rust panic strings carry the original source paths, kept COFF symbols
  name the functions. Reaching for the disassembler first wastes most of that.

- **Frida sessions.** `fp dbg` commands act on the active session (`session switch`); state that
  is only written and never read is the bug to look for when a command "does nothing".
