---
name: fridapilot-pe-analysis
description: |
  Use FridaPilot's RVA-aware PE analysis tools (fridapilot.tools.pe_rva / fp binary *-rva)
  to reverse engineer large x86-64 Windows DLLs and EXEs — Chromium-based binaries such as
  chrome.dll and Electron builds in particular. Trigger when the user wants to: find
  cross-references to a global variable, string or function inside a PE, locate the RVA of a
  known string, get exact function boundaries from .pdata, disassemble at an RVA with correct
  ImageBase, find who reads or writes a struct field at [reg+offset], or map many strings to
  their consuming functions in one scan. Also trigger on "xref", "RVA", "chrome.dll analysis",
  "reverse engineer DLL", "find references to address", "disassemble at RVA", "patch
  chrome.dll", "Chromium kernel reverse engineering", "fingerprint browser analysis". Cost
  scales with the scanned byte range, so scope scans with func-bounds before sweeping a whole
  .text — see the Performance section for measured numbers. For PE headers, imports, packer
  detection or byte-pattern search use `fp binary analyze-pe` / `search-bytes` / `fp unpack`
  instead; this skill covers the RVA-aware subset only.
---

# FridaPilot PE Binary Analysis

RVA-aware static analysis for x86-64 PE images: ImageBase-correct addressing, section-aware
RVA↔file-offset conversion, and `.pdata` (SEH `RUNTIME_FUNCTION`) function boundaries.

Every snippet and command below is checked against the real signatures and the real Typer app
by `tests/test_docs.py`. If you change `pe_rva.py` or `cli/binary.py`, that test tells you
which lines here went stale.

> The addresses in the examples (`0x2f10a40`, `0x1c43500`, …) are **placeholders**, not measured
> values from any particular build — `chrome.dll` is just a stand-in for "a large Chromium-style
> PE". Resolve real RVAs yourself with `find-string-rva` / `func-bounds` first.

## Install

```bash
pip install -e .
```

## Workflow

```
0. pe_metadata()             what the build leaked: PDB GUID, version, toolchain, Rust paths
1. find_string_rvas()        locate config keys / messages by content  -> RVAs
   find_text()               ... when the encoding is unknown (UTF-16/GBK/Shift-JIS)
2. xrefs_to_rva()            find the code that references them        -> from_rva
3. function_bounds()         exact enclosing function from .pdata      -> begin/end
4. disassemble_rva()         read the function with correct ImageBase
5. field_refs()              find accesses to this->field_ at +offset
```

Step 0 is not optional politeness — it is the step that decides how much of the rest you need.
A PDB GUID pulls public symbols off the symbol server; a Rust panic path spells out the original
source tree; kept COFF symbols name the functions outright. Use `map_refs_to_functions()` instead
of step 2 when you have many targets: it scans once and groups by `.pdata` function.

## Step 0: metadata recon

```python
from fridapilot.tools.pe_metadata import pe_metadata

meta = pe_metadata("app.exe")
meta["debug"]["symbol_server_key"]   # 'app.pdb/<32-hex GUID><age hex>/app.pdb'
meta["version_info"]["CompanyName"]
meta["toolchain"]["guesses"]         # ['rust'], ['go'], ['msvc'], ['dotnet'], ...
meta.get("rust", {}).get("own_source_paths")
```

<!-- return-keys: pe_metadata = filepath, machine, is_dll, is_dotnet, timestamp, debug, version_info, manifest, rich_header, coff_symbols, resources, security, sections, dynamic_api_resolution, toolchain -->
Keys: `filepath`, `machine`, `is_dll`, `is_dotnet`, `timestamp`, `debug`, `version_info`,
`manifest`, `rich_header`, `coff_symbols`, `resources`, `security`, `sections`,
`dynamic_api_resolution`, `toolchain` — plus `rust` when Rust markers are present.

What to do with each:

- `debug.symbol_server_key` — fetch public symbols (`https://msdl.microsoft.com/download/symbols/<key>`).
  The GUID is 32 hex chars with the first three fields little-endian; the age is appended in hex.
- `debug.pdb_path` — leaks the build machine's user name and project directory even when the PDB
  itself was never shipped.
- `toolchain.guesses` + `rust.own_source_paths` — Rust embeds `file!()` for every `panic!`, so the
  source tree survives symbol stripping. `rust.crates` lists dependency names and versions.
- `coff_symbols` — non-empty means the linker kept the COFF symbol table (common with MinGW).
- `version_info` / `manifest` — vendor labels and the requested UAC level.
- `dynamic_api_resolution.suspicious` — a tiny import table plus `LoadLibrary`/`GetProcAddress`
  means the real API set is resolved at runtime; hook those two instead of reading the imports.
- `sections[].entropy` — above ~7.2 is packed or encrypted data, not code to disassemble.

```bash
fp binary metadata app.exe
fp binary metadata app.exe --json
```

## Workflow (tool reference)

## Python SDK



## Python SDK

```python
from fridapilot.tools.pe_rva import (
    PEImage,
    find_string_rvas,
    xrefs_to_rva,
    map_refs_to_functions,
    function_bounds,
    disassemble_rva,
    field_refs,
)
```

### find_string_rvas — locate strings

```python
results = find_string_rvas("chrome.dll", ["enableTelemetry", "deviceModelName"])
results = find_string_rvas("chrome.dll", ["宽字符"], encoding="utf16le")
```

<!-- return-keys: find_string_rvas = needle, offset, rva, encoding -->
Rows: `needle`, `offset` (file offset), `rva`, `encoding`. A needle that is absent still gets a
row, with `offset` and `rva` set to `None`. Every occurrence is reported, so a string that
appears twice yields two rows.

```bash
fp binary find-string-rva chrome.dll "enableTelemetry,deviceModelName"
fp binary find-string-rva chrome.dll "宽字符" --encoding utf16le --json
```

Needles are **one comma-separated argument**, not separate arguments.

### find_text / find_strings — when the encoding is the unknown

`find_string_rvas` needs you to name the encoding (`ascii`, which encodes the needle as UTF-8, or
`utf16le`). When you do not know how the binary stores the text, search several codecs at once:

```python
from fridapilot.tools.binary_analysis import find_strings, find_text

hits = find_text("app.exe", "\u8bb8\u53ef\u8fc7\u671f",
                 encodings=("utf8", "utf16le", "gbk", "big5", "cp932"))
```

<!-- return-keys: find_text = offset, value, encoding, rva, section -->
Rows: `offset`, `value`, `encoding`, `rva`, `section`. Codecs that cannot represent the text are
skipped, and codecs producing identical bytes are merged into one hit labelled `ascii/gbk/...` —
so the encodings that appear are the ones the binary actually uses.

Bulk extraction understands legacy code pages too. The ASCII pass only accepts bytes 0x20-0x7e,
so GBK / Shift-JIS / CP1251 text is invisible to it:

```python
strings = find_strings("app.exe", min_len=4, encoding="all", codepage="gbk")
```

<!-- return-keys: find_strings = offset, value, encoding, rva, section -->
Nearly any high-byte pair decodes to *something* in GBK, so the code page pass keeps a run only
when the decoded text passes a plausibility check — expect it to be quieter than `strings`.

```bash
fp binary find-text app.exe --text "license expired" --encodings ascii,utf16le,gbk
fp binary find-strings app.exe --codepage gbk --min-len 4 --filter 许可
fp binary search-bytes app.exe "48 8b ?? 48 89" --limit 20
```

<!-- return-keys: search_bytes = offset, matched_bytes, rva, section -->
`search-bytes` (hex, `??` wildcards) and both string commands report `rva` and `section` for PE
input, so a hit feeds `func-bounds` / `xrefs-rva` without manual conversion. Offsets inside the
headers map to themselves and are labelled `(headers)`.

### vtable_of_function — which table holds this method, at which slot, for which class

Only the direction **implementation → vtable** is statically decidable. The reverse is the most
expensive wrong turn available here:

```asm
mov rax, [rcx]          ; vtable out of the object
mov rax, [rax+0x1f8]    ; slot 63
call __guard_dispatch_icall_fptr
```

`0x1f8` says nothing about *which* class is dispatched — the dynamic type lives in the object at
runtime, not in the instruction stream. Searching `[reg+0x1f8]` across a Chromium-sized DLL
returns **200+ hits from unrelated classes**, and no filter narrows it, because the information is
not there. `field_refs` now warns when the match count is that high instead of handing back a list
that looks like progress.

```python
from fridapilot.tools.pe_rva import vtable_of_function

tables = vtable_of_function("chrome.dll", 0x4f1a20)   # the method BODY, not a slot
```

<!-- return-keys: vtable_of_function = slot_rva, slot_index, vtable_rva, entries, section, rtti, vtable_refs -->
One record per containing table: `slot_rva`, `slot_index`, `vtable_rva`, `entries`, `section`,
`rtti`, `vtable_refs`.

- `slot_index` answers "which slot number is this?" — computed from the recovered table start,
  not guessed. The extent comes from growing a run of consecutive code pointers around the hit.
- `rtti.mangled` gives the class outright (an MSVC mangled name such as `.?AVWidget@app@@`) when
  the build kept RTTI. Chromium-based binaries are built with `-fno-rtti`, so expect `None`
  there — that is a fact about the build, not a failure.
- `vtable_refs` are the rip-relative references to the table start, i.e. the constructors that
  install it. With RTTI stripped these are the route to the class: disassemble one and look at
  the other members it initialises.
- `entries == 1` means an isolated function pointer (a callback or thunk), not a vtable.

```bash
fp binary vtable chrome.dll --target 0x4f1a20
fp binary vtable chrome.dll --target 0x4f1a20 --json
```

### function_xrefs — who reaches a function (direct *and* indirect)

**For a code target, use this instead of `xrefs_to_rva(kinds=("call","jmp"))`.** "Who branches
to this address" is the wrong question for a large class of real callees:

- C++ virtual methods are dispatched through a vtable;
- methods bound into a scripting engine (Blink/V8-style IDL bindings, and any comparable
  generated binding layer) are invoked out of a generated method table;
- imports go through a thunk table; callbacks are stored and called later.

For all of those the only occurrence of the function's address in the image is an 8-byte pointer
in a **data** section, which a `.text` scan never looks at. So the scan returns 0 — for a hot
function exactly as it would for dead code.

```python
from fridapilot.tools.pe_rva import function_xrefs

res = function_xrefs("chrome.dll", 0x4f2b80)
res = function_xrefs("chrome.dll", 0x4f2b80, follow=True)   # + the dispatch sites
```

<!-- return-keys: function_xrefs = target_rva, target_section, target_is_code, direct, indirect, dispatchers, scanned, verdict -->
Returns `target_rva`, `target_section`, `target_is_code`, `direct` (call/jmp sites), `indirect`
(pointer slots), `dispatchers` (with `follow=True`: the instructions that load those slots),
`scanned` (every section swept, with the kinds used), and `verdict`.

Read `verdict` first — it is there because the number that needs interpreting is zero:

- *"N direct call/jmp site(s)"* — ordinary function.
- *"no direct call/jmp, but the address appears in N data-section slot(s)"* — indirectly
  dispatched. `follow=True` then names the code that loads the slot, which is the real caller.
- *"no reference of any kind, over every code and data section"* — only now is "unreferenced" a
  defensible conclusion, and even then the address may be computed at runtime or be an exported
  entry point.

Both section classes are always swept whole, so this answer is never range-limited.

```bash
fp binary callers chrome.dll --target 0x4f2b80
fp binary callers chrome.dll --target 0x4f2b80 --follow
```

`xrefs-rva` now also refuses to be silent about this: 0 hits on an address in an executable
section prints the indirect-dispatch explanation and the `callers` command to run.

### xrefs_to_rva — cross-references to an RVA

**The range defaults to the whole section. Do not hand-pick one unless you mean to.** A partial
range returns fewer references, and an empty list from a partial scan is indistinguishable from
"nothing references this" — that exact mistake (a third of a 240 MB `.text`, read as "no
references") is why the default exists. Partial coverage is logged as a warning, and the CLI
prints the scanned extent with its percentage.

```python
from fridapilot.tools.pe_rva import section_range

refs = xrefs_to_rva("chrome.dll", 0x2f10a40)                      # whole .text
refs = xrefs_to_rva("chrome.dll", 0x2f11800, section=".rdata", kinds=("ptr",))
refs = xrefs_to_rva(                                             # deliberately narrowed
    "chrome.dll",
    target_rva=0x2f10a40,
    scan_start_rva=0x1c42000,
    scan_end_rva=0x1c43f00,
    kinds=("rip", "call", "jmp"),
    verify=True,
    scan_gaps=True,
)
text = section_range("chrome.dll", ".text")                      # {start_rva, end_rva, size}
```

<!-- return-keys: section_range = section, start_rva, end_rva, size -->
<!-- return-keys: xrefs_to_rva = from_rva, mnemonic, op_str, target_rva, kind, size -->
Rows: `from_rva`, `mnemonic`, `op_str`, `target_rva`, `kind`, `size`. `section_range` returns
`section`, `start_rva`, `end_rva`, `size`.

Kinds: `rip` (rip-relative memory operand), `call` (`E8 rel32`), `jmp` (`E9 rel32` / `EB rel8`),
`imm64` (`movabs r64, ImageBase+rva`), `ptr` (raw 8-byte VA in data), `rva32` (raw 4-byte RVA).

`ptr` matters for tables: Chromium collects `const char*` into `.rdata` arrays and only LEAs
the array base, so individual strings have no rip reference at all. If `rip` finds nothing for
a string that is obviously used, rescan `.rdata` with `kinds=("ptr",)`.

If that also finds nothing, the string may be **built inline** — the compiler emits
`movabs rcx, 0x6567617373654d` ("Message") and assembles it in registers, so there is no
operand pointing at `.rdata` to find. `xrefs_to_rva` structurally cannot find it (there is no
target RVA), and **neither can a contiguous byte search**: use `find_inline_strings` (below).

### find_inline_strings — strings the code builds instead of points at

```python
from fridapilot.tools.pe_rva import find_inline_strings

sites = find_inline_strings("chrome.dll", "ConfigValue")
sites = find_inline_strings("chrome.dll", "\u8bb8\u53ef", encoding="gbk", section=".text")
```

<!-- return-keys: find_inline_strings = text, from_rva, section, anchor_hex, opcode, chunks_total, chunks_found, coverage, func_begin_rva, func_end_rva -->
Rows: `text`, `from_rva` (the carrying instruction, ready for `disasm-rva`), `section`,
`anchor_hex`, `opcode`, `chunks_total`, `chunks_found`, `coverage`, `func_begin_rva`,
`func_end_rva`. Best coverage first.

Why a plain search cannot do this: an inline string is materialised 8 bytes at a time, so the
characters are separated by the opcode bytes carrying them. `b"ConfigValue"` (11 bytes) becomes

```
48 B8 43 6F 6E 66 69 67 56 61    movabs rax, imm64   -> "ConfigVa"
B8 6C 75 65 00                   mov eax, imm32      -> "lue\0"
```

The 11 bytes appear contiguously **nowhere** in the image, so `find_string_rvas`, `find_text` and
`search_bytes` all return nothing. Only the first 8 do — which is why a string of *exactly* 8
bytes looks like the tool works, and anything longer silently fails. This function anchors on the
first 8 bytes, then confirms the remaining groups within `window` bytes.

`opcode` is the field to trust: `"movabs"` means the anchor really is a `MOV r64, imm64` operand,
`""` means the bytes matched but no MOV immediate precedes them — possibly data, so disassemble
before believing it. `coverage == 1.0` means every group was accounted for.

```bash
fp binary inline-strings chrome.dll --text ConfigValue
fp binary inline-strings chrome.dll --text ConfigValue --confirmed --json
fp binary inline-strings app.exe --text 许可过期 --encoding gbk
```

`func_begin_rva` is `None` for a site outside every `.pdata` entry, which is common: inline
construction is a hallmark of small leaf helpers.


How rip references are found (relevant when judging results):

- **Pass A** disassembles every `.pdata` `RUNTIME_FUNCTION` in range. Function bounds give the
  synchronisation a flat linear sweep lacks, and capstone handles every prefix form — `LOCK
  CMPXCHG [rip+d], rcx`, `66 89 05` word stores, `F3 0F 10 05` movss, VEX/EVEX. An opcode
  whitelist cannot: measured on ntdll.dll, whitelisting caps rip recall at 95.5%, and the
  misses concentrate in exactly the `lock cmpxchg` accesses that mark singletons, refcounts and
  init flags.
- **Pass B** covers what `.pdata` does not (leaf functions, hand-written asm, packed code,
  32-bit images, data sections) with an opcode-agnostic displacement scan.

`verify=False` skips capstone confirmation in pass B only — pass A always decodes.
`scan_gaps=False` runs pass A alone: fewer false positives when the range spans data, at the
cost of missing references outside known functions — and it skips leaf functions entirely, so a
small wrapper that touches the target will not show up.

```bash
fp binary xrefs-rva chrome.dll --target 0x2f10a40
fp binary xrefs-rva chrome.dll --target 0x2f11800 --section .rdata --kinds ptr
fp binary xrefs-rva chrome.dll --target 0x2f10a40 --start 0x1c42000 --end 0x1c43f00
```


### function_bounds — exact function extent

```python
bounds = function_bounds("chrome.dll", 0x1c43500)   # any RVA inside the function
```

<!-- return-keys: function_bounds = begin_rva, end_rva, size, unwind_info_rva -->
Returns `begin_rva`, `end_rva`, `size`, `unwind_info_rva`, or `None` when the RVA is not inside
any `RUNTIME_FUNCTION` — which happens for leaf functions (the ABI lets them omit unwind data)
and for anything in a 32-bit image, where there is no `.pdata` at all. `None` therefore means
"no entry", not "not a function".

```bash
fp binary func-bounds chrome.dll --rva 0x1c43500
```

### disassemble_rva — RVA-aware disassembly

```python
result = disassemble_rva("chrome.dll", 0x1c43550, count=20)
result = disassemble_rva("chrome.dll", rva=0x1c43550, count=20,
                         symbols={0x2f10a40: "g_config"}, resolve_rip=True)
```

<!-- return-keys: disassemble_rva = image_base, start_rva, lines -->
Returns `image_base`, `start_rva`, `lines`; each line has `rva`, `va`, `bytes_hex`, `mnemonic`,
`op_str`, `note`. `note` carries the resolved rip target RVA and, when `symbols` is supplied,
the matching name. On an RVA with no backing file data (BSS) the result carries an `error` key
and an empty `lines` list.

The parameters are `rva` and `count` — not `start_rva` / `num_instructions`.

```bash
fp binary disasm-rva chrome.dll --rva 0x1c43550 --count 20
fp binary disasm-rva chrome.dll -r 0x1c43550 -n 60 --symbols 0x2f10a40:g_config
```

### field_refs — struct field access

Answers "who touches `this->field_` at +0xB0?".

```python
refs = field_refs("chrome.dll", 0xB0, scan_start_rva=0x1c42000,
                  scan_end_rva=0x1c43f00, kind="both")
refs = field_refs("chrome.dll", 0x78)      # range defaults to .text
```

Rows: `from_rva`, `mnemonic`, `op_str`, `kind` (`read`/`write`), `size`. Matches `mod=01`
(disp8) as well as `mod=10` (disp32), so small offsets are not silently dropped, and includes
the SSE stores MSVC emits for adjacent members.

```bash
fp binary field-refs chrome.dll --offset 0xB0 --start-rva 0x1c42000 --end-rva 0x1c43f00
fp binary field-refs chrome.dll --offset 0x78 --kind write --with-func
```

Note the option names: `--offset`, `--start-rva`, `--end-rva` (not `--start` / `--end`).

### map_refs_to_functions — many targets, one pass

```python
result = map_refs_to_functions(
    "chrome.dll",
    targets={"enableTelemetry": 0x2f10a40, "deviceModelName": 0x2f11800},
    kinds=("rip",),
)
```

<!-- return-keys: map_refs_to_functions = functions, orphans, unreferenced, scanned_bytes, scan_start_rva, scan_end_rva, section, section_coverage -->
Returns `functions` (each with `begin_rva`, `end_rva`, `size`, `labels`, `refs`, sorted by how
many distinct labels they use), `orphans` (references outside any `.pdata` entry),
`unreferenced` (labels nothing pointed at), `scanned_bytes`, and the range actually scanned:
`scan_start_rva`, `scan_end_rva`, `section`, `section_coverage` (1.0 = the whole section).

**Check `section_coverage` before believing `unreferenced`.** Anything below 1.0 means the scan
did not see the whole section, so "unreferenced" only means "not referenced in the part I looked
at". The range defaults to the whole section, so it is 1.0 unless you narrowed it.


The CLI variant resolves the strings for you — `--strings` for an explicit list, `--prefix` to
auto-collect every NUL-terminated `.rdata` string with that prefix:

```bash
fp binary map-refs chrome.dll --strings "enableTelemetry,deviceModelName"
fp binary map-refs chrome.dll --prefix np- --min-labels 2
```

`--prefix` takes a **string prefix** (e.g. `np-`), not `rva=label` pairs.

### PEImage — low-level access

```python
img = PEImage("chrome.dll")
img.image_base             # ImageBase from the optional header
img.is_64bit
img.rva_to_off(0x1000)     # -> file offset, or None for BSS / unmapped
img.off_to_rva(0x400)      # -> RVA, or None outside every raw section
img.va_to_rva(0x180c43550)
img.rva_to_va(0xc43550)
img.read_rva(0xc43550, 64) # clamped to the containing section
img.in_file(0x2f10a40)     # False for uninitialised .data
img.section_of(0xc43550)   # ".text"
img.exception_table()      # [(begin_rva, end_rva, unwind_rva), ...] - cached, sorted
img.function_at(0xc43500)  # -> (begin_rva, end_rva, unwind_rva) | None, binary search
```

`exception_table()` yields **three**-element tuples and is empty for images without `.pdata`.
It is parsed once per `PEImage` and bounded by `min(VirtualSize, SizeOfRawData)`, so
file-alignment padding never shows up as entries — reuse one `PEImage` instead of constructing
it per lookup.

## Performance

A single-target rip query is dominated by the candidate scan, not by disassembly: a rip operand
is always ModRM mod=00/rm=101 + disp32, so the displacements that could resolve to the target are
found at C speed first and only the `.pdata` functions containing one get decoded. Measured on a
251 MB `.text` (Chromium-sized DLL), full 100% coverage: **≈5.6 s** for one target, down from
≈11 minutes when every function was decoded (linear capstone decode costs ≈2.7 s/MB). ntdll
(1.5 MB `.text`, 5650 `.pdata` entries): well under a second per target, and
`map_refs_to_functions` costs about one scan for *all* targets together.

So a full-section scan is normally the right call — do not pre-narrow the range to save time and
risk the partial-coverage false negative. Two things still cost real time:

**`index-build` pays the full decode.** It records refs to *every* data address, so the prefilter
keeps nearly all candidates and the build is the ≈11-minute job the single-target path avoids. It
is worth it when dozens of queries follow, not as a shortcut for the first one:

```bash
fp binary index-build chrome.dll
fp binary xrefs-rva chrome.dll --target 0x2f10a40 --kinds rip   # now a DB query
fp binary index-info chrome.dll
fp binary index-drop chrome.dll
```

```python
from fridapilot.tools.rip_index import build_rip_index, index_info

stats = build_rip_index("chrome.dll", section=".text")
info = index_info("chrome.dll")
```

<!-- return-keys: build_rip_index = sha256, refs, targets, section, scan_start_rva, scan_end_rva, target_ranges, seconds, db_path -->
`build_rip_index` decodes every `.pdata` function once and stores each rip reference whose target
lands in a data section. Measured on ntdll: 3.9 s to build (8389 refs to 2400 targets), after
which the same query that took 4.2 s returns immediately with identical results. It is keyed by
file **content hash**, so a patched binary has no index rather than a stale one, and it records
the range and target sections it covers — a query outside them falls back to a real scan instead
of returning a short list. `--no-index` forces a rescan; `kinds` other than `rip` still scan.

Practical order of work:

1. `metadata` (free) and `find-string-rva` (fast, whole-file `bytes.find`)
2. `index-build` once, if more than a couple of xref questions are coming
3. `xrefs-rva` (whole section by default — check the printed coverage)
4. `func-bounds` to pin the function, then `disasm-rva` / `field-refs` inside it
5. `map-refs` when you have N targets and no index — never loop `xrefs-rva` N times

## Decision Strategy

Follow this order on every PE target. Each step's output decides whether the next is needed.

**Step 0 — `pe_metadata` (always first, zero cost).** A PDB GUID fetches public symbols from
the Microsoft symbol server; Rust panic paths leak the source tree; kept COFF symbols name the
functions. If any of these are present, most of the later steps become unnecessary — plan
around the names you already have. Section entropy >7.2 means packed/encrypted data: unpack
before disassembling. A tiny import table with `LoadLibrary`/`GetProcAddress` signals dynamic
API resolution — hook those two functions at runtime instead of reading the imports.

**Step 1 — Anchor location.** Use `find-string-rva` when the encoding is known (UTF-8/UTF-16),
`find-text` when it is not (searches multiple codecs simultaneously), and `search-bytes` for
constants, magic values, or instruction patterns. All return RVA + section, so results feed
directly into step 2.

**Step 2 — Cross-references.** `xrefs-rva` defaults to scanning the whole section. Do NOT
hand-pick a sub-range unless you genuinely intend a narrow search — a partial scan that returns
nothing is indistinguishable from "this target has no references", and that exact mistake
**Step 2 — Cross-references.** First decide *what the target is*. A **function** goes to
`function_xrefs` / `fp binary callers`, never to `xrefs-rva --kinds call,jmp`: a callee reached
only through a vtable, an IDL binding table or an import thunk has no direct branch anywhere in
the image, so "who calls it" returns 0 for a hot function exactly as for dead code.

For **data**, `xrefs-rva` defaults to scanning the whole section. Do NOT
hand-pick a sub-range unless you genuinely intend a narrow search — a partial scan that returns
nothing is indistinguishable from "this target has no references", and that exact mistake
happened twice on a 240 MB `.text` (21.8% and 16.3% coverage, both read as "no references").
Always check the printed coverage percentage. If `rip` finds
nothing for a string that is obviously used, rescan `.rdata` with `kinds=("ptr",)` (Chromium
collects `const char*` into arrays and only LEAs the array base). If that also finds nothing,
the string may be built inline via `movabs` — use `find-inline-strings`, **not** `find-text`: the
characters are split by the opcodes carrying them, so no contiguous search reaches them.
For N targets use `map-refs`, which scans once.

**Step 2.5 — rip index (optional, amortises cost).** When the investigation will ask more than
a couple of xref questions on the same binary, run `index-build` once. It scans every `.pdata`
function and stores every rip reference whose target lands in a data section. Afterwards
`xrefs-rva --kinds rip` becomes a database query (~0s vs 4s on ntdll). The index is keyed by
file content hash and refuses queries outside its recorded range, so it never returns stale or
incomplete data. `--no-index` forces a rescan; `kinds` other than `rip` still scan.

**Step 3 — Converge.** `func-bounds` gives the exact function extent from `.pdata` (None means
no `.pdata` entry — leaf function or 32-bit image, not "not a function"). `disasm-rva` reads
the function with correct ImageBase and annotates rip/call targets. `field-refs` locates struct
field accesses at a given offset.

**Step 4 — Switch to Frida.** When values only exist at runtime (encryption keys, protocol
contents, dynamically resolved addresses), switch to `fp attach`/`fp dbg`/`fp inject`. Static
analysis found the function; dynamic analysis reads its arguments.


## Gotchas

- **Pass RVAs, not file offsets or VAs.** The `disassemble` command's `--address` is a file
  offset; every `*-rva` command and every `pe_rva` function takes an RVA. `PEImage.rva_to_off` /
  `off_to_rva` convert, and the delta differs per section.

- **`.pdata` is x64-only.** On a 32-bit image `function_bounds` returns `None`, `exception_table`
  is empty, and `xrefs_to_rva` relies entirely on pass B (`scan_gaps=True`, the default).
- **Scanning for `call`/`jmp` is the wrong question for most C++ callees.** Virtual methods, IDL
  binding-table entries and import thunks are reached through a pointer, so a code-section scan
  finds nothing regardless of how heavily used they are. `function_xrefs` sweeps code *and* data
  and says which case it is. *(enforced:
  `tests/test_pe_rva.py::test_call_jmp_scan_cannot_see_an_indirect_only_callee`)*
- **A struct/vtable offset is not an identity.** `[reg+0x1f8]` matched 200+ unrelated classes in
  one Chromium DLL. The dispatch site does not know the object's type, so this cannot be filtered
  — go `vtable_of_function` from the implementation, or decide it at runtime. `field_refs` warns
  above 100 hits. *(enforced: `tests/test_pe_rva.py::test_field_refs_warns_when_the_offset_cannot_discriminate`)*
- **On a `.pdata`-less leaf, runtime caller attribution fails too.** `Backtracer.ACCURATE` walks
  unwind info, so it returns an empty or single-frame stack; and `Interceptor`'s trampoline makes
  `this.returnAddress` report the hooked function's own address rather than the caller — measured
  on a 2-instruction getter, which reported itself. Check `func-bounds` before planning to
  identify callers at runtime; when it returns `None`, compare behaviour across inputs (vary one
  setting, count invocations of a downstream function) instead. The generated native hook now
  falls back to `Backtracer.FUZZY` and labels which backtracer produced the frames.
- **`rip` finding nothing is not proof of absence.** Try `ptr` on `.rdata`, widen the range, and
  check `find_inline_strings` — a string built from immediates has no address to reference, so
  every xref scan and every contiguous byte search misses it by construction. Only a string of
  exactly 8 bytes happens to survive a plain search, which is what hid this for so long.
- Heuristics worth knowing, not guarantees: libc++ `std::string` stores up to 22 `char`s inline
  before heap-allocating, so read the SSO flag byte before dereferencing; and a `movzx byte +
  test + jne` on a global in Chromium is often PGO hot/cold splitting rather than the real
  feature gate, so follow the writes (`field_refs`, `xrefs_to_rva` with `kinds=("rip",)`) before
  concluding you found the switch.
