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

> Addresses in the examples (`0xfcae886`, `0x1044f64c`, …) are **placeholders**, not measured
> values from any particular build. Always resolve real RVAs with `find-string-rva` first.

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
results = find_string_rvas("chrome.dll", ["enableCanvasNoise", "webglRenderer"])
results = find_string_rvas("chrome.dll", ["宽字符"], encoding="utf16le")
```

<!-- return-keys: find_string_rvas = needle, offset, rva, encoding -->
Rows: `needle`, `offset` (file offset), `rva`, `encoding`. A needle that is absent still gets a
row, with `offset` and `rva` set to `None`. Every occurrence is reported, so a string that
appears twice yields two rows.

```bash
fp binary find-string-rva chrome.dll "enableCanvasNoise,webglRenderer"
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

### xrefs_to_rva — cross-references to an RVA

**The range defaults to the whole section. Do not hand-pick one unless you mean to.** A partial
range returns fewer references, and an empty list from a partial scan is indistinguishable from
"nothing references this" — that exact mistake (a third of a 240 MB `.text`, read as "no
references") is why the default exists. Partial coverage is logged as a warning, and the CLI
prints the scanned extent with its percentage.

```python
from fridapilot.tools.pe_rva import section_range

refs = xrefs_to_rva("chrome.dll", 0x1044f64c)                    # whole .text
refs = xrefs_to_rva("chrome.dll", 0xfb3dfc0, section=".rdata", kinds=("ptr",))
refs = xrefs_to_rva(                                             # deliberately narrowed
    "chrome.dll",
    target_rva=0x1044f64c,
    scan_start_rva=0xc42a90,
    scan_end_rva=0xc43f95,
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

If that also finds nothing, the string may be **built inline** — Chromium emits
`movabs rcx, 0x6573696f4e747865` ("extNoise") and assembles it in registers, so there is no
operand pointing at `.rdata` to find. The little-endian immediate bytes are the characters in
order, so `find_text` locates it directly in `.text`; `xrefs_to_rva` structurally cannot.

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
fp binary xrefs-rva chrome.dll --target 0x1044f64c
fp binary xrefs-rva chrome.dll --target 0xfb3dfc0 --section .rdata --kinds ptr
fp binary xrefs-rva chrome.dll --target 0x1044f64c --start 0xc42a90 --end 0xc43f95
```


### function_bounds — exact function extent

```python
bounds = function_bounds("chrome.dll", 0xc43500)   # any RVA inside the function
```

<!-- return-keys: function_bounds = begin_rva, end_rva, size, unwind_info_rva -->
Returns `begin_rva`, `end_rva`, `size`, `unwind_info_rva`, or `None` when the RVA is not inside
any `RUNTIME_FUNCTION` — which happens for leaf functions (the ABI lets them omit unwind data)
and for anything in a 32-bit image, where there is no `.pdata` at all. `None` therefore means
"no entry", not "not a function".

```bash
fp binary func-bounds chrome.dll --rva 0xc43500
```

### disassemble_rva — RVA-aware disassembly

```python
result = disassemble_rva("chrome.dll", 0xc43550, count=20)
result = disassemble_rva("chrome.dll", rva=0xc43550, count=20,
                         symbols={0x1044f640: "g_config"}, resolve_rip=True)
```

<!-- return-keys: disassemble_rva = image_base, start_rva, lines -->
Returns `image_base`, `start_rva`, `lines`; each line has `rva`, `va`, `bytes_hex`, `mnemonic`,
`op_str`, `note`. `note` carries the resolved rip target RVA and, when `symbols` is supplied,
the matching name. On an RVA with no backing file data (BSS) the result carries an `error` key
and an empty `lines` list.

The parameters are `rva` and `count` — not `start_rva` / `num_instructions`.

```bash
fp binary disasm-rva chrome.dll --rva 0xc43550 --count 20
fp binary disasm-rva chrome.dll -r 0xc43550 -n 60 --symbols 0x1044f640:g_config
```

### field_refs — struct field access

Answers "who touches `this->field_` at +0xB0?".

```python
refs = field_refs("chrome.dll", 0xB0, scan_start_rva=0xc42a90,
                  scan_end_rva=0xc43f95, kind="both")
refs = field_refs("chrome.dll", 0x78)      # range defaults to .text
```

Rows: `from_rva`, `mnemonic`, `op_str`, `kind` (`read`/`write`), `size`. Matches `mod=01`
(disp8) as well as `mod=10` (disp32), so small offsets are not silently dropped, and includes
the SSE stores MSVC emits for adjacent members.

```bash
fp binary field-refs chrome.dll --offset 0xB0 --start-rva 0xc42a90 --end-rva 0xc43f95
fp binary field-refs chrome.dll --offset 0x78 --kind write --with-func
```

Note the option names: `--offset`, `--start-rva`, `--end-rva` (not `--start` / `--end`).

### map_refs_to_functions — many targets, one pass

```python
result = map_refs_to_functions(
    "chrome.dll",
    targets={"enableCanvasNoise": 0xfcae886, "webglRenderer": 0xfcba225},
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
fp binary map-refs chrome.dll --strings "enableCanvasNoise,webglRenderer"
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
img.in_file(0x1044f640)    # False for uninitialised .data
img.section_of(0xc43550)   # ".text"
img.exception_table()      # [(begin_rva, end_rva, unwind_rva), ...] - cached, sorted
img.function_at(0xc43500)  # -> (begin_rva, end_rva, unwind_rva) | None, binary search
```

`exception_table()` yields **three**-element tuples and is empty for images without `.pdata`.
It is parsed once per `PEImage` and bounded by `min(VirtualSize, SizeOfRawData)`, so
file-alignment padding never shows up as entries — reuse one `PEImage` instead of constructing
it per lookup.

## Performance

Measured with the current implementation on ntdll.dll (1.5 MB `.text`, 5650 `.pdata` entries):
a full `.text` rip scan takes ≈4 s per target, and `map_refs_to_functions` costs the same ≈4 s
for *all* targets together.

Cost scales with the scanned byte range, so a full sweep of a ~100 MB `.text` is minutes, not
seconds. Practical order of work:

1. `find-string-rva` (fast, whole-file `bytes.find`)
2. `xrefs-rva` scoped to a few hundred KB when you can guess the region
3. `func-bounds` to pin the function, then `disasm-rva` / `field-refs` inside it
4. `map-refs` when you have N targets — never loop `xrefs-rva` N times over the same range

## Gotchas

- **Pass RVAs, not file offsets or VAs.** The `disassemble` command's `--address` is a file
  offset; every `*-rva` command and every `pe_rva` function takes an RVA. `PEImage.rva_to_off` /
  `off_to_rva` convert, and the delta differs per section.

- **`.pdata` is x64-only.** On a 32-bit image `function_bounds` returns `None`, `exception_table`
  is empty, and `xrefs_to_rva` relies entirely on pass B (`scan_gaps=True`, the default).
- **`rip` finding nothing is not proof of absence.** Try `ptr` on `.rdata`, and widen the range.
- Heuristics worth knowing, not guarantees: libc++ `std::string` stores up to 22 `char`s inline
  before heap-allocating, so read the SSO flag byte before dereferencing; and a `movzx byte +
  test + jne` on a global in Chromium is often PGO hot/cold splitting rather than the real
  feature gate, so follow the writes (`field_refs`, `xrefs_to_rva` with `kinds=("rip",)`) before
  concluding you found the switch.
