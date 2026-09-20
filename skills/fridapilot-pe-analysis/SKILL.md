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
1. find_string_rvas()        locate config keys / messages by content  -> RVAs
2. xrefs_to_rva()            find the code that references them        -> from_rva
3. function_bounds()         exact enclosing function from .pdata      -> begin/end
4. disassemble_rva()         read the function with correct ImageBase
5. field_refs()              find accesses to this->field_ at +offset
```

Use `map_refs_to_functions()` instead of step 2 when you have many targets: it scans once and
groups by `.pdata` function.

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

### xrefs_to_rva — cross-references to an RVA

```python
refs = xrefs_to_rva(
    "chrome.dll",
    target_rva=0x1044f64c,
    scan_start_rva=0xc42a90,
    scan_end_rva=0xc43f95,
    kinds=("rip", "call", "jmp"),
    verify=True,
    scan_gaps=True,
)
```

<!-- return-keys: xrefs_to_rva = from_rva, mnemonic, op_str, target_rva, kind, size -->
Rows: `from_rva`, `mnemonic`, `op_str`, `target_rva`, `kind`, `size`.

Kinds: `rip` (rip-relative memory operand), `call` (`E8 rel32`), `jmp` (`E9 rel32` / `EB rel8`),
`imm64` (`movabs r64, ImageBase+rva`), `ptr` (raw 8-byte VA in data), `rva32` (raw 4-byte RVA).

`ptr` matters for tables: Chromium collects `const char*` into `.rdata` arrays and only LEAs
the array base, so individual strings have no rip reference at all. If `rip` finds nothing for
a string that is obviously used, rescan `.rdata` with `kinds=("ptr",)`.

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
cost of missing references outside known functions.

```bash
fp binary xrefs-rva chrome.dll --target 0x1044f64c --start 0xc42a90 --end 0xc43f95
fp binary xrefs-rva chrome.dll --target 0xfb3dfc0 --start 0xf545000 --end 0x11394000 --kinds ptr
fp binary xrefs-rva chrome.dll --target 0x1044f64c --start 0x1000 --end 0xf545000 --pdata-only
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
    scan_start_rva=0x1000,
    scan_end_rva=0xf545000,
    kinds=("rip",),
)
```

<!-- return-keys: map_refs_to_functions = functions, orphans, unreferenced, scanned_bytes -->
Returns `functions` (each with `begin_rva`, `end_rva`, `size`, `labels`, `refs`, sorted by how
many distinct labels they use), `orphans` (references outside any `.pdata` entry),
`unreferenced` (labels nothing pointed at) and `scanned_bytes`.

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

- **Pass RVAs, not file offsets or VAs.** `fp binary disassemble --address` takes a file offset;
  every `*-rva` command and every `pe_rva` function takes an RVA. `PEImage.rva_to_off` /
  `off_to_rva` convert, and the delta differs per section.
- **`.pdata` is x64-only.** On a 32-bit image `function_bounds` returns `None`, `exception_table`
  is empty, and `xrefs_to_rva` relies entirely on pass B (`scan_gaps=True`, the default).
- **`rip` finding nothing is not proof of absence.** Try `ptr` on `.rdata`, and widen the range.
- Heuristics worth knowing, not guarantees: libc++ `std::string` stores up to 22 `char`s inline
  before heap-allocating, so read the SSO flag byte before dereferencing; and a `movzx byte +
  test + jne` on a global in Chromium is often PGO hot/cold splitting rather than the real
  feature gate, so follow the writes (`field_refs`, `xrefs_to_rva` with `kinds=("rip",)`) before
  concluding you found the switch.
