---
name: fridapilot-pe-analysis
description: |
  Use FridaPilot's PE binary analysis tools for reverse engineering Windows DLLs and EXEs — 
  especially large Chromium-based binaries (chrome.dll, electron apps). Trigger this skill when
  the user wants to: find cross-references to a global variable or string in a PE binary,
  disassemble a function at a specific RVA, find who reads/writes a struct field at [reg+offset],
  locate string RVAs in a PE, get function boundaries from .pdata, or map multiple targets to
  their referencing functions in one scan. Also trigger when the user mentions "xref", "RVA",
  "chrome.dll analysis", "reverse engineer DLL", "find references to address", "disassemble at
  offset", "patch chrome.dll", "Chromium kernel reverse engineering", "fingerprint browser analysis",
  or any PE binary reverse engineering task. This skill is especially valuable for binaries over
  100MB where IDA/Ghidra are slow — FridaPilot's RVA-aware tools handle 280MB chrome.dll in seconds.
---

# FridaPilot PE Binary Analysis

FridaPilot provides RVA-aware static analysis tools for x86-64 PE binaries. These tools correctly handle ImageBase, section alignment, and .pdata function boundaries — critical for analyzing Chromium's 280MB chrome.dll where standard tools fail.

## Installation

```bash
pip install -e D:\work\FridaPilot
```

## Core Workflow

The typical reverse engineering workflow with FridaPilot:

```
1. find_string_rvas()  → locate config key strings by name → get their RVAs
2. xrefs_to_rva()      → find code that references those strings → get function RVAs
3. function_bounds()   → get exact function boundaries from .pdata
4. disassemble_rva()   → disassemble the function with correct ImageBase
5. field_refs()        → find who reads/writes a specific struct field
```

## Python SDK

All tools are importable as Python functions:

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

## Tool Reference

### 1. find_string_rvas — Locate strings in PE

Find the RVA of known strings (config keys, error messages, file names).

```python
results = find_string_rvas("chrome.dll", ["enableCanvasNoise", "webglRenderer", "fingerprint-config"])
# Returns: [{"needle": "enableCanvasNoise", "rva": 0xfcae886, "section": ".rdata", "offset": 0xfc9e886}, ...]
```

CLI: `fp binary find-string-rva chrome.dll "enableCanvasNoise" "webglRenderer"`

### 2. xrefs_to_rva — Cross-reference scan

Find all code that references a specific RVA (string, global variable, function).

```python
refs = xrefs_to_rva(
    "chrome.dll",
    target_rva=0x1044f64c,          # the global variable address
    scan_start_rva=0xc42a90,        # function start (or broader range)
    scan_end_rva=0xc43f95,          # function end
    kinds=("rip", "call", "jmp"),   # what reference types to find
    verify=True,                     # capstone verification (recommended)
)
# Returns: [{"from_rva": 0xc43563, "mnemonic": "cmp", "op_str": "byte ptr [rip + ...]",
#            "target_rva": 0x1044f64c, "kind": "rip", "size": 7}, ...]
```

**Kinds**: `rip` (RIP-relative memory operand), `call` (E8 rel32), `jmp` (E9/EB), `imm64` (movabs), `ptr` (raw 8-byte VA in data), `rva32` (raw 4-byte RVA)

**For whole-.text scan**, use the section bounds:
```python
# Scan entire .text section (slow on 280MB DLL — ~10 minutes)
refs = xrefs_to_rva("chrome.dll", 0xfcae886, 0x1000, 0x10000000, kinds=("rip",))
```

CLI: `fp binary xrefs-rva chrome.dll 0xfcae886 --start 0xc42a90 --end 0xc43f95`

### 3. function_bounds — Get exact function boundaries

Uses x64 .pdata (RUNTIME_FUNCTION) table for precise function start/end.

```python
bounds = function_bounds("chrome.dll", 0xc43500)  # any RVA inside the function
# Returns: {"begin_rva": 0xc42a90, "end_rva": 0xc43f95, "size": 5381, "unwind_info_rva": 0xf4d1234}
# Returns None if RVA is not inside any RUNTIME_FUNCTION
```

CLI: `fp binary func-bounds chrome.dll 0xc43500`

### 4. disassemble_rva — RVA-aware disassembly

Disassemble with correct ImageBase, RIP-relative target annotations, and call target resolution.

```python
result = disassemble_rva("chrome.dll", start_rva=0xc43550, num_instructions=20)
# Returns: {"image_base": 0x180000000, "start_rva": 0xc43550,
#           "lines": [{"rva": 0xc43550, "va": 0x180c43550, "bytes_hex": "803d...",
#                       "mnemonic": "cmp", "op_str": "byte ptr [rip + 0xf80c0f0]",
#                       "note": "→ .data 0x1044f640"}, ...]}
```

CLI: `fp binary disasm-rva chrome.dll 0xc43550 --count 20`

### 5. field_refs — Find struct field access

Find code that reads or writes `[register + offset]` — answers "who accesses this->field_ at +0x50?"

```python
refs = field_refs(
    "chrome.dll",
    offset=0x50,                    # struct field offset
    scan_start_rva=0xc42a90,
    scan_end_rva=0xc43f95,
    kind="both",                    # "read", "write", or "both"
)
# Returns: [{"from_rva": 0xc43xxx, "mnemonic": "mov", "op_str": "rax, [rdi + 0x50]",
#            "kind": "read", "size": 4}, ...]
```

CLI: `fp binary field-refs chrome.dll 0x50 --start 0xc42a90 --end 0xc43f95 --kind both`

### 6. map_refs_to_functions — Batch multi-target scan

Map many target RVAs to their referencing functions in ONE pass (avoids N × xrefs_to_rva).

```python
result = map_refs_to_functions(
    "chrome.dll",
    targets={
        "enableCanvasNoise": 0xfcae886,
        "webglRenderer": 0xfcba225,
        "fingerprint-config": 0xf4c5017,
    },
    scan_start_rva=0x1000,
    scan_end_rva=0x10000000,
)
# Returns: {"functions": [{begin_rva, end_rva, size, labels: [...], refs: [...]}],
#           "orphans": [...], "unreferenced": [...], "scanned_bytes": int}
```

CLI: `fp binary map-refs chrome.dll --prefix 0xfcae886=enableCanvasNoise 0xfcba225=webglRenderer`

### 7. PEImage — Low-level PE access

```python
img = PEImage("chrome.dll")
img.image_base          # 0x180000000
img.is_64bit            # True
img.rva_to_off(0x1000)  # file offset
img.off_to_rva(0x400)   # RVA
img.read_rva(0xc43550, 64)  # read 64 bytes at RVA
img.section_of(0xc43550)    # ".text"
img.exception_table()       # [(begin_rva, end_rva), ...] from .pdata
```

## Important Notes

- **RVA vs file offset vs VA**: FridaPilot handles all conversions. Always pass RVA to functions, not file offsets or VAs.
- **Large binaries**: Full .text scan of 280MB chrome.dll takes ~10 minutes per target. Use `function_bounds()` first to narrow the scan range.
- **.pdata coverage**: x64 PE images have .pdata with exact function boundaries. `xrefs_to_rva` uses this for precise disassembly (Pass A) plus displacement scan for gaps (Pass B).
- **Chromium-specific**: libc++ std::string has SSO (small string optimization) — inline buffer for ≤22 chars, heap-allocated for longer. Read the SSO flag byte before interpreting string data.
- **Byte flag patterns**: `movzx byte + test + jne` in Chromium is often trace-guided hot/cold splitting, not a real conditional gate. The actual gate logic may be elsewhere.
