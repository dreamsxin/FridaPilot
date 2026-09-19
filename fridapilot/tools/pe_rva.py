"""RVA-aware PE analysis tools (ImageBase-correct disassembly & xrefs).

The base ``binary_analysis.disassemble`` / ``xrefs_to`` treat the given address
as BOTH a file offset AND a virtual address. That is only correct when a
section's RVA equals its file offset and ImageBase is 0. For real PEs — e.g. a
289 MB ``chrome.dll`` with ImageBase ``0x180000000`` and ``.text`` RVA ``0x1000``
vs raw offset ``0x600`` — rip-relative references and call/jmp targets resolve to
garbage, which silently misleads reverse engineering.

This module maps between RVA / VA / file offset through the PE section table so
disassembly, string location and cross-references are accurate. It captures the
general workflow used to reverse chrome.dll's fingerprint logic and is reusable
for any large, non-trivially-laid-out PE.

No LLM dependency. Requires: pefile, capstone.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class PEImage:
    """RVA/VA/file-offset aware PE image.

    Example:
        img = PEImage("chrome.dll")
        img.image_base                 # 0x180000000
        img.rva_to_off(0x3226410)      # RVA -> file offset via section table
        img.read_rva(0x10b2d260, 64)   # bytes at an RVA (None if BSS/unmapped)
        img.in_file(0x10b2d260)        # False for uninitialized .data (BSS)
    """

    def __init__(self, path: str | Path):
        import pefile

        self.path = str(path)
        self._pe = pefile.PE(self.path, fast_load=True)
        self.image_base = self._pe.OPTIONAL_HEADER.ImageBase
        self.is_64bit = self._pe.FILE_HEADER.Machine == 0x8664
        self._pdata: list[tuple[int, int, int]] | None = None
        self._sections: list[tuple[int, int, int, int, str]] = []
        for s in self._pe.sections:
            self._sections.append((
                s.VirtualAddress, s.Misc_VirtualSize,
                s.PointerToRawData, s.SizeOfRawData,
                s.Name.rstrip(b"\x00").decode("latin1"),
            ))
        with open(self.path, "rb") as f:
            self._data = f.read()

    # ── address mapping ──
    def rva_to_off(self, rva: int) -> int | None:
        """RVA -> file offset, or None if the RVA is in BSS / unmapped."""
        for va, vs, praw, rsize, _ in self._sections:
            if va <= rva < va + max(vs, rsize):
                delta = rva - va
                if delta < rsize:
                    return praw + delta
        return None

    def off_to_rva(self, off: int) -> int | None:
        """File offset -> RVA, or None if not inside any raw section."""
        for va, _vs, praw, rsize, _ in self._sections:
            if praw <= off < praw + rsize:
                return va + (off - praw)
        return None

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def read_rva(self, rva: int, n: int) -> bytes | None:
        """Read n bytes at an RVA, clamped to the containing section boundary."""
        off = self.rva_to_off(rva)
        if off is None:
            return None
        # Clamp to section boundary to avoid cross-section reads
        for va, _vs, praw, rsize, _ in self._sections:
            if praw <= off < praw + rsize:
                available = (praw + rsize) - off
                actual = min(n, available)
                return self._data[off:off + actual]
        return self._data[off:off + n]

    def in_file(self, rva: int) -> bool:
        """True if the RVA has backing file data (False for BSS/uninitialized)."""
        return self.rva_to_off(rva) is not None

    def section_of(self, rva: int) -> str:
        for va, vs, _praw, rsize, name in self._sections:
            if va <= rva < va + max(vs, rsize):
                return name
        return ""

    def exception_table(self) -> list[tuple[int, int, int]]:
        """``.pdata`` RUNTIME_FUNCTION entries as (begin_rva, end_rva, unwind_rva).

        Empty for images without ``.pdata`` (32-bit PE). Bounds use
        ``min(VirtualSize, SizeOfRawData)``: SizeOfRawData is file-aligned, so
        walking it would parse alignment padding as entries (and can read past the
        section when the size is not a multiple of 12). The table is already sorted
        by BeginAddress and is cached per image — callers may scan it repeatedly.
        """
        if self._pdata is not None:
            return self._pdata
        import struct as _st
        entries: list[tuple[int, int, int]] = []
        for _va, vs, praw, rsize, name in self._sections:
            if name != ".pdata":
                continue
            size = min(vs, rsize) if vs else rsize
            for i in range(size // 12):
                begin, end, unwind = _st.unpack_from("<III", self._data, praw + i * 12)
                if begin == 0 and end == 0:
                    break
                entries.append((begin, end, unwind))
            break
        self._pdata = entries
        return entries

    def function_at(self, rva: int) -> tuple[int, int, int] | None:
        """Containing RUNTIME_FUNCTION for an RVA (binary search), or None."""
        table = self.exception_table()
        lo, hi = 0, len(table) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            begin, end, unwind = table[mid]
            if rva < begin:
                hi = mid - 1
            elif rva >= end:
                lo = mid + 1
            else:
                return begin, end, unwind
        return None



def find_string_rvas(
    binary_path: str | Path,
    needles: list[str],
    encoding: str = "ascii",
) -> list[dict[str, Any]]:
    """Locate exact strings and report their RVA (and file offset).

    Args:
        needles: exact substrings to locate.
        encoding: "ascii" or "utf16le".

    Returns:
        List of {needle, offset, rva, encoding}; offset/rva are None if absent.
    """
    img = PEImage(binary_path)
    data = img._data
    out: list[dict[str, Any]] = []
    for needle in needles:
        pat = needle.encode("utf-8") if encoding == "ascii" else needle.encode("utf-16-le")
        start = 0
        found = 0
        while True:
            idx = data.find(pat, start)
            if idx < 0:
                break
            out.append({
                "needle": needle, "offset": idx,
                "rva": img.off_to_rva(idx), "encoding": encoding,
            })
            found += 1
            start = idx + 1
        if found == 0:
            out.append({"needle": needle, "offset": None, "rva": None, "encoding": encoding})
    return out


def disassemble_rva(
    binary_path: str | Path,
    rva: int,
    count: int = 40,
    symbols: dict[int, str] | None = None,
    resolve_rip: bool = True,
) -> dict[str, Any]:
    """RVA-aware disassembly with ImageBase-correct VA and reference annotation.

    Unlike ``disassemble()``, the start is an RVA; instructions decode at
    VA = ImageBase + RVA, so rip-relative operands and call/jmp targets resolve
    correctly. Each line carries the resolved target RVA and, when ``symbols``
    is given, the symbolic name.

    Args:
        rva: start RVA (not a file offset).
        count: max instructions.
        symbols: optional {rva: name} to tag call/jmp/rip targets.
        resolve_rip: annotate rip-relative operands with their target RVA.

    Returns:
        {image_base, start_rva, lines: [{rva, va, bytes_hex, mnemonic, op_str, note}]}
    """
    import capstone
    from capstone import x86 as cx86

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    symbols = symbols or {}
    data = img.read_rva(rva, count * 16)
    if data is None:
        return {"image_base": img.image_base, "start_rva": rva,
                "error": "RVA 0x%x has no backing file data (BSS/unmapped)" % rva,
                "lines": []}
    lines: list[dict[str, Any]] = []
    for insn in md.disasm(data, img.rva_to_va(rva)):
        cur_rva = insn.address - img.image_base
        note = ""
        if insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
            tgt_rva = int(insn.op_str, 16) - img.image_base
            name = symbols.get(tgt_rva, "")
            note = ("<<< %s 0x%x" % (name, tgt_rva)) if name else ("-> 0x%x" % tgt_rva)
        elif resolve_rip and "rip" in insn.op_str:
            for op in insn.operands:
                if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                    tgt_rva = insn.address + insn.size + op.mem.disp - img.image_base
                    name = symbols.get(tgt_rva, "")
                    note = "; [rip]-> RVA 0x%x%s" % (tgt_rva, (" " + name) if name else "")
                    break
        lines.append({
            "rva": cur_rva, "va": insn.address, "bytes_hex": insn.bytes.hex(),
            "mnemonic": insn.mnemonic, "op_str": insn.op_str, "note": note,
        })
        if len(lines) >= count:
            break
    return {"image_base": img.image_base, "start_rva": rva, "lines": lines}


def function_bounds(
    binary_path: str | Path,
    rva: int,
) -> dict[str, Any] | None:
    """Exact function bounds for an RVA, read from the x64 ``.pdata`` table.

    Every non-leaf x64 function has a ``RUNTIME_FUNCTION`` entry (12 bytes:
    BeginAddress / EndAddress / UnwindInfoAddress, all RVAs) used for SEH unwinding.
    Looking the RVA up there is exact and instant — far better than scanning
    backwards for ``push rbp`` / ``sub rsp, N``, which is unreliable on optimised
    code with shrink-wrapped or split prologues.

    The table is sorted by BeginAddress, so this is a binary search.

    Returns {begin_rva, end_rva, size, unwind_info_rva} or None when the RVA is a
    leaf function (no entry) or outside .pdata coverage.
    """
    img = PEImage(binary_path)
    found = img.function_at(rva)
    if found is None:
        return None
    begin, end, unwind = found
    return {"begin_rva": begin, "end_rva": end,
            "size": end - begin, "unwind_info_rva": unwind}



def field_refs(
    binary_path: str | Path,
    offset: int,
    scan_start_rva: int | None = None,
    scan_end_rva: int | None = None,
    kind: str = "both",
    verify: bool = True,
) -> list[dict[str, Any]]:
    """Find reads/writes of a struct field at ``[reg + offset]``.

    The practical question when reverse-engineering a C++ object: "who writes
    ``this->field_`` at +0xB0?". Answering it by hand is where RVA/file-offset
    conversion bugs bite — each section has its own ``VirtualAddress`` vs
    ``PointerToRawData`` delta, so a single constant is wrong the moment you cross
    a section boundary. This routine goes through the section table.

    Matches x86-64 ``mod=10`` (disp32) memory operands:
      write  ``REX.W 89 /r disp32``   mov [reg+off], r64
             ``REX.W C7 /r disp32``   mov [reg+off], imm32
             ``REX.W 01/29/31/09/21`` add/sub/xor/or/and [reg+off], r64
      read   ``REX.W 8B /r disp32``   mov r64, [reg+off]
             ``REX.W 03/2B/33/0B/23`` add/sub/xor/or/and r64, [reg+off]
             ``REX.W 3B/85``          cmp/test

    Args:
        offset: the disp32 value (struct field offset).
        scan_start_rva/scan_end_rva: default to the whole ``.text``.
        kind: "read", "write" or "both".
        verify: decode each candidate with capstone (filters partial-instruction
            false positives, which is exactly how the hand-rolled version failed).

    Returns list of {from_rva, mnemonic, op_str, kind, size}.
    """
    import struct

    import capstone

    WRITE_OPS = {0x89: "mov", 0xC7: "mov", 0x01: "add", 0x29: "sub",
                 0x31: "xor", 0x09: "or", 0x21: "and"}
    READ_OPS = {0x8B: "mov", 0x03: "add", 0x2B: "sub", 0x33: "xor",
                0x0B: "or", 0x23: "and", 0x3B: "cmp", 0x85: "test"}

    img = PEImage(binary_path)
    if scan_start_rva is None or scan_end_rva is None:
        for va, vs, _praw, rsize, name in img._sections:
            if name == ".text":
                scan_start_rva = scan_start_rva if scan_start_rva is not None else va
                scan_end_rva = scan_end_rva if scan_end_rva is not None else va + max(vs, rsize)
                break
    if scan_start_rva is None or scan_end_rva is None:
        return []

    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return []

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    base = img.image_base
    want_w = kind in ("write", "both")
    want_r = kind in ("read", "both")
    disp_bytes = struct.pack("<i", offset)

    out: list[dict[str, Any]] = []
    n = len(data)
    # An x86-64 memory operand encodes the displacement in one of three widths and the
    # assembler always picks the shortest that fits:
    #   mod=00  no disp    (offset 0; rm=101 means rip-relative, not a struct field)
    #   mod=01  disp8      (-128..127)  <-- every struct offset <= 0x7F lands here
    #   mod=10  disp32
    # Matching only mod=10 silently misses ALL small offsets, and the failure looks like
    # a clean zero-hit result — indistinguishable from "this field is never touched".
    # Observed on chrome.dll: `mov rcx,[rdi+0x78]` = 48 8B 4F 78 (mod=01).
    if offset == 0:
        want_mods = (0x00, 0x40, 0x80)
    elif -128 <= offset <= 127:
        want_mods = (0x40, 0x80)
    else:
        want_mods = (0x80,)
    disp8_byte = struct.pack("<b", offset) if -128 <= offset <= 127 else None

    # SSE moves are how MSVC initialises two adjacent 8-byte members in one go, and
    # how it copies small structs. They carry NO REX.W (the operand size comes from
    # the 0F escape opcode), so a scan that requires 0x48-0x4F never sees them.
    #   0F 11 /r   movups m128, xmm      store
    #   0F 29 /r   movaps m128, xmm      store
    #   0F 10 /r   movups xmm, m128      load
    #   0F 28 /r   movaps xmm, m128      load
    # An optional REX (0x40-0x4F) may precede 0F when xmm8-15 / r8-r15 are involved.
    SSE_W = {0x11: "movups", 0x29: "movaps"}
    SSE_R = {0x10: "movups", 0x28: "movaps"}


    def _classify(i: int):
        """-> (modrm_index, mnemonic, is_write) or None."""
        b0 = data[i]
        # REX.W + general-purpose op
        if 0x48 <= b0 <= 0x4F:
            opc = data[i + 1]
            if want_w and opc in WRITE_OPS:
                return i + 2, WRITE_OPS[opc], True
            if want_r and opc in READ_OPS:
                return i + 2, READ_OPS[opc], False
            # REX + 0F xx  (SSE with extended registers)
            if opc == 0x0F:
                s = data[i + 2]
                if want_w and s in SSE_W:
                    return i + 3, SSE_W[s], True
                if want_r and s in SSE_R:
                    return i + 3, SSE_R[s], False
            return None
        # bare REX (no W) + 0F xx
        if 0x40 <= b0 <= 0x47 and data[i + 1] == 0x0F:
            s = data[i + 2]
            if want_w and s in SSE_W:
                return i + 3, SSE_W[s], True
            if want_r and s in SSE_R:
                return i + 3, SSE_R[s], False
            return None
        # no prefix
        if b0 == 0x0F:
            s = data[i + 1]
            if want_w and s in SSE_W:
                return i + 2, SSE_W[s], True
            if want_r and s in SSE_R:
                return i + 2, SSE_R[s], False
        return None

    out: list[dict[str, Any]] = []
    n = len(data)
    covered_until = 0          # drop candidates that start inside an accepted instruction
    for i in range(n - 11):
        if i < covered_until:
            continue
        hit = _classify(i)
        if hit is None:
            continue
        modrm_at, mnem, is_w = hit
        modrm = data[modrm_at]
        mod = modrm & 0xC0
        if mod not in want_mods:
            continue
        rm = modrm & 0x07
        if mod == 0x00 and rm == 0x05:
            continue                       # rip-relative, not a struct field
        # rm=100 means a SIB byte sits between ModRM and the displacement
        disp_at = modrm_at + 2 if rm == 0x04 else modrm_at + 1
        if mod == 0x80:
            if data[disp_at:disp_at + 4] != disp_bytes:
                continue
        elif mod == 0x40:
            if disp8_byte is None or data[disp_at:disp_at + 1] != disp8_byte:
                continue
        # mod=00 with offset 0 needs no displacement check
        rva = scan_start_rva + i

        if verify:
            insn = next(iter(md.disasm(data[i:i + 16], base + rva)), None)
            if insn is None:
                continue
            if offset != 0 and ("0x%x" % abs(offset)) not in insn.op_str:
                continue
            covered_until = i + insn.size
            out.append({"from_rva": rva, "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str, "size": insn.size,
                        "kind": "write" if is_w else "read"})
        else:
            out.append({"from_rva": rva, "mnemonic": mnem,
                        "op_str": "[reg+0x%x]" % offset, "size": 0,
                        "kind": "write" if is_w else "read"})
    return out




def _iter_rip_refs(
    img: PEImage,
    md: Any,
    data: bytes,
    scan_start_rva: int,
    scan_end_rva: int,
    is_target: Any,
    verify: bool = True,
    scan_gaps: bool = True,
):
    """Yield (from_rva, target_rva, mnemonic, op_str, size) for rip-relative refs
    whose resolved target satisfies ``is_target(target_rva)``.

    Two complementary passes, because neither alone is enough:

    A. **Linear disassembly inside every ``.pdata`` RUNTIME_FUNCTION** intersecting
       the range. Function bounds are exact, so linear decoding cannot drift into
       inter-function data the way a whole-section sweep does, and capstone handles
       every encoding form. An opcode whitelist structurally cannot: measured on
       ntdll.dll, whitelisting caps recall at ~95% and the misses are systematic —
       ``F0`` (lock cmpxchg/inc/and on a global, i.e. exactly the singletons and
       refcounts one is looking for), ``66``/``F2``/``F3`` (word stores, movsd,
       movdqa/movdqu) and VEX/EVEX, all of which put prefixes ahead of the opcode.
       Padding or a jump table inside a function only costs a one-byte resync.

    B. **Opcode-agnostic disp32 scan over the ranges ``.pdata`` does not cover**
       (leaf functions, hand-written asm, packed code, 32-bit images, data
       sections). A rip operand always has ModRM mod=00 / rm=101 immediately before
       the 4-byte displacement, so candidates are found by displacement arithmetic
       instead of an opcode table, then confirmed by decoding from up to 8 bytes
       back (prefixes + 1-2 byte opcode + ModRM).

    Args:
        is_target: predicate on the resolved target RVA (equality for one target,
            set membership for many).
        verify: decode pass-B candidates with capstone. Pass A always decodes.
        scan_gaps: run pass B. False = strict ``.pdata``-only mode, which trades
            recall outside known functions for precision in data-heavy ranges.
    """
    import struct as _st

    from capstone import x86 as cx86

    base = img.image_base
    n = len(data)

    def rip_target(insn) -> int | None:
        for op in insn.operands:
            if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp - base
        return None

    # ── pass A: decode .pdata-covered functions ──
    covered: list[tuple[int, int]] = []
    for begin, end, _unwind in img.exception_table():
        if end <= scan_start_rva or begin >= scan_end_rva:
            continue
        lo, hi = max(begin, scan_start_rva), min(end, scan_end_rva)
        covered.append((lo, hi))
        pos = lo
        while pos < hi:
            progressed = False
            for insn in md.disasm(data[pos - scan_start_rva:hi - scan_start_rva],
                                  base + pos):
                progressed = True
                pos = insn.address - base + insn.size
                tgt = rip_target(insn)
                if tgt is not None and is_target(tgt):
                    yield (insn.address - base, tgt,
                           insn.mnemonic, insn.op_str, insn.size)
            if not progressed:
                pos += 1  # data byte inside the function: resync and continue

    if not scan_gaps:
        return

    # ── pass B: displacement scan over the uncovered remainder ──
    covered.sort()
    gaps: list[tuple[int, int]] = []
    cur = scan_start_rva
    for lo, hi in covered:
        if lo > cur:
            gaps.append((cur, lo))
        cur = max(cur, hi)
    if cur < scan_end_rva:
        gaps.append((cur, scan_end_rva))

    for lo, hi in gaps:
        for i in range(max(lo - scan_start_rva, 1), min(hi - scan_start_rva, n - 4)):
            if (data[i - 1] & 0xC7) != 0x05:  # ModRM: mod=00, rm=101 (rip+disp32)
                continue
            disp = _st.unpack_from("<i", data, i)[0]
            end_rva = scan_start_rva + i + 4
            for imm in (0, 1, 2, 4):  # trailing immediate widths
                if not is_target(end_rva + imm + disp):
                    continue
                if not verify:
                    yield (scan_start_rva + i - 2, end_rva + imm + disp,
                           "(unverified)", "[rip%+d]" % disp, 0)
                    break
                # Walk back from the longest possible encoding: prefixes sit ahead
                # of the opcode, so the outermost start that still ends at this
                # displacement is the real instruction. Taking the innermost would
                # report the REX-less alias (``8B 05`` inside ``48 8B 05``), which
                # resolves to the same target but is not a real reference site.
                for back in range(8, 1, -1):
                    if i - back < 0:
                        continue
                    insn = next(iter(md.disasm(data[i - back:i - back + 16],
                                              base + scan_start_rva + i - back)), None)
                    if insn is None or insn.size < back + 4:
                        continue  # displacement not inside this instruction
                    tgt = rip_target(insn)
                    if tgt is not None and is_target(tgt):
                        yield (insn.address - base, tgt,
                               insn.mnemonic, insn.op_str, insn.size)
                        break
                break



def map_refs_to_functions(


    binary_path: str | Path,
    targets: dict[str, int],
    scan_start_rva: int,
    scan_end_rva: int,
    kinds: tuple[str, ...] = ("rip",),
) -> dict[str, Any]:
    """Map many target RVAs to the functions that reference them, in ONE pass.

    Answers "which functions consume these N strings, and which does each use?" —
    the practical shape of mapping a patched binary. Running ``xrefs_to_rva`` N times
    would rescan the whole section N times; this scans once and groups by the
    ``.pdata`` function that contains each reference.

    Args:
        targets: {label: rva}. Labels are free-form (usually the string itself).
        kinds: same vocabulary as ``xrefs_to_rva``; "rip" is the useful one here.

    Returns:
        {
          "functions": [{begin_rva, end_rva, size, labels: [...], refs: [{label, from_rva}]}],
          "orphans":   [{label, from_rva}],   # reference outside any .pdata entry
          "unreferenced": [label, ...],
          "scanned_bytes": int,
        }
    """
    import struct

    import capstone

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return {"functions": [], "orphans": [], "unreferenced": list(targets),
                "scanned_bytes": 0}


    base = img.image_base
    by_rva: dict[int, list[str]] = {}
    for label, rva in targets.items():
        by_rva.setdefault(rva, []).append(label)
    va_set = {base + r: r for r in by_rva}

    hits: list[tuple[int, int, int]] = []  # (from_rva, target_rva, insn_size)
    n = len(data)
    want_rip = "rip" in kinds
    want_ptr = "ptr" in kinds
    want_imm = "imm64" in kinds

    if want_rip:
        for from_rva, tgt, _mnem, _op, size in _iter_rip_refs(
                img, md, data, scan_start_rva, scan_end_rva, lambda t: t in by_rva):
            hits.append((from_rva, tgt, size))

    if want_imm or want_ptr:
        for i in range(n - 9):
            b0 = data[i]
            if want_imm and b0 in (0x48, 0x49) and 0xB8 <= data[i + 1] <= 0xBF:
                va = struct.unpack_from("<Q", data, i + 2)[0]
                if va in va_set:
                    hits.append((scan_start_rva + i, va_set[va], 10))
            if want_ptr:
                va = struct.unpack_from("<Q", data, i)[0]
                if va in va_set:
                    hits.append((scan_start_rva + i, va_set[va], 8))


    # drop refs that fall inside an earlier instruction (REX-less double reading)
    hits.sort()
    pruned: list[tuple[int, int]] = []
    covered = -1
    for from_rva, tgt, size in hits:
        if from_rva < covered:
            continue
        pruned.append((from_rva, tgt))
        covered = from_rva + size

    # group by .pdata function (PEImage caches the RUNTIME_FUNCTION table, so the
    # per-hit lookup is a binary search over an already-parsed list)
    funcs: dict[int, dict[str, Any]] = {}
    orphans: list[dict[str, Any]] = []
    referenced: set[int] = set()
    for from_rva, tgt in pruned:
        referenced.add(tgt)
        label = by_rva[tgt][0]
        fb = img.function_at(from_rva)
        if fb is None:
            orphans.append({"label": label, "from_rva": from_rva})
            continue
        begin, end, _unwind = fb

        entry = funcs.setdefault(begin, {
            "begin_rva": begin, "end_rva": end, "size": end - begin,
            "labels": [], "refs": [],
        })
        entry["refs"].append({"label": label, "from_rva": from_rva})
        if label not in entry["labels"]:
            entry["labels"].append(label)


    out_funcs = sorted(funcs.values(), key=lambda f: -len(f["labels"]))
    return {
        "functions": out_funcs,
        "orphans": orphans,
        "unreferenced": sorted(l for r, ls in by_rva.items() if r not in referenced
                               for l in ls),
        "scanned_bytes": n,
    }


def xrefs_to_rva(


    binary_path: str | Path,
    target_rva: int,
    scan_start_rva: int,
    scan_end_rva: int,
    kinds: tuple[str, ...] = ("rip", "call", "jmp"),
    verify: bool = True,
    scan_gaps: bool = True,
) -> list[dict[str, Any]]:
    """RVA-aware cross-reference scan within [scan_start_rva, scan_end_rva).

    Rip-relative references are found by **disassembling each ``.pdata``
    RUNTIME_FUNCTION**, falling back to an **opcode-agnostic displacement scan**
    where ``.pdata`` has no coverage (see ``_iter_rip_refs``). A single linear
    ``md.disasm()`` over a whole ``.text`` is not usable: it terminates at the first
    non-instruction byte (jump tables, alignment padding, constant pools), so on a
    245 MB chrome.dll almost everything past the first gap is lost. Function bounds
    give the synchronisation points that a flat sweep lacks. Absolute kinds (call /
    jmp / imm64 / ptr / rva32) stay pure byte scans — their encodings are fixed.

    Kinds:
      - "rip":   rip-relative operand (LEA / MOV / CMP / LOCK CMPXCHG / SSE / ...)
      - "call":  direct ``E8 rel32``
      - "jmp":   direct ``E9 rel32`` (and short ``EB rel8``)
      - "imm64": ``MOV r64, imm64`` loading ImageBase+target_rva
      - "ptr":   raw 8-byte VA (pointer tables, vtables, kSwitchNames[]-style arrays)
      - "rva32": raw 4-byte RVA

    ``ptr`` is essential for switch-name tables: Chromium collects ``const char*``
    into a ``.rdata`` array and only LEAs the array base, so the individual strings
    have no rip-relative reference at all.

    Args:
        verify: decode displacement-scan candidates with capstone to confirm the
            operand and instruction length. The ``.pdata`` pass always decodes.
            False is faster and noisier.
        scan_gaps: also scan the ranges ``.pdata`` does not cover (leaf functions,
            hand-written asm, packed code, 32-bit images, data sections). False =
            strict ``.pdata``-only mode: fewer false positives when the range spans
            data, at the cost of missing references outside known functions.

    Returns list of {from_rva, mnemonic, op_str, target_rva, kind, size}.
    """
    import struct

    import capstone

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return []

    base = img.image_base
    target_va = base + target_rva
    want = set(kinds)
    out: list[dict[str, Any]] = []
    n = len(data)

    seen: set[tuple[int, str]] = set()

    def _emit(from_rva: int, kind: str, mnemonic: str, op_str: str, size: int = 0):
        key = (from_rva, kind)
        if key in seen:
            return
        seen.add(key)
        out.append({"from_rva": from_rva, "mnemonic": mnemonic, "op_str": op_str,
                    "target_rva": target_rva, "kind": kind, "size": size})

    # ── rip-relative ──
    if "rip" in want:
        for from_rva, _tgt, mnem, op_str, size in _iter_rip_refs(
                img, md, data, scan_start_rva, scan_end_rva,
                lambda t: t == target_rva, verify=verify, scan_gaps=scan_gaps):
            _emit(from_rva, "rip", mnem, op_str, size)

    # ── absolute encodings: fixed-shape byte scans ──
    for i in range(n - 9):
        b0 = data[i]

        # ── direct call / jmp rel32 ──
        if (b0 == 0xE8 and "call" in want) or (b0 == 0xE9 and "jmp" in want):
            rel = struct.unpack_from("<i", data, i + 1)[0]
            if scan_start_rva + i + 5 + rel == target_rva:
                kind = "call" if b0 == 0xE8 else "jmp"
                _emit(scan_start_rva + i, kind, kind, "0x%x" % target_va)


        # ── short jmp rel8 ──
        if b0 == 0xEB and "jmp" in want:
            rel = struct.unpack_from("<b", data, i + 1)[0]
            if scan_start_rva + i + 2 + rel == target_rva:
                _emit(scan_start_rva + i, "jmp", "jmp", "0x%x" % target_va)

        # ── mov r64, imm64 ──
        if "imm64" in want and (b0 in (0x48, 0x49)) and 0xB8 <= data[i + 1] <= 0xBF:
            if struct.unpack_from("<Q", data, i + 2)[0] == target_va:
                _emit(scan_start_rva + i, "imm64", "movabs", "0x%x" % target_va)

        # ── raw pointers ──
        if "ptr" in want and struct.unpack_from("<Q", data, i)[0] == target_va:
            _emit(scan_start_rva + i, "ptr", "(data)", "qword 0x%x" % target_va)
        if "rva32" in want and struct.unpack_from("<I", data, i)[0] == target_rva:
            _emit(scan_start_rva + i, "rva32", "(data)", "dword 0x%x" % target_rva)

    out.sort(key=lambda r: r["from_rva"])

    # Drop candidates that fall *inside* an earlier instruction. The displacement
    # scan can decode a shorter instruction starting one byte into a longer real one
    # (e.g. ``shufps`` out of the middle of ``mov byte [rip+disp], 1``); both resolve
    # to the same target, but only the outermost decode is a real reference. This
    # needs the real instruction to be found first, which is why the .pdata pass
    # (exact bounds, exact sizes) runs before the byte scan.
    deduped: list[dict[str, Any]] = []
    covered_until = -1
    for rec in out:
        if rec["kind"] == "rip" and rec["from_rva"] < covered_until:
            continue
        deduped.append(rec)
        if rec.get("size"):
            covered_until = rec["from_rva"] + rec["size"]

    return deduped



