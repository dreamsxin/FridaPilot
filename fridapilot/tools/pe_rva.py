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
        off = self.rva_to_off(rva)
        if off is None:
            return None
        return self._data[off:off + n]

    def in_file(self, rva: int) -> bool:
        """True if the RVA has backing file data (False for BSS/uninitialized)."""
        return self.rva_to_off(rva) is not None

    def section_of(self, rva: int) -> str:
        for va, vs, _praw, rsize, name in self._sections:
            if va <= rva < va + max(vs, rsize):
                return name
        return ""


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
    import struct

    img = PEImage(binary_path)
    pdata = None
    for va, vs, praw, rsize, name in img._sections:
        if name == ".pdata":
            pdata = (va, min(vs, rsize), praw)
            break
    if pdata is None:
        return None
    _pva, psize, ppraw = pdata
    count = psize // 12
    blob = img._data[ppraw:ppraw + count * 12]

    lo, hi = 0, count - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        begin, end, unwind = struct.unpack_from("<III", blob, mid * 12)
        if rva < begin:
            hi = mid - 1
        elif rva >= end:
            lo = mid + 1
        else:
            return {"begin_rva": begin, "end_rva": end,
                    "size": end - begin, "unwind_info_rva": unwind}
    return None


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
    from capstone import x86 as cx86

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

    RIP_OPCODES = frozenset((
        0x8D, 0x8B, 0x89, 0x63, 0x85, 0xFF, 0xC7, 0x83, 0x81,
        0x03, 0x2B, 0x3B, 0x33, 0x0B, 0x23,
        0x01, 0x29, 0x39, 0x31, 0x09, 0x21,
    ))

    hits: list[tuple[int, int, int]] = []  # (from_rva, target_rva, insn_size)
    n = len(data)
    want_rip = "rip" in kinds
    want_ptr = "ptr" in kinds
    want_imm = "imm64" in kinds

    for i in range(n - 9):
        b0 = data[i]
        if want_rip:
            for pfx in (1, 0):
                if pfx and not (0x40 <= b0 <= 0x4F):
                    continue
                op_i = i + pfx
                if op_i + 6 >= n:
                    continue
                opc = data[op_i]
                if opc == 0x0F:
                    if (data[op_i + 2] & 0xC7) != 0x05:
                        continue
                    disp_at, ilen = op_i + 3, (op_i + 7) - i
                elif opc in RIP_OPCODES:
                    if (data[op_i + 1] & 0xC7) != 0x05:
                        continue
                    disp_at, ilen = op_i + 2, (op_i + 6) - i
                else:
                    continue
                disp = struct.unpack_from("<i", data, disp_at)[0]
                cand = scan_start_rva + i
                for extra in (0, 1, 2, 4):
                    tgt = cand + ilen + extra + disp
                    if tgt not in by_rva:
                        continue
                    off = cand - scan_start_rva
                    insn = next(iter(md.disasm(data[off:off + 16], base + cand)), None)
                    if insn is None:
                        continue
                    real = None
                    for op in insn.operands:
                        if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                            real = insn.address + insn.size + op.mem.disp - base
                            break
                    if real in by_rva:
                        hits.append((cand, real, insn.size))
                    break
                else:
                    continue
                break
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

    # group by .pdata function. Load the RUNTIME_FUNCTION table once — calling
    # function_bounds() per hit would re-read the whole PE each time.
    pdata_blob = b""
    for va, vs, praw, rsize, name in img._sections:
        if name == ".pdata":
            pdata_blob = img._data[praw:praw + min(vs, rsize)]
            break
    pcount = len(pdata_blob) // 12

    def _lookup(rva: int):
        lo, hi = 0, pcount - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            begin, end, _unwind = struct.unpack_from("<III", pdata_blob, mid * 12)
            if rva < begin:
                hi = mid - 1
            elif rva >= end:
                lo = mid + 1
            else:
                return begin, end
        return None

    funcs: dict[int, dict[str, Any]] = {}
    orphans: list[dict[str, Any]] = []
    referenced: set[int] = set()
    for from_rva, tgt in pruned:
        referenced.add(tgt)
        label = by_rva[tgt][0]
        fb = _lookup(from_rva)
        if fb is None:
            orphans.append({"label": label, "from_rva": from_rva})
            continue
        begin, end = fb
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
) -> list[dict[str, Any]]:
    """RVA-aware cross-reference scan within [scan_start_rva, scan_end_rva).

    Uses **byte-pattern scanning plus per-candidate capstone verification**, not
    linear disassembly. Linear ``md.disasm()`` over a large ``.text`` silently
    terminates at the first non-instruction byte (jump tables, alignment padding,
    constant pools), so references beyond that point are missed entirely — on a
    245 MB chrome.dll that means almost everything. Byte scanning does not depend
    on instruction-stream synchronisation and therefore cannot lose alignment.

    Kinds:
      - "rip":   rip-relative operand (LEA / MOV / CMP / ...) resolving to target
      - "call":  direct ``E8 rel32``
      - "jmp":   direct ``E9 rel32`` (and short ``EB rel8``)
      - "imm64": ``MOV r64, imm64`` loading ImageBase+target_rva
      - "ptr":   raw 8-byte VA (pointer tables, vtables, kSwitchNames[]-style arrays)
      - "rva32": raw 4-byte RVA

    ``ptr`` is essential for switch-name tables: Chromium collects ``const char*``
    into a ``.rdata`` array and only LEAs the array base, so the individual strings
    have no rip-relative reference at all.

    Args:
        verify: decode each rip candidate with capstone to confirm the operand and
            instruction length. Set False for a faster, slightly noisier scan.

    Returns list of {from_rva, mnemonic, op_str, target_rva, kind}.
    """
    import struct

    import capstone
    from capstone import x86 as cx86

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

    # Opcodes that commonly carry a rip-relative memory operand. The ModRM byte
    # must have mod=00 and rm=101, i.e. (modrm & 0xC7) == 0x05.
    RIP_OPCODES = frozenset((
        0x8D,  # lea
        0x8B,  # mov r, m
        0x89,  # mov m, r
        0x63,  # movsxd
        0x03, 0x2B, 0x3B, 0x33, 0x0B, 0x23,  # add/sub/cmp/xor/or/and r, m
        0x01, 0x29, 0x39, 0x31, 0x09, 0x21,  # ... m, r
        0x85,  # test
        0xFF,  # inc/dec/call/jmp/push m
        0xC7,  # mov m, imm32
        0x83, 0x81,  # arith m, imm8/imm32
    ))

    def _decode_at(rva: int, want_len_hint: int = 16):
        off = rva - scan_start_rva
        if off < 0 or off >= n:
            return None
        for insn in md.disasm(data[off:off + want_len_hint], base + rva):
            return insn
        return None

    def _rip_target(insn) -> int | None:
        for op in insn.operands:
            if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp - base
        return None

    seen: set[tuple[int, str]] = set()

    def _emit(from_rva: int, kind: str, mnemonic: str, op_str: str, size: int = 0):
        key = (from_rva, kind)
        if key in seen:
            return
        seen.add(key)
        out.append({"from_rva": from_rva, "mnemonic": mnemonic, "op_str": op_str,
                    "target_rva": target_rva, "kind": kind, "size": size})


    for i in range(n - 9):
        b0 = data[i]

        # ── rip-relative ──
        if "rip" in want:
            # optional REX prefix (40-4F), then opcode, then ModRM
            for pfx in (1, 0):
                if pfx and not (0x40 <= b0 <= 0x4F):
                    continue
                op_i = i + pfx
                if op_i + 5 >= n:
                    continue
                opc = data[op_i]
                if opc == 0x0F:  # two-byte opcode
                    if op_i + 6 >= n or (data[op_i + 2] & 0xC7) != 0x05:
                        continue
                    disp_at, ilen = op_i + 3, (op_i + 3 + 4) - i
                elif opc in RIP_OPCODES:
                    if (data[op_i + 1] & 0xC7) != 0x05:
                        continue
                    disp_at, ilen = op_i + 2, (op_i + 2 + 4) - i
                else:
                    continue
                if disp_at + 4 > n:
                    continue
                disp = struct.unpack_from("<i", data, disp_at)[0]
                cand_rva = scan_start_rva + i
                # ``ilen`` is the length up to the end of disp32; opcodes carrying a
                # trailing immediate (C7/83/81) are 1/2/4 bytes longer. Probe those
                # tails cheaply, then let capstone settle the real length.
                for extra in (0, 1, 2, 4):
                    if cand_rva + ilen + extra + disp != target_rva:
                        continue
                    if not verify:
                        _emit(cand_rva, "rip", "(unverified)", "[rip%+d]" % disp)
                        break
                    insn = _decode_at(cand_rva)
                    if insn is not None and _rip_target(insn) == target_rva:
                        _emit(cand_rva, "rip", insn.mnemonic, insn.op_str, insn.size)
                        break

                else:
                    continue
                break


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

    # Drop candidates that fall *inside* an earlier instruction. Scanning byte by
    # byte finds both ``4C 8D 35 ...`` (lea r14) and the REX-less reading one byte
    # later (``8D 35 ...`` -> lea esi), which resolve to the same target. Only the
    # outermost decode is a real reference.
    deduped: list[dict[str, Any]] = []
    covered_until = -1
    for rec in out:
        if rec["kind"] == "rip" and rec["from_rva"] < covered_until:
            continue
        deduped.append(rec)
        if rec.get("size"):
            covered_until = rec["from_rva"] + rec["size"]
    return deduped


