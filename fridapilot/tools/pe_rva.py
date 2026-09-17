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


def xrefs_to_rva(
    binary_path: str | Path,
    target_rva: int,
    scan_start_rva: int,
    scan_end_rva: int,
    kinds: tuple[str, ...] = ("rip", "call", "jmp"),
) -> list[dict[str, Any]]:
    """RVA-aware cross-reference scan within [scan_start_rva, scan_end_rva).

    Finds:
      - "rip": rip-relative LEA/MOV/etc. whose computed target == target_rva
               (how code references a string or global by RVA)
      - "call"/"jmp": direct relative call/jmp whose target == target_rva

    Returns list of {from_rva, mnemonic, op_str, target_rva, kind}.
    """
    import capstone
    from capstone import x86 as cx86

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return []
    out: list[dict[str, Any]] = []
    for insn in md.disasm(data, img.rva_to_va(scan_start_rva)):
        cur_rva = insn.address - img.image_base
        if cur_rva >= scan_end_rva:
            break
        if insn.mnemonic in ("call", "jmp") and insn.op_str.startswith("0x"):
            tgt_rva = int(insn.op_str, 16) - img.image_base
            if tgt_rva == target_rva and insn.mnemonic in kinds:
                out.append({"from_rva": cur_rva, "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str, "target_rva": tgt_rva,
                            "kind": insn.mnemonic})
        elif "rip" in insn.op_str and "rip" in kinds:
            for op in insn.operands:
                if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                    tgt_rva = insn.address + insn.size + op.mem.disp - img.image_base
                    if tgt_rva == target_rva:
                        out.append({"from_rva": cur_rva, "mnemonic": insn.mnemonic,
                                    "op_str": insn.op_str, "target_rva": tgt_rva,
                                    "kind": "rip"})
                    break
    return out
