"""RVA-aware PE analysis tools (ImageBase-correct disassembly & xrefs).

The base ``binary_analysis.disassemble`` / ``xrefs_to`` treat the given address
as BOTH a file offset AND a virtual address. That is only correct when a
section's RVA equals its file offset and ImageBase is 0. For real PEs — e.g. a
289 MB ``chrome.dll`` with ImageBase ``0x180000000`` and ``.text`` RVA ``0x1000``
vs raw offset ``0x600`` — rip-relative references and call/jmp targets resolve to
garbage, which silently misleads reverse engineering.

This module maps between RVA / VA / file offset through the PE section table so
disassembly, string location and cross-references are accurate. Examples name
``chrome.dll`` because that is the shape of PE it was built for; nothing in the
module is specific to it.

No LLM dependency. Requires: pefile, capstone.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from fridapilot.tools.targets import resolve_target

logger = logging.getLogger(__name__)

def _pe_cache_key(path) -> tuple[str, int, int] | None:
    """Cache identity for a PEImage: resolved path + mtime + size.

    None for unreadable paths (those are never cached).
    """
    try:
        p = Path(path)
        st = p.stat()
        return (str(p.resolve()), st.st_mtime_ns, st.st_size)
    except OSError:
        return None

# Bounded instance cache (audit finding L-P1): every public helper used
# to construct its own PEImage, and each construction reads the WHOLE
# file - one function_xrefs call re-read a 240MB binary three times and
# vtable_of_function once per pointer-table hit. Keyed by content stamp
# so an edited file can never be served stale; newest 4 kept.
_PE_CACHE: dict[tuple[str, int, int], PEImage] = {}
_PE_CACHE_ORDER: list[tuple[str, int, int]] = []

# ModRM byte of a rip-relative operand: mod=00, rm=101, reg free -> 8 values.
# A rip reference cannot be encoded any other way, which is what makes the
# prefilter in _iter_rip_refs sound rather than heuristic.
_RIP_MODRM = re.compile(rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


class PEImage:

    """RVA/VA/file-offset aware PE image.

    Example:
        img = PEImage("chrome.dll")
        img.image_base                 # 0x180000000
        img.rva_to_off(0x3226410)      # RVA -> file offset via section table
        img.read_rva(0x10b2d260, 64)   # bytes at an RVA (None if BSS/unmapped)
        img.in_file(0x10b2d260)        # False for uninitialized .data (BSS)
    """

    def __new__(cls, path):
        path = resolve_target(path)
        key = _pe_cache_key(path)
        if key is not None:
            cached = _PE_CACHE.get(key)
            if cached is not None:
                return cached
        return super().__new__(cls)

    def __init__(self, path: str | Path):
        import pefile

        # An "@name" alias becomes its stored path here rather than in the CLI alone, so
        # SDK and MCP callers get it too. A plain path is returned unchanged.
        path = resolve_target(path)
        key = _pe_cache_key(path)
        if key is not None and _PE_CACHE.get(key) is self:
            return  # served from the cache: already fully initialized

        self.path = str(path)
        self._pe = pefile.PE(self.path, fast_load=True)
        self.image_base = self._pe.OPTIONAL_HEADER.ImageBase
        self.is_64bit = self._pe.FILE_HEADER.Machine == 0x8664
        self._pdata: list[tuple[int, int, int]] | None = None
        self._sections: list[tuple[int, int, int, int, str]] = []
        self._section_flags: dict[str, int] = {}
        for s in self._pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin1")
            self._sections.append((
                s.VirtualAddress, s.Misc_VirtualSize,
                s.PointerToRawData, s.SizeOfRawData,
                name,
            ))
            self._section_flags[name] = s.Characteristics
        with open(self.path, "rb") as f:
            self._data = f.read()

        if key is not None:
            _PE_CACHE[key] = self
            _PE_CACHE_ORDER.append(key)
            while len(_PE_CACHE_ORDER) > 4:
                old = _PE_CACHE_ORDER.pop(0)
                if old != key:
                    _PE_CACHE.pop(old, None)

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

    def section_range(self, name: str) -> tuple[int, int] | None:
        """(start_rva, end_rva) of a section by name, or None.

        The end uses ``max(VirtualSize, SizeOfRawData)`` because a scan wants every
        byte the section can hold; table *parsing* uses the min instead (see
        exception_table).
        """
        for va, vs, _praw, rsize, sec in self._sections:
            if sec == name:
                return va, va + max(vs, rsize)
        return None

    def is_executable(self, name: str) -> bool:
        """IMAGE_SCN_MEM_EXECUTE — tells code sections from data sections by flag."""
        return bool(self._section_flags.get(name, 0) & 0x20000000)

    def code_sections(self) -> list[tuple[str, int, int]]:
        """[(name, start_rva, end_rva)] for every executable section.

        Names are not reliable: a build can put code in a section that is not called
        ``.text`` (and packers routinely do), so the executable flag decides.
        """
        return [(sec, va, va + max(vs, rsize))
                for va, vs, _p, rsize, sec in self._sections
                if self.is_executable(sec)]

    def data_sections(self) -> list[tuple[str, int, int]]:
        """[(name, start_rva, end_rva)] for every non-executable section with content.

        These are where function pointers live: vtables, IDL/binding method tables,
        import thunk tables, jump tables. A callee that is only ever dispatched
        indirectly has its address *here* and nowhere in the code sections.
        """
        return [(sec, va, va + max(vs, rsize))
                for va, vs, _p, rsize, sec in self._sections
                if not self.is_executable(sec) and max(vs, rsize) > 0]


def _find_all(data: bytes, pattern: bytes, start: int = 0):
    """Yield every offset of ``pattern`` in ``data`` (overlapping allowed).

    ``bytes.find`` runs in C. The equivalent per-byte Python loop with
    ``struct.unpack_from`` costs ≈0.3 s/MB, so a pointer-table sweep of a
    Chromium-sized data section took minutes and was therefore skipped — which is
    precisely how an indirectly-dispatched callee ends up reported as unreferenced.
    Measured on a 32 MB buffer: 0.16 s here vs ≈10 s for the loop.
    """
    pos = data.find(pattern, start)
    while pos >= 0:
        yield pos
        pos = data.find(pattern, pos + 1)





def _enclosing_cstring(data: bytes, idx: int, pat_len: int, wide: bool,
                       window: int = 512) -> tuple[bytes | None, bool, int]:
    """The NUL-terminated string containing a hit, and whether the hit IS that string.

    A substring search answers "these bytes appear here", never "a string equal to the
    needle lives here". The difference has produced wrong conclusions twice in real
    analyses, both times through the same shortcut: checking only that the needle is
    followed by NUL. ``ID3D12Device::CheckFeatureSupport`` *ends* with
    ``FeatureSupport\\0``, so it passes that test — the tail is constrained, the start
    is not. Only the byte before the hit can settle it, so this walks both ways.

    Returns (raw_bytes, whole, start_offset). ``None``/-1 means no terminator within
    ``window`` on one side, i.e. the hit is probably not in a C string at all (code, a
    length-prefixed blob, binary data) — reported as unknown rather than guessed. What
    is returned is the NUL-delimited run around the hit, so when the neighbouring bytes
    are pointers rather than text the run legitimately carries that noise with it; only
    ``whole`` is a verdict. ``start_offset`` is the file offset of the run's first byte,
    which is the address code actually references — the hit offset is not, and
    recovering it by subtracting where the needle appears in the run is wrong as soon as
    the needle occurs twice.
    """
    step = 2 if wide else 1
    unit_zero = b"\0" * step
    lo = max(idx - window, 0)
    start = idx
    while start - step >= lo:
        if data[start - step:start] == unit_zero:
            break
        start -= step
    else:
        return None, False, -1
    hi = min(idx + pat_len + window, len(data))
    end = idx + pat_len
    while end + step <= hi:
        if data[end:end + step] == unit_zero:
            break
        end += step
    else:
        return None, False, -1
    return data[start:end], start == idx and end == idx + pat_len, start


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
        List of {needle, offset, rva, string_rva, encoding, section, whole, enclosing};
        offset/rva are None if absent.

        ``whole`` and ``enclosing`` exist because every hit is a *substring* match.
        ``enclosing`` is the NUL-terminated string the hit sits inside (None when the
        hit is not inside one), and ``whole`` is True only when that string equals the
        needle. Do not treat a hit as a standalone string, or as evidence that an
        identifier exists in the image, without checking them: 18 hits for
        ``FeatureSupport`` in one Chromium DLL were 17 D3D12 log messages plus
        ``queryFeatureSupport``, and none of them was the key being looked for.

        ``string_rva`` is the RVA of ``enclosing``'s first byte — the address the code
        actually LEAs, and therefore the one to hand to ``map_refs_to_functions`` or
        ``xrefs_to_rva``. ``rva`` points at the *hit*, which is only the same address
        when the needle starts the string; deriving it as
        ``rva - enclosing.index(needle)`` is wrong the moment the needle occurs twice in
        the string, which is routine for a keyword matched against a source path.
    """
    img = PEImage(binary_path)
    data = img._data
    out: list[dict[str, Any]] = []
    for needle in needles:
        pat = needle.encode("utf-8") if encoding == "ascii" else needle.encode("utf-16-le")
        # Report the codec actually used: the "ascii" spelling encodes
        # UTF-8, so a non-ASCII needle must not be mislabeled (audit L-P3).
        codec = "utf-16-le" if encoding != "ascii" else "utf-8"
        start = 0
        found = 0
        while True:
            idx = data.find(pat, start)
            if idx < 0:
                break
            rva = img.off_to_rva(idx)
            raw, whole, str_off = _enclosing_cstring(data, idx, len(pat), encoding != "ascii")
            codec = "utf-8" if encoding == "ascii" else "utf-16-le"
            out.append({
                "needle": needle, "offset": idx,
                "rva": rva, "encoding": codec,
                "string_rva": img.off_to_rva(str_off) if str_off >= 0 else None,
                "section": img.section_of(rva) if rva is not None else "",
                "whole": whole,
                "enclosing": raw.decode(codec, "replace") if raw is not None else None,
            })
            found += 1
            start = idx + 1
        if found == 0:
            out.append({"needle": needle, "offset": None, "rva": None, "encoding": codec,
                        "string_rva": None,
                        "section": "", "whole": False, "enclosing": None})
    return out


def _text_at(img: PEImage, rva: int, min_len: int = 4, cap: int = 200) -> tuple[str, str] | None:
    """Readable text at an RVA as (text, encoding), or None.

    ASCII first, then UTF-16LE. Trying only ASCII is the documented reason wide strings
    vanish from output that looks complete, and a resolved reference target is exactly
    where a wide string shows up in Chromium code.
    """
    raw = img.read_rva(rva, cap)
    if not raw:
        return None
    run = raw.split(b"\0")[0]
    if len(run) >= min_len and all(0x20 <= c < 0x7F for c in run):
        return run.decode(), "ascii"
    end = 0
    while end + 1 < len(raw) and raw[end + 1] == 0 and 0x20 <= raw[end] < 0x7F:
        end += 2
    if end // 2 >= min_len:
        return raw[:end].decode("utf-16-le"), "utf16le"
    return None


def _immediate_text(insn, cx86) -> str:
    """Text carried in an instruction's immediate operand, or "".

    The discovery direction of ``find_inline_strings``: while reading code, a
    ``movabs rax, 0x6567617373654d`` is 8 characters of a string being assembled in a
    register, and nothing in the mnemonic says so. Reads the operand rather than
    parsing ``op_str``, which loses the width and breaks on negative values.
    """
    for op in insn.operands:
        if op.type != cx86.X86_OP_IMM:
            continue
        raw = (op.imm & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little").rstrip(b"\0")
        if len(raw) >= 4 and all(0x20 <= c < 0x7F for c in raw):
            return raw.decode()
    return ""


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
                    # Section and content, not just the address: without them every
                    # data reference looks alike and the reader has to jump away to
                    # find out whether it is a string, a vtable or a counter.
                    note = "; [rip]-> RVA 0x%x" % tgt_rva
                    section = img.section_of(tgt_rva)
                    if section:
                        note += " [%s]" % section
                    if name:
                        note += " " + name
                    found = _text_at(img, tgt_rva)
                    if found:
                        note += ' "%s"' % found[0][:60]
                    break
        text_imm = _immediate_text(insn, cx86)
        if text_imm:
            note += '   ; imm="%s"' % text_imm
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



_SOURCE_SUFFIXES = (".cc", ".cpp", ".cxx", ".h", ".hpp", ".mm", ".rs")


def _decode_body(img: PEImage, md: Any, begin: int, end: int, budget: int):
    """Yield the instructions of a function body, resyncing over embedded data.

    A jump table, alignment junk or a constant pool inside the body stops capstone
    dead, so a single ``md.disasm`` pass ends early and everything after the stall is
    silently missed — the synthetic fixture's data-in-code byte caught exactly that,
    hiding the one ``call`` in the function. Resyncing costs one byte per stall, the
    same trade ``_iter_rip_refs`` already makes.
    """
    span = max(min(end - begin, budget), 0)
    data = img.read_rva(begin, span) or b""
    base_va = img.rva_to_va(begin)
    pos = 0
    while pos < len(data):
        progressed = False
        for insn in md.disasm(data[pos:], base_va + pos):
            progressed = True
            pos = insn.address - base_va + insn.size
            yield insn
        if not progressed:
            pos += 1


def _function_strings(img: PEImage, md: Any, begin: int, end: int,
                      budget: int = 8192, limit: int = 24):
    """Strings a function reaches, split into source paths / symbols / everything else.

    The cheapest substitute for a symbol table on an unstripped-ish Chromium build:
    ``DCHECK``/``NOTREACHED`` expand to ``__FILE__`` and ``__PRETTY_FUNCTION__``, and
    histogram names are literals too, so the strings a function points at usually name
    it. Yield depends on the build — a release image strips most DCHECKs, so the honest
    result is often only the plain strings (measured on one 294 MB release chrome.dll:
    a 981-byte function yielded ``user-data-dir`` and ``protected-cookiesfile`` and no
    source path at all). Both are returned separately instead of pretending one exists.
    """
    from capstone import x86 as cx86

    paths: list[str] = []
    symbols: list[str] = []
    other: list[str] = []
    for insn in _decode_body(img, md, begin, end, budget):
        for op in insn.operands:
            if op.type != cx86.X86_OP_MEM or op.mem.base != cx86.X86_REG_RIP:
                continue
            tgt = insn.address + insn.size + op.mem.disp - img.image_base
            found = _text_at(img, tgt)
            if not found:
                continue
            text = found[0]
            bucket = {"source_path": paths, "symbol": symbols}.get(
                _classify_text(text), other)
            if text not in bucket and len(bucket) < limit:
                bucket.append(text)
        imm = _immediate_text(insn, cx86)
        if imm and imm not in other and len(other) < limit:
            other.append(imm)
    return paths, symbols, other


def describe_function(
    binary_path: str | Path,
    rva: int,
    budget: int = 8192,
    limit: int = 24,
) -> dict[str, Any]:
    """Label an unnamed function from the strings its own body references.

    Every other function in this module answers with a bare address — "referenced from
    0x748a05b" — and leaves identifying that function to the reader. This closes the
    loop cheaply: one function is decoded, its rip targets are read as text, and the
    result is classified so the caller can tell a ``__FILE__`` path from an arbitrary
    literal instead of guessing.

    ``function_bounds`` returning None means "no RUNTIME_FUNCTION", not "not a
    function", so a leaf is described over ``budget`` bytes with ``has_bounds`` False
    rather than refused.

    Returns {rva, begin_rva, end_rva, size, has_bounds, source_paths, symbols,
    strings, label}.
    """
    import capstone

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True

    found = img.function_at(rva)
    if found is not None:
        begin, end = found[0], found[1]
    else:
        begin, end = rva, rva + budget
    paths, symbols, other = _function_strings(img, md, begin, end, budget, limit)
    label = " | ".join(paths or symbols or other)[:200]
    return {
        "rva": rva, "begin_rva": begin, "end_rva": end, "size": end - begin,
        "has_bounds": found is not None,
        "source_paths": paths, "symbols": symbols, "strings": other,
        "label": label or "(no readable strings)",
    }


MAX_FUNCTION_SPAN = 1 << 20
MAX_REGION_SPAN = 64 << 20


def _classify_text(text: str) -> str:
    """Which kind of literal this is: a __FILE__ path, a symbol, or plain text."""
    if any(s in text for s in _SOURCE_SUFFIXES) and ("/" in text or "\\" in text):
        return "source_path"
    if "::" in text:
        return "symbol"
    return "text"


def function_strings(
    binary_path: str | Path,
    ranges: list[tuple[int, int | None]],
    budget: int = 0,
    min_len: int = 4,
    limit: int = 0,
    cap: int = 200,
) -> dict[str, Any]:
    """Every string each given code range references, with the RVA on both ends.

    The fastest way to identify a function in a stripped image: ``DCHECK`` /
    ``NOTREACHED`` expand to ``__FILE__``, log calls carry their own message, endpoint
    URLs and ``base::Feature`` names are literals. A 2836-byte function usually names
    itself without a single line of disassembly being read.

    This is the addressed form of what ``describe_function`` summarises. Two differences
    matter in practice:

    * every row carries ``from_rva`` (the referencing instruction) and ``target_rva``
      plus its ``section``. A reference into ``.rdata`` next to a Dawn/Skia shader or a
      V8 error table is indistinguishable from a real hit by text alone, and the target
      address is what lets the reader throw it out;
    * nothing is silently dropped. ``describe_function`` decodes at most ``budget``
      bytes and keeps at most 24 strings per bucket while still reporting the function's
      full ``size``, so a large function comes back looking complete. Here ``budget``
      defaults to the whole range and ``complete`` says whether the range was decoded
      end to end.

    Args:
        ranges: [(begin_rva, end_rva)]. ``end_rva=None`` means "resolve the bounds from
            ``.pdata``", falling back to ``begin + 8192`` for a leaf with no
            RUNTIME_FUNCTION (reported as ``has_bounds=False``).
        budget: max bytes to decode per range; 0 means the whole range, capped at
            ``MAX_FUNCTION_SPAN``.
        min_len: shortest run accepted as text at a target.
        limit: max rows per range; 0 means unlimited.
        cap: longest string returned.

    Returns:
        {path, ranges: [{begin_rva, end_rva, size, has_bounds, decoded_bytes, complete,
        truncated, count, strings: [{from_rva, target_rva, section, encoding, kind,
        text}]}], total, notes}
    """
    import capstone
    from capstone import x86 as cx86

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True

    notes: list[str] = []
    out_ranges: list[dict[str, Any]] = []
    total = 0
    for begin, end in ranges:
        has_bounds = True
        if end is None:
            found = img.function_at(begin)
            if found is not None:
                begin, end = found[0], found[1]
            else:
                has_bounds = False
                end = begin + 8192
        span = max(end - begin, 0)
        allowed = min(span, budget or MAX_FUNCTION_SPAN)
        rows: list[dict[str, Any]] = []
        seen: set[tuple[int, int | None]] = set()
        truncated = False
        for insn in _decode_body(img, md, begin, begin + allowed, allowed):
            hits: list[tuple[int | None, str, str]] = []
            for op in insn.operands:
                if op.type != cx86.X86_OP_MEM or op.mem.base != cx86.X86_REG_RIP:
                    continue
                tgt = insn.address + insn.size + op.mem.disp - img.image_base
                found_text = _text_at(img, tgt, min_len=min_len, cap=cap)
                if found_text:
                    hits.append((tgt, found_text[0], found_text[1]))
            imm = _immediate_text(insn, cx86)
            if imm:
                # An inline-constructed string has no .rdata copy at all, so there is no
                # target address to report - the characters are in the opcode bytes.
                hits.append((None, imm, "inline"))
            from_rva = insn.address - img.image_base
            for target_rva, text, enc in hits:
                key = (from_rva, target_rva)
                if key in seen:
                    continue
                seen.add(key)
                if limit and len(rows) >= limit:
                    truncated = True
                    break
                rows.append({
                    "from_rva": from_rva,
                    "target_rva": target_rva,
                    "section": img.section_of(target_rva) if target_rva is not None else "",
                    "encoding": enc,
                    "kind": "inline" if enc == "inline" else _classify_text(text),
                    "text": text,
                })
            if truncated:
                break
        out_ranges.append({
            "begin_rva": begin, "end_rva": end, "size": span,
            "has_bounds": has_bounds,
            "decoded_bytes": allowed, "complete": allowed >= span and not truncated,
            "truncated": truncated, "count": len(rows), "strings": rows,
        })
        total += len(rows)
        if allowed < span:
            notes.append(
                f"0x{begin:x}: decoded {allowed} of {span} bytes - raise budget "
                f"(cap {MAX_FUNCTION_SPAN}) or the tail is unexamined")
    if not notes:
        notes.append("every range decoded end to end")
    return {"path": str(binary_path), "ranges": out_ranges, "total": total, "notes": notes}


def strings_in_range(
    binary_path: str | Path,
    start_rva: int | None = None,
    end_rva: int | None = None,
    section: str = "",
    min_len: int = 4,
    encoding: str = "ascii",
    limit: int = 0,
) -> dict[str, Any]:
    """Strings inside one RVA range or section, keyed by RVA.

    ``binary_analysis.find_strings`` scans the whole file and then keeps the first N by
    offset, which on a 250 MB image returns headers and never reaches ``.rdata``.
    Aiming at a range is what finds a *table*: a run of adjacent literals - vendor
    ``base::Feature`` names, a config key list, an endpoint set - is obvious when the
    neighbourhood is printed in address order and invisible in a whole-file dump.

    ``terminated`` distinguishes a real C string from a printable fragment of binary
    data: an unterminated run inside a pointer table is text by accident.

    Args:
        section: section name; overrides start/end when given.
        start_rva/end_rva: explicit range (RVAs, not file offsets).
        encoding: ``ascii``, ``utf16le`` or ``all``.
        limit: max rows; 0 means unlimited.

    Returns:
        {path, section, start_rva, end_rva, scanned_bytes, complete, count, truncated,
        strings: [{rva, offset, encoding, length, terminated, text}]}
    """
    img = PEImage(binary_path)
    if section:
        found = img.section_range(section)
        if found is None:
            names = ", ".join(name for name, _s, _e in
                              img.code_sections() + img.data_sections())
            raise ValueError(f"no section named {section!r} (have: {names})")
        start_rva, end_rva = found
    if start_rva is None or end_rva is None or end_rva <= start_rva:
        raise ValueError("pass a section name, or start_rva and end_rva with end > start")

    span = end_rva - start_rva
    scanned = min(span, MAX_REGION_SPAN)
    data = img.read_rva(start_rva, scanned) or b""
    rows: list[dict[str, Any]] = []
    truncated = False
    # Regex, not a per-byte Python loop: the same reason the absolute-pattern kinds go
    # through bytes.find. A 32 MB .rdata is 0.1 s here and ~10 s walked in Python.
    patterns = []
    if encoding in ("ascii", "all"):
        patterns.append(("ascii", re.compile(rb"[\x20-\x7e]{%d,}" % min_len)))
    if encoding in ("utf16le", "all"):
        patterns.append(("utf16le", re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)))
    if not patterns:
        raise ValueError(f"unknown encoding {encoding!r} (ascii, utf16le, all)")

    for enc, pattern in patterns:
        for m in pattern.finditer(data):
            if limit and len(rows) >= limit:
                truncated = True
                break
            raw = m.group()
            tail = data[m.end():m.end() + (2 if enc == "utf16le" else 1)]
            rva = start_rva + m.start()
            rows.append({
                "rva": rva,
                "offset": img.rva_to_off(rva),
                "encoding": enc,
                "length": len(raw) // 2 if enc == "utf16le" else len(raw),
                "terminated": tail.startswith(b"\0"),
                "text": (raw.decode("utf-16-le") if enc == "utf16le"
                         else raw.decode("ascii")),
            })
        if truncated:
            break
    rows.sort(key=lambda r: r["rva"])
    return {
        "path": str(binary_path), "section": section,
        "start_rva": start_rva, "end_rva": end_rva,
        "scanned_bytes": len(data), "complete": len(data) >= span and not truncated,
        "count": len(rows), "truncated": truncated, "strings": rows,
    }


def function_callees(
    binary_path: str | Path,
    rva: int,
    budget: int = 8192,
    label: bool = True,
) -> list[dict[str, Any]]:
    """Direct callees of one function, each labelled by the strings in its body.

    The other half of ``function_xrefs``: that answers "who reaches this", this answers
    "what does this reach". Only ``call`` with an immediate target is listed — an
    indirect ``call rax`` names no callee in the instruction stream, the same reason
    a call/jmp scan cannot see a virtual method.

    Returns [{from_rva, callee_rva, begin_rva, end_rva, size, has_bounds, label}],
    deduplicated by callee and ordered by call site.
    """
    import capstone

    img = PEImage(binary_path)
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True

    found = img.function_at(rva)
    begin, end = (found[0], found[1]) if found else (rva, rva + budget)

    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for insn in _decode_body(img, md, begin, end, budget):
        if insn.mnemonic != "call" or not insn.op_str.startswith("0x"):
            continue
        callee = int(insn.op_str, 16) - img.image_base
        if callee in seen:
            continue
        seen.add(callee)
        bounds = img.function_at(callee)
        c_begin, c_end = (bounds[0], bounds[1]) if bounds else (callee, callee + budget)
        text = ""
        if label:
            paths, syms, other = _function_strings(img, md, c_begin, c_end, budget)
            text = " | ".join(paths or syms or other)[:160]
        out.append({
            "from_rva": insn.address - img.image_base, "callee_rva": callee,
            "begin_rva": c_begin, "end_rva": c_end, "size": c_end - c_begin,
            "has_bounds": bounds is not None, "label": text,
        })
    return out


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
                 0x31: "xor", 0x09: "or", 0x21: "and",
                 # byte-sized
                 0x88: "mov", 0xC6: "mov", 0x00: "add", 0x28: "sub",
                 0x30: "xor", 0x08: "or", 0x20: "and", 0x80: "arith",
                 0xFE: "inc/dec", 0xFF: "inc/dec/call",
                 # shift
                 0xC0: "shift", 0xC1: "shift", 0xD0: "shift", 0xD1: "shift",
                 0xD2: "shift", 0xD3: "shift",
                 # group3
                 0xF6: "test/neg", 0xF7: "test/neg",
                 # xchg
                 0x86: "xchg", 0x87: "xchg",
                 }
    READ_OPS = {0x8B: "mov", 0x03: "add", 0x2B: "sub", 0x33: "xor",
                0x0B: "or", 0x23: "and", 0x3B: "cmp", 0x85: "test",
                # byte-sized
                0x8A: "mov", 0x02: "add", 0x2A: "sub", 0x32: "xor",
                0x0A: "or", 0x22: "and", 0x3A: "cmp", 0x84: "test",
                # lea (often used to take address of struct field)
                0x8D: "lea",
                # adc / sbb
                0x12: "adc", 0x13: "adc", 0x1A: "sbb", 0x1B: "sbb",
                # movsxd
                0x63: "movsxd",
                }

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
    for i in range(n - 7):
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

    # A struct offset only identifies a field if it is rare. Hundreds of hits mean the
    # offset is shared by unrelated classes and the result is noise, not an answer —
    # measured: one vtable slot offset produced 200+ hits across a Chromium DLL, almost
    # all from other types. Say so rather than handing back a list that looks like
    # progress. Nothing can fix this by filtering: the dispatch site does not know the
    # object's dynamic type, so `[reg+off]` cannot be narrowed to one class. Anchor on
    # something unambiguous instead (a string, a called function, a vtable identity via
    # vtable_of_function), or settle it at runtime by behavioural comparison.
    if len(out) > 100:
        logger.warning(
            "%d matches for [reg+0x%x] — this offset is not discriminating. Unrelated "
            "classes share struct and vtable-slot offsets, and a dispatch site carries "
            "no type information, so this cannot be narrowed by filtering. If 0x%x is a "
            "vtable slot, start from the implementation (vtable_of_function) instead; "
            "otherwise anchor on a string or a call and confirm at runtime",
            len(out), offset, offset)
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

    Two complementary passes over a shared candidate list, because neither alone is
    enough. Both start from the same prefilter: a rip operand is always ModRM
    mod=00 / rm=101 + disp32, so the displacement positions that could resolve to a
    wanted target are found in C first, and everything below only looks there.

    A. **Linear disassembly inside every ``.pdata`` RUNTIME_FUNCTION** that contains
       a candidate. Function bounds are exact, so linear decoding cannot drift into
       inter-function data the way a whole-section sweep does, and capstone handles
       every encoding form. An opcode whitelist structurally cannot: measured on
       ntdll.dll, whitelisting caps recall at ~95% and the misses are systematic —
       ``F0`` (lock cmpxchg/inc/and on a global, i.e. exactly the singletons and
       refcounts one is looking for), ``66``/``F2``/``F3`` (word stores, movsd,
       movdqa/movdqu) and VEX/EVEX, all of which put prefixes ahead of the opcode.
       Padding or a jump table inside a function only costs a one-byte resync.

    B. **The candidates outside ``.pdata`` coverage** (leaf functions, hand-written
       asm, packed code, 32-bit images, data sections), confirmed by decoding from up
       to 8 bytes back (prefixes + 1-2 byte opcode + ModRM) instead of by an opcode
       table.

    Args:
        is_target: predicate on the resolved target RVA (equality for one target,
            set membership for many).
        verify: decode pass-B candidates with capstone. Pass A always decodes.
        scan_gaps: run pass B. False = strict ``.pdata``-only mode, which trades
            recall outside known functions for precision in data-heavy ranges.
    """
    import bisect
    import struct as _st

    from capstone import x86 as cx86

    base = img.image_base
    n = len(data)

    def rip_target(insn) -> int | None:
        for op in insn.operands:
            if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp - base
        return None

    # ── prefilter: where could a matching displacement possibly sit? ──
    #
    # A rip-relative operand is ALWAYS ModRM mod=00 / rm=101 followed by disp32, and
    # the resolved target is fully determined by that displacement, the end of the
    # instruction and the trailing-immediate width (0/1/2/4 — no rip form carries a
    # wider immediate). So the offsets below are a SUPERSET of every real reference to
    # a wanted target: the ModRM byte is found in C, and the arithmetic runs only on
    # the ~2% of positions that pass.
    #
    # This is what makes pass A affordable. Linear decode with capstone costs ≈2.7 s/MB
    # (measured on a 251 MB Chromium .text: ≈11 minutes for one query, which reads as a
    # hang and gets killed). A .pdata function containing no candidate cannot reference
    # the target, so it is never decoded, and a single-target query drops to seconds.
    candidates: list[int] = []
    for match in _RIP_MODRM.finditer(data, 0, max(n - 5, 0)):
        i = match.start() + 1
        disp = _st.unpack_from("<i", data, i)[0]
        end_rva = scan_start_rva + i + 4
        for imm in (0, 1, 2, 4):
            if is_target(end_rva + imm + disp):
                candidates.append(i)
                break

    # ── pass A: decode .pdata-covered functions ──
    covered: list[tuple[int, int]] = []
    for begin, end, _unwind in img.exception_table():
        if end <= scan_start_rva or begin >= scan_end_rva:
            continue
        lo, hi = max(begin, scan_start_rva), min(end, scan_end_rva)
        covered.append((lo, hi))  # recorded even when skipped: pass B needs the gaps
        # No candidate displacement inside the function (widened by the longest
        # encoding, so an instruction starting just before ``lo`` still counts) means
        # no reference here, so there is nothing for the decoder to find.
        k = bisect.bisect_left(candidates, lo - scan_start_rva - 8)
        if k >= len(candidates) or candidates[k] >= hi - scan_start_rva:
            continue
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

    # ── pass B: confirm the candidates that fall outside .pdata ──
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
        i_lo = max(lo - scan_start_rva, 1)
        i_hi = min(hi - scan_start_rva, n - 4)
        for k in range(bisect.bisect_left(candidates, i_lo), len(candidates)):
            i = candidates[k]
            if i >= i_hi:
                break
            disp = _st.unpack_from("<i", data, i)[0]
            end_rva = scan_start_rva + i + 4
            tgt = next(t for t in (end_rva + imm + disp for imm in (0, 1, 2, 4))
                       if is_target(t))
            if not verify:
                yield (scan_start_rva + i - 2, tgt, "(unverified)",
                       "[rip%+d]" % disp, 0)
                continue
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
                hit = rip_target(insn)
                if hit is not None and is_target(hit):
                    yield (insn.address - base, hit,
                           insn.mnemonic, insn.op_str, insn.size)
                    break



def map_refs_to_functions(
    binary_path: str | Path,
    targets: dict[str, int],
    scan_start_rva: int | None = None,
    scan_end_rva: int | None = None,
    kinds: tuple[str, ...] = ("rip",),
    section: str = "",
) -> dict[str, Any]:
    """Map many target RVAs to the functions that reference them, in ONE pass.

    Answers "which functions consume these N strings, and which does each use?" —
    the practical shape of mapping a patched binary. Running ``xrefs_to_rva`` N times
    would rescan the whole section N times; this scans once and groups by the
    ``.pdata`` function that contains each reference.

    Args:
        targets: {label: rva}. Labels are free-form (usually the string itself).
        scan_start_rva / scan_end_rva: omit either to take it from the section
            (``.text`` by default, or ``section=``).
        kinds: same vocabulary as ``xrefs_to_rva``; "rip" is the useful one here.
        section: scan this whole section instead.

    Returns:
        {
          "functions": [{begin_rva, end_rva, size, labels: [...], refs: [{label, from_rva}]}],
          "orphans":   [{label, from_rva}],   # reference outside any .pdata entry
          "unreferenced": [label, ...],
          "scanned_bytes": int,
          "scan_start_rva": int, "scan_end_rva": int,
          "section": str, "section_coverage": float,   # 1.0 = the whole section
        }

    ``section_coverage`` is there so a caller can tell "nothing references these"
    apart from "the scan only looked at part of the section".
    """
    import struct

    import capstone

    img = PEImage(binary_path)
    scan_start_rva, scan_end_rva, section_name = _resolve_scan_range(
        img, scan_start_rva, scan_end_rva, section)
    full = img.section_range(section_name) if section_name else None
    coverage = 1.0
    if full and full[1] > full[0]:
        coverage = round(
            (min(scan_end_rva, full[1]) - max(scan_start_rva, full[0])) / (full[1] - full[0]), 4)
    scan_info = {"scan_start_rva": scan_start_rva, "scan_end_rva": scan_end_rva,
                 "section": section_name, "section_coverage": coverage}
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True
    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return {"functions": [], "orphans": [], "unreferenced": list(targets),
                "scanned_bytes": 0, **scan_info}



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
        "unreferenced": sorted(name for rva, names in by_rva.items()
                               if rva not in referenced for name in names),
        "scanned_bytes": n,
        **scan_info,
    }



def _resolve_scan_range(
    img: PEImage,
    scan_start_rva: int | None,
    scan_end_rva: int | None,
    section: str = "",
    default_section: str = ".text",
) -> tuple[int, int, str]:
    """Resolve a scan range, defaulting to a whole section, and flag partial cover.

    A truncated range is the easiest way to get a confidently wrong answer out of
    this module: scanning a third of a 240 MB ``.text`` returns an empty list that
    is indistinguishable from "nothing references this". It has already caused a
    false negative in practice. So:

    * omitting either bound fills it from the section (``.text`` by default, or the
      section containing the bound that *was* given);
    * ``section=".rdata"`` asks for that section outright;
    * a range that covers only part of its containing section is logged as a
      warning with the percentage, so the gap is visible instead of silent.

    Returns (start_rva, end_rva, section_name).
    """
    if section:
        found = img.section_range(section)
        if found is None:
            raise ValueError(f"no section named {section!r} in this image")
        lo, hi = found
        return (lo if scan_start_rva is None else scan_start_rva,
                hi if scan_end_rva is None else scan_end_rva, section)

    if scan_start_rva is None or scan_end_rva is None:
        if scan_start_rva is not None:
            anchor = scan_start_rva
        else:
            # Anchor one byte below the end: an end RVA that coincides
            # with the next section's start would otherwise resolve to
            # the wrong section and yield an empty scan (audit L-P5).
            anchor = scan_end_rva - 1 if scan_end_rva else scan_end_rva
        name = (img.section_of(anchor) if anchor is not None else None) or default_section
        found = img.section_range(name) or img.section_range(default_section)
        if found is None:
            raise ValueError(
                f"cannot default the scan range: this image has no {default_section} "
                "section, pass scan_start_rva/scan_end_rva explicitly")
        lo, hi = found
        scan_start_rva = lo if scan_start_rva is None else scan_start_rva
        scan_end_rva = hi if scan_end_rva is None else scan_end_rva

    containing = img.section_of(scan_start_rva) or ""
    full = img.section_range(containing) if containing else None
    if full and (scan_start_rva > full[0] or scan_end_rva < full[1]):
        span = full[1] - full[0]
        covered = (min(scan_end_rva, full[1]) - max(scan_start_rva, full[0])) / span
        logger.warning(
            "scan range 0x%x-0x%x covers %.1f%% of %s (0x%x-0x%x): an incomplete "
            "range returns fewer references, which looks identical to having none",
            scan_start_rva, scan_end_rva, covered * 100, containing, full[0], full[1])
    return scan_start_rva, scan_end_rva, containing


def section_range(binary_path: str | Path, name: str = ".text") -> dict[str, Any] | None:
    """(start/end RVA and size of a section) — use it instead of guessing bounds."""
    found = PEImage(binary_path).section_range(name)
    if found is None:
        return None
    return {"section": name, "start_rva": found[0], "end_rva": found[1],
            "size": found[1] - found[0]}


def xrefs_to_rva(
    binary_path: str | Path,
    target_rva: int,
    scan_start_rva: int | None = None,
    scan_end_rva: int | None = None,
    kinds: tuple[str, ...] = ("rip", "call", "jmp"),
    verify: bool = True,
    scan_gaps: bool = True,
    section: str = "",
    use_index: bool = True,
    diagnose: bool = True,
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
        scan_start_rva / scan_end_rva: omit either to take it from the section
            (``.text`` by default, or ``section=``). Passing a partial range is how
            a scan silently under-reports: a third of a 240 MB ``.text`` returns an
            empty list that looks exactly like "no references". Partial coverage is
            logged as a warning.
        section: scan this whole section instead (".rdata" for ``ptr``/``rva32``).
        verify: decode displacement-scan candidates with capstone to confirm the
            operand and instruction length. The ``.pdata`` pass always decodes.
            False is faster and noisier.
        scan_gaps: also scan the ranges ``.pdata`` does not cover (leaf functions,
            hand-written asm, packed code, 32-bit images, data sections). False =
            strict ``.pdata``-only mode: fewer false positives when the range spans
            data, at the cost of missing references outside known functions.
        use_index: answer the rip part from a prebuilt ``rip_index`` when one covers
            this file content, range and target section — turning a minutes-long
            sweep into a query. The index refuses queries outside its recorded
            coverage, so a miss falls back to scanning rather than under-reporting.


    Returns list of {from_rva, mnemonic, op_str, target_rva, kind, size}.
    """
    import struct

    import capstone

    img = PEImage(binary_path)
    scan_start_rva, scan_end_rva, _section_name = _resolve_scan_range(
        img, scan_start_rva, scan_end_rva, section)

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
        cached = None
        if use_index:
            from fridapilot.tools.rip_index import lookup_rip_refs
            cached = lookup_rip_refs(binary_path, target_rva,
                                     scan_start_rva, scan_end_rva,
                                     scan_gaps=scan_gaps)
        if cached is not None:
            # Served from the persistent index, which only answers queries inside
            # the range and target sections it recorded (see rip_index).
            for rec in cached:
                _emit(rec["from_rva"], "rip", rec["mnemonic"], rec["op_str"], rec["size"])
            if want - {"rip"}:
                logger.info("rip refs came from the index; the %s scan still runs",
                            ", ".join(sorted(want - {"rip"})))
        else:
            for from_rva, _tgt, mnem, op_str, size in _iter_rip_refs(
                    img, md, data, scan_start_rva, scan_end_rva,
                    lambda t: t == target_rva, verify=verify, scan_gaps=scan_gaps):
                _emit(from_rva, "rip", mnem, op_str, size)


    # ── absolute encodings: whole-pattern searches ──
    #
    # ptr / rva32 / imm64 all look for one FIXED byte string (the target VA or RVA),
    # so bytes.find does the work in C. This used to share the per-byte walk below at
    # ≈0.3 s/MB, which made a pointer-table sweep of a Chromium-sized data section a
    # minutes-long job — so it got skipped, and an indirectly-dispatched callee read
    # as "no references". 32 MB: 0.16 s here vs ≈10 s in the loop.
    if "ptr" in want:
        for i in _find_all(data, struct.pack("<Q", target_va)):
            _emit(scan_start_rva + i, "ptr", "(data)", "qword 0x%x" % target_va)
    if "rva32" in want:
        for i in _find_all(data, struct.pack("<I", target_rva)):
            _emit(scan_start_rva + i, "rva32", "(data)", "dword 0x%x" % target_rva)
    if "imm64" in want:
        for i in _find_all(data, struct.pack("<Q", target_va)):
            # MOV r64, imm64 is REX.W + B8+r, so the immediate starts two bytes in.
            if i >= 2 and data[i - 2] in (0x48, 0x49) and 0xB8 <= data[i - 1] <= 0xBF:
                _emit(scan_start_rva + i - 2, "imm64", "movabs", "0x%x" % target_va)

    # call / jmp are rel32 / rel8: the encoded bytes depend on the address of the
    # instruction itself, so there is no fixed pattern to search for and the byte walk
    # stays. Skipped entirely when only absolute kinds were asked for.
    if want & {"call", "jmp"}:
        # rel32 needs bytes i..i+4, so i <= n-5 (the old n-9 silently
        # skipped the last five bytes of the section - audit L-P2).
        for i in range(n - 4):
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

    # An empty result is the dangerous one: it reads as "nothing references this"
    # whatever the actual reason. Say which reason applies before the caller guesses.
    if not deduped and diagnose \
            and img.is_executable(img.section_of(target_rva) or "") \
            and not (want & {"ptr", "rva32"}):
        logger.warning(
            "no %s reference to code at 0x%x. A function that is only dispatched "
            "indirectly (C++ virtual, Blink IDL binding table, import thunk) is never "
            "the operand of a call/jmp — its address sits in a data-section pointer "
            "table instead. Use function_xrefs(), which scans both, before concluding "
            "it is unreferenced",
            "/".join(sorted(want)), target_rva)

    return deduped


def function_xrefs(
    binary_path: str | Path,
    target_rva: int,
    follow: bool = False,
    verify: bool = True,
    use_index: bool = True,
) -> dict[str, Any]:
    """Who reaches this function — direct calls *and* pointer-table entries.

    ``xrefs_to_rva(..., kinds=("call","jmp"))`` answers "who has a direct branch to
    this address". For a large class of real callees that question has no instances
    and the empty answer means nothing:

    * C++ virtual methods are dispatched through a vtable;
    * methods bound into a scripting engine (Blink/V8-style IDL bindings and any
      comparable generated binding layer) are invoked out of a generated method table;
    * imported functions go through a thunk table;
    * callbacks are passed as addresses and called later.

    In all of those the only occurrence of the function's address in the image is an
    8-byte pointer sitting in a *data* section — a place the default ``.text`` scan
    never looks. Asking "who calls it" and getting 0 is then guaranteed, and is
    indistinguishable from the function being dead.

    So scan both: ``call``/``jmp`` over every executable section, ``ptr``/``rva32``
    over every data section, and report each with the coverage it achieved. The
    pointer sweep is a ``bytes.find`` pass, so adding it costs almost nothing.

    Args:
        follow: after finding pointer slots, run one rip scan over the code sections
            to find the instructions that load those slots — the actual dispatch
            sites. One pass regardless of slot count; skip it to stay cheap.

    Returns:
        {target_rva, target_section, target_is_code, direct, indirect, dispatchers,
         scanned, verdict}. ``verdict`` is a sentence, because the number that needs
        interpreting most often is zero.
    """
    img = PEImage(binary_path)
    target_section = img.section_of(target_rva) or ""
    target_is_code = img.is_executable(target_section)

    scanned: list[dict[str, Any]] = []
    direct: list[dict[str, Any]] = []
    indirect: list[dict[str, Any]] = []

    for name, lo, hi in img.code_sections():
        scanned.append({"section": name, "start_rva": lo, "end_rva": hi, "kinds": "call,jmp"})
        for rec in xrefs_to_rva(binary_path, target_rva, lo, hi,
                                kinds=("call", "jmp"), verify=verify,
                                use_index=use_index, diagnose=False):
            func = img.function_at(rec["from_rva"])
            rec["section"] = name
            rec["func_begin_rva"] = func[0] if func else None
            direct.append(rec)

    for name, lo, hi in img.data_sections():
        scanned.append({"section": name, "start_rva": lo, "end_rva": hi, "kinds": "ptr,rva32"})
        for rec in xrefs_to_rva(binary_path, target_rva, lo, hi,
                                kinds=("ptr",), verify=False, use_index=False):
            rec["section"] = name
            indirect.append(rec)

    # Second hop: the slot addresses are what the dispatching code actually loads.
    dispatchers: list[dict[str, Any]] = []
    if follow and indirect:
        import capstone

        slots = {r["from_rva"] for r in indirect}
        md = capstone.Cs(capstone.CS_ARCH_X86,
                         capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
        md.detail = True
        for name, lo, hi in img.code_sections():
            blob = img.read_rva(lo, hi - lo)
            if blob is None:
                continue
            for from_rva, slot, mnem, op_str, size in _iter_rip_refs(
                    img, md, blob, lo, hi, lambda t: t in slots,
                    verify=verify, scan_gaps=True):
                func = img.function_at(from_rva)
                dispatchers.append({
                    "from_rva": from_rva, "slot_rva": slot, "mnemonic": mnem,
                    "op_str": op_str, "size": size, "section": name,
                    "func_begin_rva": func[0] if func else None,
                })

    if not target_is_code:
        verdict = (f"0x{target_rva:x} is in {target_section or '(unmapped)'}, which is not "
                   "executable — this is data, not a function. Use xrefs_to_rva with "
                   "kinds=('rip','ptr') instead")
    elif direct:
        verdict = (f"{len(direct)} direct call/jmp site(s)"
                   + (f", plus {len(indirect)} pointer-table slot(s)" if indirect else ""))
    elif indirect:
        verdict = (f"no direct call/jmp, but the address appears in {len(indirect)} "
                   "data-section slot(s): this function is dispatched indirectly "
                   "(vtable / binding table / thunk)")
        if dispatchers:
            verdict += (f"; {len(dispatchers)} dispatch site(s) load those slots — "
                        "those are the callers")
        elif follow:
            verdict += ("; no instruction loads those slots directly, so the table base is "
                        "indexed at runtime — disassemble the table's own references instead")
        else:
            verdict += ". The callers load the slot — re-run with follow=True to find them"
    else:
        verdict = ("no reference of any kind, over every code and data section in the "
                   "image. Remaining possibilities: the address is computed at runtime "
                   "(relocation, +offset arithmetic), it is an exported entry point "
                   "reached from outside this module, or the RVA is wrong")

    return {
        "target_rva": target_rva,
        "target_section": target_section,
        "target_is_code": target_is_code,
        "direct": direct,
        "indirect": indirect,
        "dispatchers": dispatchers,
        "scanned": scanned,
        "verdict": verdict,
    }


# ── vtables ─────────────────────────────────────────────────────────────────

def _is_code_ptr(img: PEImage, va: int) -> bool:
    """Does this VA point into an executable section of this image?"""
    if va < img.image_base:
        return False
    return img.is_executable(img.section_of(va - img.image_base) or "")


def _decode_msvc_rtti(img: PEImage, vtable_rva: int) -> dict[str, Any] | None:
    """Read the MSVC RTTI class name from the qword just below a vtable.

    MSVC x64 stores a ``_RTTICompleteObjectLocator*`` at ``vtable - 8``:
    ``{signature, offset, cdOffset, pTypeDescriptor(RVA), pClassDescriptor(RVA),
    pSelf(RVA)}``, and the TypeDescriptor's mangled name starts 16 bytes into it.

    Returns None when RTTI is absent — the *normal* case for Chromium and anything
    else built with ``-fno-rtti``. Absence is a fact about the build, not an error.
    """
    import struct

    blob = img.read_rva(vtable_rva - 8, 8)
    if blob is None or len(blob) < 8:
        return None
    locator_va = struct.unpack("<Q", blob)[0]
    if locator_va < img.image_base:
        return None
    loc = img.read_rva(locator_va - img.image_base, 16)
    if loc is None or len(loc) < 16:
        return None
    signature, _offset, _cd_offset, type_desc_rva = struct.unpack("<IIII", loc)
    if signature not in (0, 1) or not type_desc_rva:
        return None
    # TypeDescriptor: pVFTable(8) + spare(8) + name[]
    name_blob = img.read_rva(type_desc_rva + 16, 512)
    if not name_blob:
        return None
    raw = name_blob.split(b"\x00", 1)[0]
    if not raw.startswith(b".?A"):          # every MSVC type descriptor name does
        return None
    return {"mangled": raw.decode("latin1"), "type_descriptor_rva": type_desc_rva}


def vtable_of_function(
    binary_path: str | Path,
    func_rva: int,
    max_entries: int = 4096,
) -> list[dict[str, Any]]:
    """Given a virtual method body, find the vtable(s) holding it and its slot index.

    This is the direction of the vtable question that is statically decidable, and it
    is worth being explicit that **the other direction is not**. At a dispatch site

        mov rax, [rcx]          ; vtable out of the object
        mov rax, [rax+0x1f8]    ; slot 63
        call __guard_dispatch_icall_fptr

    the displacement ``0x1f8`` carries no information about which class is being
    dispatched: the dynamic type lives in the object at runtime, not in the
    instruction stream. Searching ``[reg+0x1f8]`` over a Chromium-sized DLL therefore
    returns hundreds of hits from unrelated classes, and no filter can fix that —
    measured: 200+ hits for one slot offset, almost all noise. Start from the
    implementation instead, which is unambiguous.

    Method: find every data-section qword holding ``ImageBase + func_rva`` (one
    ``bytes.find`` pass), then grow a run of consecutive code pointers around each hit
    to recover the table's extent. The slot index is ``(hit - table_start) / 8``.
    MSVC RTTI below the table gives the class name outright when the build kept it.

    Returns one record per containing table:
        {slot_rva, slot_index, vtable_rva, entries, section, rtti, vtable_refs}
    ``vtable_refs`` are rip-relative references to the table start — the constructors
    that install it, which is how you identify the class when RTTI is absent.
    """
    import struct

    img = PEImage(binary_path)
    if not img.is_executable(img.section_of(func_rva) or ""):
        raise ValueError(
            f"0x{func_rva:x} is not in an executable section; vtable_of_function "
            "expects the address of a function body")

    target_va = img.image_base + func_rva
    needle = struct.pack("<Q", target_va)
    out: list[dict[str, Any]] = []

    for name, lo, hi in img.data_sections():
        blob = img.read_rva(lo, hi - lo)
        if blob is None:
            continue
        for i in _find_all(blob, needle):
            if i % 8:
                # A vtable slot is qword-aligned; an unaligned hit is a coincidence
                # inside other data, not a table entry.
                continue

            # Grow a run of consecutive code pointers around the hit. A vtable is a
            # dense run of them, and the run ends at the RTTI pointer / padding / the
            # next table, so this recovers the extent without needing symbols.
            start = i
            while start >= 8 and (start - i) // 8 > -max_entries:
                prev = struct.unpack_from("<Q", blob, start - 8)[0]
                if not _is_code_ptr(img, prev):
                    break
                start -= 8
            end = i + 8
            while end + 8 <= len(blob) and (end - i) // 8 < max_entries:
                nxt = struct.unpack_from("<Q", blob, end)[0]
                if not _is_code_ptr(img, nxt):
                    break
                end += 8

            vtable_rva = lo + start
            slot_rva = lo + i
            entries = (end - start) // 8
            refs = xrefs_to_rva(binary_path, vtable_rva, kinds=("rip",),
                                diagnose=False)
            out.append({
                "slot_rva": slot_rva,
                "slot_index": (i - start) // 8,
                "vtable_rva": vtable_rva,
                "entries": entries,
                "section": name,
                "rtti": _decode_msvc_rtti(img, vtable_rva),
                "vtable_refs": [r["from_rva"] for r in refs],
            })

    out.sort(key=lambda r: r["slot_rva"])
    if not out:
        logger.warning(
            "0x%x does not appear in any data-section pointer run, so it is not in a "
            "vtable: it is either called directly (see function_xrefs) or its address "
            "is only ever computed at runtime", func_rva)
    return out


# ── inline (immediate-encoded) strings ──────────────────────────────────────

# MOV r64, imm64 is `REX.W B8+r`; with REX.B for r8-r15 the prefix is 0x49.
_MOVABS_PREFIXES = (0x48, 0x49)


def _immediate_chunks(pat: bytes) -> list[bytes]:
    """Split a string into the immediates a compiler would materialise it from.

    An inline string is built register-width at a time, so the bytes that actually
    appear in ``.text`` are 8-byte groups, not the string. The tail is the awkward
    part: for a length that is not a multiple of 8, MSVC emits a narrower store for
    the remainder (``mov eax, imm32``) while clang prefers an *overlapping* 8-byte
    store of the last 8 bytes. Both forms are offered for the final group so the
    match does not depend on which compiler produced the binary.
    """
    chunks = [pat[i:i + 8] for i in range(0, len(pat), 8)]
    if len(pat) > 8 and len(pat) % 8:
        chunks.append(pat[-8:])          # clang's overlapping tail store
    return [c for c in chunks if c]


def find_inline_strings(
    binary_path: str | Path,
    text: str,
    encoding: str = "utf8",
    section: str = ".text",
    scan_start_rva: int | None = None,
    scan_end_rva: int | None = None,
    window: int = 96,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Find a string that code *constructs in registers* instead of pointing at.

    This is the blind spot every other locator in this module shares. An inline
    string has no ``.rdata`` copy and therefore no address, so:

    * ``find_string_rvas`` / ``find_text`` / ``search_bytes`` search for contiguous
      bytes, and the string is **not contiguous** — the immediates are separated by
      the opcode bytes of the instructions carrying them. ``b"ConfigValue"`` is
      emitted as ``48 B8 'ConfigVa' | B8 'lue' 00``, so a search for the 11 bytes
      finds nothing while a search for the first 8 succeeds. Strings of exactly 8
      bytes are the one length where a plain search happens to work, which is how
      this gap stayed hidden.
    * ``xrefs_to_rva`` needs a target RVA to reference, and there is no target.
      Structurally, not a tuning problem.

    So search for the first 8 bytes as an anchor — 8 bytes of text is already a very
    specific pattern — then confirm the remaining groups appear within ``window``
    bytes, and report how complete the reconstruction was.

    Args:
        text: the string to look for, as it appears in source.
        encoding: codec used to turn ``text`` into bytes ("utf8", "utf16le", "gbk", …).
        section: section to search; ".text" is where inline construction lives.
        scan_start_rva / scan_end_rva: omit to take the whole section.
        window: bytes after the anchor in which the remaining groups must appear.
            Construction is contiguous in practice; the default tolerates
            interleaved stores and register shuffling.
        limit: maximum number of sites to return.

    Returns list of {text, from_rva, section, anchor_hex, opcode, chunks_total,
    chunks_found, coverage, func_begin_rva, func_end_rva}, best coverage first.
    ``opcode == "movabs"`` means the anchor is genuinely a MOV r64, imm64 operand
    rather than an incidental byte match, and is the field to filter on.
    """
    try:
        from fridapilot.tools.binary_analysis import TEXT_CODECS
        pat = text.encode(TEXT_CODECS.get(encoding.lower(), encoding))
    except (LookupError, UnicodeEncodeError) as exc:
        raise ValueError(f"cannot encode {text!r} as {encoding}: {exc}") from exc
    if len(pat) < 4:
        raise ValueError(
            f"{text!r} encodes to {len(pat)} bytes: too short to identify an inline "
            "construction site, use find_text/search_bytes instead")

    img = PEImage(binary_path)
    scan_start_rva, scan_end_rva, section_name = _resolve_scan_range(
        img, scan_start_rva, scan_end_rva, section)
    data = img.read_rva(scan_start_rva, scan_end_rva - scan_start_rva)
    if data is None:
        return []

    chunks = _immediate_chunks(pat)
    anchor = chunks[0]
    rest = chunks[1:]

    out: list[dict[str, Any]] = []
    start = 0
    while len(out) < limit:
        i = data.find(anchor, start)
        if i < 0:
            break
        start = i + 1

        # Which of the remaining groups show up just after the anchor?
        tail = data[i + len(anchor): i + len(anchor) + window]
        found = 1 + sum(1 for c in rest if c in tail)
        # The two tail variants are alternatives, so only one of them can ever be
        # present; count the group once rather than penalising the coverage.
        expected = len(chunks) - (1 if len(pat) > 8 and len(pat) % 8 else 0)
        found = min(found, expected)

        # Report the instruction start, not the immediate, so that from_rva can be
        # fed straight to disassemble_rva / function_bounds like every other
        # reference in this module. Falls back to the anchor when the carrier
        # instruction is not one of the two recognised forms.
        opcode = ""
        head = 0
        if i >= 2 and data[i - 2] in _MOVABS_PREFIXES and 0xB8 <= data[i - 1] <= 0xBF:
            opcode, head = "movabs", 2
        elif i >= 1 and 0xB8 <= data[i - 1] <= 0xBF:
            opcode, head = "mov r32, imm32", 1

        rva = scan_start_rva + i - head
        func = img.function_at(rva)
        out.append({
            "text": text,
            "from_rva": rva,
            "section": img.section_of(rva) or section_name,
            "anchor_hex": anchor.hex(),
            "opcode": opcode,
            "chunks_total": expected,
            "chunks_found": found,
            "coverage": found / expected,
            "func_begin_rva": func[0] if func else None,
            "func_end_rva": func[1] if func else None,
        })

    # A confirmed movabs with every group present is the answer; an unconfirmed
    # partial match is a lead. Order accordingly.
    out.sort(key=lambda r: (-r["coverage"], r["opcode"] == "", r["from_rva"]))
    return out



