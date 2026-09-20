"""Persistent rip-reference index: scan a PE once, answer xref queries forever.

The cost model of ``pe_rva.xrefs_to_rva`` is per-scan, not per-target: a full
``.text`` sweep of a 240 MB DLL takes minutes whether you are looking for one
target or twenty. Investigating a binary means asking dozens of such questions
over days, so the same bytes get decoded again and again.

This module decodes every ``.pdata`` function once, records every rip-relative
reference whose target lands in a data section, and stores the pairs in SQLite.
Afterwards a lookup is an indexed query.

The one rule that matters: **an index may only answer a question it actually
covers.** Every build records its scan range, section, gap-scan flag and target
filter; ``lookup_rip_refs`` returns None when the query falls outside that, so the
caller runs a real scan instead of receiving a confidently short answer. Silently
serving a partial index would recreate the exact failure this whole area already
produced once (a third of a ``.text`` scanned, the empty result read as "nothing
references this").

Pure Python. Requires: pefile, capstone.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fridapilot.tools.pe_rva import PEImage, _iter_rip_refs

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".fridapilot" / "rip_index.db"

# Bumped when the scanning logic changes in a way that invalidates stored rows.
INDEX_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT NOT NULL UNIQUE,
    filepath      TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    image_base    INTEGER NOT NULL,
    section       TEXT NOT NULL,
    scan_start_rva INTEGER NOT NULL,
    scan_end_rva  INTEGER NOT NULL,
    scan_gaps     INTEGER NOT NULL,
    target_ranges TEXT NOT NULL,      -- JSON [[lo, hi, name], ...] the index covers
    ref_count     INTEGER NOT NULL,
    build_seconds REAL NOT NULL,
    index_version INTEGER NOT NULL,
    built_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rip_refs (
    image_id   INTEGER NOT NULL,
    target_rva INTEGER NOT NULL,
    from_rva   INTEGER NOT NULL,
    mnemonic   TEXT NOT NULL,
    op_str     TEXT NOT NULL,
    size       INTEGER NOT NULL
);
"""

REF_INDEX = ("CREATE INDEX IF NOT EXISTS idx_rip_refs_target "
             "ON rip_refs(image_id, target_rva)")


def _sha256(path: Path) -> str:
    """Content hash as the image identity.

    Path and mtime both lie: binaries get copied, re-downloaded and patched in
    place. Hashing 240 MB costs well under a second and makes a stale index
    impossible rather than unlikely.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _conn(db_path: str | Path | None = None):
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _data_section_ranges(binary_path: str | Path) -> list[tuple[int, int, str]]:
    """Non-executable section ranges — where interesting xref targets live.

    Strings, globals, vtables and pointer tables are all in data. Indexing
    code-to-code rip references as well would multiply the row count for results
    that ``function_bounds`` / disassembly answer better.
    """
    import pefile

    pe = pefile.PE(str(binary_path), fast_load=True)
    ranges: list[tuple[int, int, str]] = []
    for section in pe.sections:
        if section.Characteristics & 0x20000000:      # IMAGE_SCN_MEM_EXECUTE
            continue
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if end > start:
            ranges.append((start, end, name))
    return sorted(ranges)


def build_rip_index(
    binary_path: str | Path,
    section: str = ".text",
    target_sections: list[str] | None = None,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Decode ``section`` once and store every rip reference into data sections.

    Args:
        section: code section to scan (the whole section, always — a partial index
            would be unusable as a cache).
        target_sections: restrict recorded targets to these sections; default is
            every non-executable section.

    Returns build stats: {sha256, refs, targets, section, scan_start_rva,
    scan_end_rva, target_ranges, seconds, db_path}.
    """
    import capstone

    path = Path(binary_path)
    started = time.time()
    img = PEImage(path)
    bounds = img.section_range(section)
    if bounds is None:
        raise ValueError(f"no section named {section!r} in {path.name}")
    lo, hi = bounds

    ranges = _data_section_ranges(path)
    if target_sections:
        wanted = set(target_sections)
        ranges = [r for r in ranges if r[2] in wanted]
        missing = wanted - {r[2] for r in ranges}
        if missing:
            raise ValueError(f"no such non-executable section(s): {sorted(missing)}")
    if not ranges:
        raise ValueError("no data sections to index targets in")

    def is_target(rva: int) -> bool:
        for start, end, _name in ranges:
            if start <= rva < end:
                return True
        return False

    data = img.read_rva(lo, hi - lo)
    if data is None:
        raise ValueError(f"cannot read {section} of {path.name}")

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if img.is_64bit else capstone.CS_MODE_32)
    md.detail = True

    digest = _sha256(path)
    rows: list[tuple[int, int, str, str, int]] = []
    targets: set[int] = set()
    for from_rva, target_rva, mnemonic, op_str, size in _iter_rip_refs(
            img, md, data, lo, hi, is_target, verify=True, scan_gaps=True):
        rows.append((target_rva, from_rva, mnemonic, op_str, size))
        targets.add(target_rva)

    elapsed = round(time.time() - started, 2)
    payload = json.dumps(ranges)

    with _conn(db_path) as conn:
        # Rebuild from scratch: a half-updated index is worse than none.
        old = conn.execute("SELECT image_id FROM images WHERE sha256=?", (digest,)).fetchone()
        if old:
            conn.execute("DELETE FROM rip_refs WHERE image_id=?", (old["image_id"],))
            conn.execute("DELETE FROM images WHERE image_id=?", (old["image_id"],))
        cursor = conn.execute(
            "INSERT INTO images (sha256, filepath, file_size, image_base, section, "
            "scan_start_rva, scan_end_rva, scan_gaps, target_ranges, ref_count, "
            "build_seconds, index_version, built_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))",
            (digest, str(path.resolve()), path.stat().st_size, img.image_base, section,
             lo, hi, 1, payload, len(rows), elapsed, INDEX_VERSION),
        )
        image_id = cursor.lastrowid
        conn.executemany(
            "INSERT INTO rip_refs (image_id, target_rva, from_rva, mnemonic, op_str, size) "
            "VALUES (?,?,?,?,?,?)",
            [(image_id, *row) for row in rows],
        )
        conn.execute(REF_INDEX)

    logger.info("indexed %d rip refs to %d targets in %s (%.1fs)",
                len(rows), len(targets), path.name, elapsed)
    return {
        "sha256": digest, "refs": len(rows), "targets": len(targets),
        "section": section, "scan_start_rva": lo, "scan_end_rva": hi,
        "target_ranges": ranges, "seconds": elapsed,
        "db_path": str(Path(db_path) if db_path else DEFAULT_DB_PATH),
    }


def index_info(binary_path: str | Path,
               db_path: str | Path | None = None) -> dict[str, Any] | None:
    """Metadata of the stored index for this exact file content, or None."""
    path = Path(binary_path)
    digest = _sha256(path)
    with _conn(db_path) as conn:
        row = conn.execute("SELECT * FROM images WHERE sha256=?", (digest,)).fetchone()
    if row is None:
        return None
    info = dict(row)
    info["target_ranges"] = json.loads(info["target_ranges"])
    return info


def lookup_rip_refs(
    binary_path: str | Path,
    target_rva: int,
    scan_start_rva: int | None = None,
    scan_end_rva: int | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]] | None:
    """Rip references to ``target_rva`` from the index, or None if not covered.

    None means "ask the scanner", and is returned when there is no index for this
    file content, when the index predates the current INDEX_VERSION, when the
    requested range is not inside the indexed range, or when the target is outside
    the indexed target sections. Answering outside coverage would hand back a
    short list that looks authoritative.
    """
    info = index_info(binary_path, db_path)
    if info is None:
        return None
    if info["index_version"] != INDEX_VERSION:
        logger.info("rip index for %s is version %d, current is %d - rebuilding needed",
                    Path(binary_path).name, info["index_version"], INDEX_VERSION)
        return None
    if scan_start_rva is not None and scan_start_rva < info["scan_start_rva"]:
        return None
    if scan_end_rva is not None and scan_end_rva > info["scan_end_rva"]:
        return None
    if not any(lo <= target_rva < hi for lo, hi, _name in info["target_ranges"]):
        return None

    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT from_rva, mnemonic, op_str, size FROM rip_refs "
            "WHERE image_id=? AND target_rva=? ORDER BY from_rva",
            (info["image_id"], target_rva),
        ).fetchall()

    lo = scan_start_rva if scan_start_rva is not None else info["scan_start_rva"]
    hi = scan_end_rva if scan_end_rva is not None else info["scan_end_rva"]
    return [
        {"from_rva": r["from_rva"], "mnemonic": r["mnemonic"], "op_str": r["op_str"],
         "target_rva": target_rva, "kind": "rip", "size": r["size"]}
        for r in rows if lo <= r["from_rva"] < hi
    ]


def drop_index(binary_path: str | Path, db_path: str | Path | None = None) -> bool:
    """Delete the index for this file content. True if one existed."""
    digest = _sha256(Path(binary_path))
    with _conn(db_path) as conn:
        row = conn.execute("SELECT image_id FROM images WHERE sha256=?", (digest,)).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM rip_refs WHERE image_id=?", (row["image_id"],))
        conn.execute("DELETE FROM images WHERE image_id=?", (row["image_id"],))
    return True


def list_indexes(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Every stored index, newest first."""
    with _conn(db_path) as conn:
        rows = conn.execute(
            "SELECT sha256, filepath, file_size, section, scan_start_rva, scan_end_rva, "
            "ref_count, build_seconds, built_at FROM images ORDER BY built_at DESC",
        ).fetchall()
    return [dict(r) for r in rows]
