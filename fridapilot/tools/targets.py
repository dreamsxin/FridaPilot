"""Named targets: short aliases for the long paths real binaries live at.

Every analysis command takes the image as a positional path, and the paths that matter
are the ones nobody wants to type twice - a Chromium build under
``%APPDATA%\\<vendor>\\browser\\<build>\\<version>\\chrome.dll`` runs to ~90 characters.

Pasting that into command after command is how a shell line gets truncated mid-analysis,
and the workaround people reach for - a throwaway script with the path hardcoded - takes
the whole tool layer out of the loop. So an alias is stored once and spelled ``@name``
wherever a path is accepted:

    fp target add anty "C:\\...\\chrome.dll"
    fp binary describe @anty --rva 0x3402b40
    fp disasm view @anty --section .text

Resolution happens at the three places that actually open an image - ``pe_rva.PEImage``,
``disasm_view.ImageView`` and the ``binary_analysis`` entry points - so it applies to the
CLI, the MCP server and direct SDK use alike, and a plain path is returned untouched.

The store is a JSON file, not a SQLite table: it holds a handful of short strings that a
human may well want to edit or copy between machines, and the existing databases
(``history.db``, ``rip_index.db``) are keyed by content hash for caching rather than by
name for reference.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

TARGETS_PATH = Path.home() / ".fridapilot" / "targets.json"

# Aliases name a file on disk, so they are restricted to what cannot be mistaken for
# one: no separators, no drive colon, nothing that would make "@x/y" ambiguous.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _load(path: Path | None = None) -> dict[str, str]:
    store = path or TARGETS_PATH
    try:
        raw = store.read_text(encoding="utf-8")
    except OSError:
        return {}                      # not created yet: no aliases, not an error
    try:
        data = json.loads(raw)
    except ValueError:
        # A truncated or hand-edited file would otherwise read as "no aliases defined",
        # and every later command would report the alias as a missing file.
        logger.warning("%s is not valid JSON; ignoring every alias in it", store)
        return {}
    if not isinstance(data, dict):
        logger.warning("%s does not contain a name -> path object; ignoring it", store)
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _save(targets: dict[str, str], path: Path | None = None) -> None:
    store = path or TARGETS_PATH
    store.parent.mkdir(parents=True, exist_ok=True)
    # Write then rename: truncating the real file in place loses every alias if the
    # process dies mid-write, and _load cannot tell that from "nothing defined". The
    # temporary file is a sibling because os.replace is only atomic within a filesystem.
    tmp = store.with_name(store.name + ".tmp")
    tmp.write_text(json.dumps(targets, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, store)


def list_targets(path: Path | None = None) -> dict[str, str]:
    """{name: path} for every stored alias.

    Args:
        path: alias store to read; defaults to ``TARGETS_PATH`` (tests override it).
    """
    return _load(path)


def add_target(name: str, target: str | Path, path: Path | None = None) -> str:
    """Store ``name`` -> absolute path of ``target`` and return the stored path.

    The path is resolved now rather than at use time: an alias recorded from one working
    directory and used from another would otherwise point somewhere else. Existence is
    required for the same reason - a typo caught here beats an alias that resolves to a
    missing file in every later command.

    Args:
        name: the alias, spelled ``@name`` on a command line. Letters, digits, dot, dash
            and underscore only, so it can never be confused with a path.
        target: the image the alias stands for.
        path: alias store to write; defaults to ``TARGETS_PATH`` (tests override it).

    Raises:
        ValueError: the name is not alias-shaped, or ``target`` is not an existing file.
    """
    if not _NAME_RE.match(name):
        raise ValueError(
            f"invalid target name {name!r}: letters, digits, dot, dash and underscore only")
    resolved = Path(target).expanduser()
    if not resolved.is_file():
        raise ValueError(f"{target}: not a file")
    resolved = resolved.resolve()
    targets = _load(path)
    targets[name] = str(resolved)
    _save(targets, path)
    return str(resolved)


def remove_target(name: str, path: Path | None = None) -> bool:
    """Forget an alias. False when it was not there.

    Args:
        name: the alias to drop. The file it pointed at is untouched.
        path: alias store to write; defaults to ``TARGETS_PATH`` (tests override it).
    """
    targets = _load(path)
    if name not in targets:
        return False
    del targets[name]
    _save(targets, path)
    return True


def resolve_target(spec: str | Path, path: Path | None = None) -> str | Path:
    """Turn ``@name`` into its stored path; return anything else unchanged.

    Args:
        spec: an alias (``@name``) or an ordinary path, which is passed through as-is.
        path: alias store to read; defaults to ``TARGETS_PATH`` (tests override it).

    Raises:
        ValueError: ``spec`` is an alias that is not defined. Unknown aliases are not
            passed through as filenames, because ``@anty`` reaching the filesystem
            produces "No such file or directory: '@anty'" - which reads like a broken
            path rather than a missing alias.
    """
    if not isinstance(spec, str) or not spec.startswith("@"):
        return spec
    name = spec[1:]
    targets = _load(path)
    if name in targets:
        return targets[name]
    known = ", ".join(sorted(targets)) or "(none defined)"
    raise ValueError(f"unknown target alias {spec!r}; defined: {known}")
