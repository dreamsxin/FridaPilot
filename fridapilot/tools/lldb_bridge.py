"""LLDB Integration - Python-based LLDB debugging support for macOS/iOS targets.

Provides LLDB-specific debugging primitives that complement the Frida-based
debugger (tools/debugger.py). Use LLDB for:
- True hardware breakpoints and single-step debugging
- macOS/iOS targets where Frida may be detected
- Kernel-level debugging (kext/DriverKit)
- Process attach without Frida injection overhead

Requires: python3-lldb (system package) or Xcode (macOS)
No LLM dependency.
"""

from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LLDBBreakpoint:
    """An LLDB breakpoint."""
    id: int
    address: str = ""
    symbol: str = ""
    module: str = ""
    hit_count: int = 0
    enabled: bool = True


@dataclass
class LLDBFrame:
    """A stack frame from LLDB backtrace."""
    index: int
    module: str = ""
    address: str = ""
    symbol: str = ""
    source: str = ""
    line: int = 0


@dataclass
class LLDBRegisterSet:
    """CPU registers from LLDB."""
    general: dict[str, str] = field(default_factory=dict)
    floating: dict[str, str] = field(default_factory=dict)


class LLDBBridge:
    """Bridge to LLDB via subprocess (works without python3-lldb installed).

    Falls back to subprocess-based LLDB commands when the native Python
    lldb module is not available. This works on any system with lldb in PATH.
    """

    def __init__(self) -> None:
        self._lldb_path = _find_lldb()
        self._process: subprocess.Popen | None = None
        self._native_available = _check_native_lldb()

    @property
    def available(self) -> bool:
        return self._lldb_path is not None

    def _run_cmd(self, *args: str, timeout: int = 30) -> str:
        """Run an lldb command and return output."""
        if not self._lldb_path:
            raise RuntimeError("LLDB not found in PATH")
        cmd = [self._lldb_path, "--no-lldbinit", "--batch", "--one-line-on-crash", "bt", *args]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                return result.stdout + result.stderr + f"\n[exit code: {result.returncode}]"
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[LLDB timeout after {timeout}s]"
        except Exception as e:
            return f"[LLDB error: {e}]"

    def analyze_binary(self, binary_path: str) -> dict[str, Any]:
        """Analyze a Mach-O binary with LLDB: sections, symbols, load commands.

        Args:
            binary_path: Path to the Mach-O binary.

        Returns:
            Dict with binary info, sections, symbols, entitlements.
        """
        p = Path(binary_path)
        if not p.exists():
            return {"binary": binary_path, "error": f"File not found: {binary_path}"}
        # Use the path as an argv element to avoid shell injection via filenames
        safe_path = str(p.resolve())
        output = self._run_cmd(
            "-o", f"target create {safe_path}",
            "-o", "image list",
            "-o", "image dump sections",
            "-o", "target modules dump symtab",
            "-o", "quit",
        )
        return {
            "binary": binary_path,
            "raw_output": output,
            "sections": _parse_sections(output),
            "symbols": _parse_symbols(output),
        }

    def get_macho_info(self, binary_path: str) -> dict[str, Any]:
        """Get Mach-O binary info: architecture, load commands, encryption status.

        Equivalent to `otool -l` but parsed into structured format.
        """
        result: dict[str, Any] = {"binary": binary_path}

        # Use otool if available, otherwise lldb
        otool = _find_tool("otool")
        if otool:
            enc_out = subprocess.run(
                [otool, "-l", binary_path], capture_output=True, text=True, timeout=30,
            ).stdout
            result["encrypted"] = "cryptid 1" in enc_out
            result["load_commands"] = _parse_load_commands(enc_out)
        else:
            output = self._run_cmd(
                "-o", f"target create \"{binary_path}\"",
                "-o", "image dump sections",
                "-o", "quit",
            )
            result["encrypted"] = False  # Can't determine without otool
            result["raw"] = output

        # Architecture
        file_output = subprocess.run(
            ["file", binary_path], capture_output=True, text=True, timeout=10,
        ).stdout if _find_tool("file") else ""
        result["arch"] = "arm64" if "arm64" in file_output else "x86_64" if "x86_64" in file_output else "unknown"
        result["fat"] = "universal" in file_output.lower() or "Mach-O universal" in file_output

        return result

    def check_codesign(self, binary_path: str) -> dict[str, Any]:
        """Check code signing and entitlements of a Mach-O binary."""
        result: dict[str, Any] = {"binary": binary_path}

        codesign = _find_tool("codesign")
        if codesign:
            sig_out = subprocess.run(
                [codesign, "-dvvv", binary_path], capture_output=True, text=True, timeout=10,
            )
            result["signature"] = sig_out.stderr  # codesign outputs to stderr
            result["signed"] = "valid on disk" in sig_out.stderr

            ent_out = subprocess.run(
                [codesign, "-d", "--entitlements", ":-", binary_path],
                capture_output=True, text=True, timeout=10,
            )
            result["entitlements"] = ent_out.stdout
        else:
            result["signature"] = "codesign not available (not macOS?)"
            result["signed"] = None

        return result

    def dump_objc_classes(self, binary_path: str) -> list[str]:
        """Extract Objective-C class names from a Mach-O binary.

        Uses class-dump if available, otherwise falls back to LLDB.
        """
        class_dump = _find_tool("class-dump")
        if class_dump:
            out = subprocess.run(
                [class_dump, "-C", ".*", binary_path],
                capture_output=True, text=True, timeout=60,
            ).stdout
            classes = re.findall(r"@interface (\S+)", out)
            return sorted(set(classes))

        # Fallback: use strings to find ObjC class names
        out = subprocess.run(
            ["strings", binary_path], capture_output=True, text=True, timeout=30,
        ).stdout if _find_tool("strings") else ""
        classes = [line for line in out.splitlines() if line.startswith("_OBJC_CLASS_$_")]
        return [c.replace("_OBJC_CLASS_$_", "") for c in sorted(set(classes))]

    def remote_attach(self, host: str, port: int = 1234) -> str:
        """Generate LLDB commands for remote debugging (iOS USB tunnel).

        Returns the LLDB command sequence as a string.
        """
        return (
            f"# On device: debugserver *:{port} --attach=<pid>\n"
            f"# On host:\n"
            f"lldb\n"
            f"platform select remote-ios\n"
            f"process connect connect://{host}:{port}\n"
            f"# Or for USB via iproxy:\n"
            f"# iproxy {port} {port}\n"
            f"# process connect connect://localhost:{port}\n"
        )


# ── Helper Functions ──────────────────────────────────────────

def _find_lldb() -> str | None:
    """Find lldb executable in PATH."""
    import shutil
    return shutil.which("lldb")


def _find_tool(name: str) -> str | None:
    """Find a tool in PATH."""
    import shutil
    return shutil.which(name)


def _check_native_lldb() -> bool:
    """Check if native Python lldb module is available."""
    try:
        import lldb  # noqa: F401
        return True
    except ImportError:
        return False


def _parse_sections(output: str) -> list[dict]:
    """Parse LLDB section dump output."""
    sections = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("0x") and "]" in line:
            parts = line.split()
            if len(parts) >= 4:
                sections.append({
                    "address": parts[0],
                    "name": parts[-1] if not parts[-1].startswith("0x") else "",
                })
    return sections


def _parse_symbols(output: str) -> list[str]:
    """Parse LLDB symbol table dump, return function names."""
    symbols = []
    for line in output.splitlines():
        if "Code" in line and "X" in line:
            parts = line.split()
            for p in parts:
                if p and not p.startswith("0x") and not p.startswith("["):
                    symbols.append(p)
                    break
    return symbols[:500]  # Limit output


def _parse_load_commands(otool_output: str) -> list[dict]:
    """Parse otool -l output into structured load commands."""
    commands = []
    current: dict[str, str] = {}
    for line in otool_output.splitlines():
        line = line.strip()
        if line.startswith("Load command"):
            if current:
                commands.append(current)
            current = {"index": line}
        elif "cmd " in line:
            current["cmd"] = line.split("cmd ")[-1].strip()
        elif "name " in line:
            current["name"] = line.split("name ")[-1].split(" (")[0].strip()
        elif "cryptid " in line:
            current["cryptid"] = line.split("cryptid ")[-1].strip()
    if current:
        commands.append(current)
    return commands
