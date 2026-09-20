"""Pydantic schemas for FridaPilot data models."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    """Frida device connection type."""
    LOCAL = "local"
    USB = "usb"
    REMOTE = "remote"


class RuntimeType(str, Enum):
    """Target application runtime type."""
    JAVA = "java"          # Android Java/ART
    OBJC = "objc"          # iOS Objective-C
    SWIFT = "swift"        # iOS Swift
    NATIVE = "native"      # C/C++
    ELECTRON = "electron"  # Electron/Node/V8
    NODE = "node"          # Node.js
    PYTHON = "python"      # Python
    UNKNOWN = "unknown"


class ProcessInfo(BaseModel):
    """Information about a running process."""
    pid: int
    name: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class ModuleInfo(BaseModel):
    """Information about a loaded module."""
    name: str
    base_address: str
    size: int
    path: str = ""


class ExportInfo(BaseModel):
    """Information about a module export."""
    name: str
    address: str
    type: str = "function"


class ClassInfo(BaseModel):
    """Information about a runtime class (Java/ObjC)."""
    name: str
    methods: list[str] = Field(default_factory=list)


# ── Binary analysis models ────────────────────────────────────


class SectionInfo(BaseModel):
    """PE/ELF section information."""
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    characteristics: str = ""


class ImportEntry(BaseModel):
    """Imported function."""
    dll: str = ""
    name: str = ""
    ordinal: int | None = None


class PEAnalysis(BaseModel):
    """Result of PE binary analysis."""
    filepath: str
    is_64bit: bool = False
    is_dotnet: bool = False
    is_dll: bool = False
    machine: str = ""
    timestamp: int = 0
    entry_point: int = 0
    image_base: int = 0
    sections: list[SectionInfo] = Field(default_factory=list)
    imports: list[ImportEntry] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    debug_info: dict[str, Any] = Field(default_factory=dict)


class ELFAnalysis(BaseModel):
    """Result of ELF binary analysis."""
    filepath: str
    is_64bit: bool = False
    is_pie: bool = False
    machine: str = ""
    entry_point: int = 0
    sections: list[SectionInfo] = Field(default_factory=list)
    symbols: list[str] = Field(default_factory=list)
    dynamic_libs: list[str] = Field(default_factory=list)


class DisassemblyLine(BaseModel):
    """A single disassembly instruction."""
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str


class DisassemblyResult(BaseModel):
    """Result of disassembling a region."""
    start_address: int
    instructions: list[DisassemblyLine] = Field(default_factory=list)
    architecture: str = ""
    mode: str = ""


class StringMatch(BaseModel):
    """A string found in a binary.

    ``rva``/``section`` are filled for PE input: a file offset cannot be fed to the
    RVA tools (xrefs_to_rva, function_bounds) because the delta differs per section.
    """
    offset: int
    value: str
    encoding: str = "ascii"
    rva: int | None = None
    section: str = ""


class ByteMatch(BaseModel):
    """A byte pattern match in a binary."""
    offset: int
    matched_bytes: str  # hex representation
    rva: int | None = None
    section: str = ""



class XrefResult(BaseModel):
    """Cross-reference to a target address."""
    from_address: int
    instruction: str = ""
    xref_type: str = "call"  # call / jump / data


class GoAnalysis(BaseModel):
    """Result of Go binary analysis."""
    filepath: str
    go_version: str = ""
    build_info: str = ""
    packages: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    strings_sample: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
