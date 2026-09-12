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
