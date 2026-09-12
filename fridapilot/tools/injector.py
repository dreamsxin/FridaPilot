"""Injector - Attach, spawn, inject, and detach lifecycle management.

Pure Frida wrappers for session management.
No LLM dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

import frida

from fridapilot.models.schemas import DeviceType
from fridapilot.tools.recon import get_device
from fridapilot.tools.observer import Observer


@dataclass
class Session:
    """Wraps a Frida session with metadata."""
    frida_session: frida.core.Session
    pid: int
    target: str
    device_type: DeviceType
    scripts: list[frida.core.Script] = field(default_factory=list)
    observer: Observer = field(default_factory=Observer)

    @property
    def is_detached(self) -> bool:
        return self.frida_session.is_detached


def _resolve_pid(device: frida.core.Device, name: str) -> int:
    """Resolve a process name to PID."""
    for proc in device.enumerate_processes():
        if proc.name == name:
            return proc.pid
    raise ValueError(f"Process not found: {name}")


def attach(
    target: str | int,
    device_type: DeviceType = DeviceType.LOCAL,
    host: str = "",
) -> Session:
    """Attach to a running process by name or PID."""
    device = get_device(device_type, host)
    pid = target if isinstance(target, int) else _resolve_pid(device, target)
    frida_session = device.attach(pid)
    return Session(
        frida_session=frida_session,
        pid=pid,
        target=str(target),
        device_type=device_type,
    )


def spawn(
    package: str,
    device_type: DeviceType = DeviceType.LOCAL,
    host: str = "",
) -> Session:
    """Spawn an application and attach."""
    device = get_device(device_type, host)
    pid = device.spawn([package])
    frida_session = device.attach(pid)
    session = Session(
        frida_session=frida_session,
        pid=pid,
        target=package,
        device_type=device_type,
    )
    return session


def inject(session: Session, script_source: str) -> frida.core.Script:
    """Inject a Frida script into the session."""
    script = session.frida_session.create_script(script_source)
    script.on("message", session.observer.on_message)
    script.load()
    session.scripts.append(script)
    return script


def resume(session: Session, device_type: DeviceType = DeviceType.LOCAL, host: str = "") -> None:
    """Resume a spawned process (call after inject)."""
    device = get_device(device_type, host)
    device.resume(session.pid)


def detach(session: Session) -> None:
    """Detach from the target process and unload all scripts."""
    for script in session.scripts:
        try:
            script.unload()
        except Exception:
            pass
    session.scripts.clear()
    try:
        session.frida_session.detach()
    except Exception:
        pass
