"""Recon Tools - Process, module, class, and method enumeration.

Pure Frida wrappers for target discovery and runtime reconnaissance.
No LLM dependency.
"""

from __future__ import annotations

import frida

from fridapilot.models.schemas import (
    ClassInfo,
    DeviceType,
    ExportInfo,
    ModuleInfo,
    ProcessInfo,
    RuntimeType,
)


def get_device(device_type: DeviceType = DeviceType.LOCAL, host: str = "") -> frida.core.Device:
    """Get a Frida device by type."""
    mgr = frida.get_device_manager()
    if device_type == DeviceType.USB:
        return mgr.get_usb_device()
    elif device_type == DeviceType.REMOTE:
        return mgr.add_remote_device(host)
    return frida.get_local_device()


def list_processes(
    device_type: DeviceType = DeviceType.LOCAL,
    host: str = "",
) -> list[ProcessInfo]:
    """List running processes on the target device."""
    device = get_device(device_type, host)
    processes = device.enumerate_processes()
    return [
        ProcessInfo(
            pid=p.pid,
            name=p.name,
            parameters=p.parameters if hasattr(p, "parameters") else {},
        )
        for p in processes
    ]


def enumerate_modules(session: frida.core.Session) -> list[ModuleInfo]:
    """Enumerate loaded modules in the target process."""
    script = session.create_script(
        "rpc.exports.getModules = () => Process.enumerateModules();"
    )
    script.load()
    modules = script.exports_sync.get_modules()
    script.unload()
    return [
        ModuleInfo(
            name=m["name"],
            base_address=m["base"],
            size=m["size"],
            path=m.get("path", ""),
        )
        for m in modules
    ]


def enumerate_classes(
    session: frida.core.Session,
    filter_prefix: str = "",
) -> list[ClassInfo]:
    """Enumerate Java/ObjC classes. Tries Java first, then ObjC."""
    script = session.create_script("""
        rpc.exports.getClasses = () => {
            // Try Java first
            if (Java && Java.available) {
                const classes = [];
                Java.perform(() => {
                    Java.enumerateLoadedClasses({
                        onMatch(name) { classes.push(name); },
                        onComplete() {}
                    });
                });
                return { runtime: 'java', classes };
            }
            // Try ObjC
            if (ObjC && ObjC.available) {
                return { runtime: 'objc', classes: Object.keys(ObjC.classes) };
            }
            return { runtime: 'unknown', classes: [] };
        };
    """)
    script.load()
    result = script.exports_sync.get_classes()
    script.unload()
    classes = result.get("classes", [])
    if filter_prefix:
        classes = [c for c in classes if c.startswith(filter_prefix)]
    return [ClassInfo(name=c) for c in sorted(classes)]


def enumerate_methods(session: frida.core.Session, class_name: str) -> list[str]:
    """Enumerate methods of a given class (Java or ObjC)."""
    script = session.create_script("""
        rpc.exports.getMethods = (className) => {
            if (Java && Java.available) {
                let methods = [];
                Java.perform(() => {
                    const cls = Java.use(className);
                    methods = cls.class.getDeclaredMethods().map(m => m.toString());
                });
                return methods;
            }
            if (ObjC && ObjC.available) {
                const cls = ObjC.classes[className];
                if (cls) return cls.$ownMethods;
            }
            return [];
        };
    """)
    script.load()
    methods = script.exports_sync.get_methods(class_name)
    script.unload()
    return methods


def enumerate_exports(session: frida.core.Session, module_name: str) -> list[ExportInfo]:
    """Enumerate exports of a specific module."""
    script = session.create_script("""
        rpc.exports.getExports = (modName) => {
            return Module.enumerateExports(modName);
        };
    """)
    script.load()
    exports = script.exports_sync.get_exports(module_name)
    script.unload()
    return [
        ExportInfo(
            name=e["name"],
            address=e["address"],
            type=e.get("type", "function"),
        )
        for e in exports
    ]
