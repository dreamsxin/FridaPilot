"""Bypass Tools - Anti-debug, SSL pinning, and anti-Frida bypasses.

No LLM dependency.
"""

from __future__ import annotations

from fridapilot.tools.script_forge import get_template


def get_ssl_bypass_script() -> str:
    """Get the SSL pinning bypass Frida script."""
    return get_template("ssl-bypass")


def get_anti_debug_script() -> str:
    """Get an anti-debug bypass Frida script (ptrace / svc)."""
    return """\
// Anti-debug bypass: intercept ptrace
// Frida 16/17 compat: static Module lookup APIs were removed in Frida 17.
const fpPtrace = (typeof Module.getGlobalExportByName === "function")
    ? (() => { try { return Module.getGlobalExportByName("ptrace"); } catch (e) { return null; } })()
    : Module.findExportByName(null, "ptrace");
if (!fpPtrace) {
    // No ptrace on this platform (e.g. Windows): skip instead of
    // attach(undefined) killing the whole script (audit finding L-C4).
    send({ type: 'bypass', detail: 'ptrace not present - anti-debug bypass skipped' });
} else Interceptor.attach(fpPtrace, {
    onEnter(args) {
        this.request = args[0].toInt32();
    },
    onLeave(retval) {
        if (this.request === 0) { // PT_TRACE_ME
            retval.replace(ptr(0));
            send({ type: 'bypass', detail: 'ptrace PT_TRACE_ME bypassed' });
        }
    }
});
"""
