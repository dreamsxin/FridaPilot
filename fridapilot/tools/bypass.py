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
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
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
