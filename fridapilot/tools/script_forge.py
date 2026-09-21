"""Script Forge - Frida script templates and generation.

Built-in template library for common hooking patterns.
No LLM dependency.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Registry of built-in template names
TEMPLATE_REGISTRY: dict[str, str] = {
    # ── Generic templates ──
    "java-hook": "java_hook.js",
    "objc-hook": "objc_hook.js",
    "native-hook": "native_hook.js",
    "ssl-bypass": "ssl_bypass.js",
    "crypto-monitor": "crypto_monitor.js",
    "electron-ipc": "electron_ipc.js",
    "node-hook": "node_hook.js",
    # ── Android ──
    "android-comprehensive": "android/comprehensive.js",
    "android-hardening-bypass": "android/hardening_bypass.js",
    # ── iOS ──
    "ios-comprehensive": "ios/comprehensive.js",
    "ios-hardening-bypass": "ios/hardening_bypass.js",
    # ── Windows ──
    "windows-comprehensive": "windows/comprehensive.js",
    "windows-hardening-bypass": "windows/hardening_bypass.js",
    # ── macOS ──
    "macos-comprehensive": "macos/comprehensive.js",
    # ── Linux ──
    "linux-comprehensive": "linux/comprehensive.js",
    # ── Electron ──
    "electron-comprehensive": "electron/comprehensive.js",
    "electron-hardening-bypass": "electron/hardening_bypass.js",
}


def list_templates() -> list[str]:
    """List available template names."""
    return sorted(TEMPLATE_REGISTRY.keys())


def get_template(name: str, **kwargs: Any) -> str:
    """Load a template by name and apply variable substitution.

    Args:
        name: Template name from TEMPLATE_REGISTRY.
        **kwargs: Variables to substitute in the template (e.g., class_name, method_name).

    Returns:
        The Frida script content as a string.
    """
    if name not in TEMPLATE_REGISTRY:
        available = ", ".join(list_templates())
        raise ValueError(f"Unknown template '{name}'. Available: {available}")

    template_path = TEMPLATES_DIR / TEMPLATE_REGISTRY[name]
    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    content = template_path.read_text(encoding="utf-8")

    def _js_escape(value: Any) -> str:
        """Escape a value for interpolation into a single-quoted JS string.

        Template placeholders sit inside '...' literals, so the dangerous
        characters are backslash, single quote and line breaks. Without
        this, a value like `it's` breaks the generated script or injects
        code (audit finding M-C7).
        """
        text = str(value)
        return (text.replace("\\", "\\\\")
                    .replace("'", "\\'")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r"))

    for key, value in kwargs.items():
        content = content.replace(f"{{{{{key}}}}}", _js_escape(value))

    # A missing argument used to leave {{placeholders}} in the output and
    # the broken script only failed later at load time - fail here instead
    # with the exact list (audit finding M-C7).
    leftover = sorted(set(re.findall(r"\{\{(\w+)\}\}", content)))
    if leftover:
        raise ValueError(
            f"template '{name}' has unsubstituted placeholders: "
            + ", ".join("{{" + p + "}}" for p in leftover)
            + " - pass the matching arguments")
    return content


def load_script_file(path: str) -> str:
    """Load a user-provided Frida script from disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Script file not found: {path}")
    return p.read_text(encoding="utf-8")
