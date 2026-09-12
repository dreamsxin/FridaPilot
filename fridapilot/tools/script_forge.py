"""Script Forge - Frida script templates and generation.

Built-in template library for common hooking patterns.
No LLM dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Registry of built-in template names
TEMPLATE_REGISTRY: dict[str, str] = {
    "java-hook": "java_hook.js",
    "objc-hook": "objc_hook.js",
    "native-hook": "native_hook.js",
    "ssl-bypass": "ssl_bypass.js",
    "crypto-monitor": "crypto_monitor.js",
    "electron-ipc": "electron_ipc.js",
    "node-hook": "node_hook.js",
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
    # Simple {{variable}} substitution
    for key, value in kwargs.items():
        content = content.replace(f"{{{{{key}}}}}", str(value))
    return content


def load_script_file(path: str) -> str:
    """Load a user-provided Frida script from disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Script file not found: {path}")
    return p.read_text(encoding="utf-8")
