"""Observer - Collect send messages, console output, errors, and crashes.

Pure Frida message handler with structured output.
Includes sensitive data auto-detection for tokens, passwords, keys, and URLs.
No LLM dependency.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

# ── Sensitive data detection patterns ─────────────────────────

_SENSITIVE_PATTERNS: dict[str, re.Pattern] = {
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "bearer_token": re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}"),
    "api_key": re.compile(r"(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})", re.IGNORECASE),
    "password": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})", re.IGNORECASE),
    "secret": re.compile(r"(?:secret|secret_key|client_secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,})", re.IGNORECASE),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "hex_key_16": re.compile(r"(?:key|iv|aes|encrypt)\s*[:=]\s*['\"]?([0-9a-fA-F]{32})\b", re.IGNORECASE),
    "hex_key_32": re.compile(r"(?:key|iv|aes|encrypt)\s*[:=]\s*['\"]?([0-9a-fA-F]{64})\b", re.IGNORECASE),
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "url_with_auth": re.compile(r"https?://[^:]+:[^@]+@[^\s]+"),
    "internal_url": re.compile(r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s]+"),
    "crypto_material": re.compile(r"(?:BCrypt|Crypt|AES|DES|RSA)\w*\s*[:=({]", re.IGNORECASE),
}


@dataclass
class SensitiveMatch:
    """A detected sensitive data item in collected messages."""
    pattern_name: str  # e.g. "jwt_token", "password", "hex_key_16"
    value_preview: str  # Truncated/masked value for safe display
    message_index: int  # Index in observer.messages
    severity: str = "HIGH"  # HIGH / MEDIUM / LOW


@dataclass
class Message:
    """A captured Frida message."""
    timestamp: float
    type: str  # "send" | "error" | "log"
    payload: Any = None
    stack: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "type": self.type,
            "payload": self.payload,
            "stack": self.stack,
        }


class Observer:
    """Collects and structures Frida runtime messages.

    Includes auto-detection of sensitive data (tokens, passwords, keys, URLs).
    """

    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.sensitive_findings: list[SensitiveMatch] = []
        self._callbacks: list[Callable[[Message], None]] = []

    def on_message(self, message: dict, data: Any) -> None:
        """Frida message handler - pass this to script.on('message', ...)."""
        msg_type = message.get("type", "unknown")
        if msg_type == "send":
            msg = Message(
                timestamp=time.time(),
                type="send",
                payload=message.get("payload"),
            )
        elif msg_type == "error":
            msg = Message(
                timestamp=time.time(),
                type="error",
                payload=message.get("description", str(message)),
                stack=message.get("stack"),
            )
        else:
            msg = Message(
                timestamp=time.time(),
                type=msg_type,
                payload=str(message),
            )
        self.messages.append(msg)

        # Auto-detect sensitive data in payload
        self._scan_sensitive(msg, len(self.messages) - 1)

        for cb in self._callbacks:
            cb(msg)

    def _scan_sensitive(self, msg: Message, index: int) -> None:
        """Scan a message payload for sensitive data patterns."""
        text = _payload_to_text(msg.payload)
        if not text:
            return

        for pattern_name, regex in _SENSITIVE_PATTERNS.items():
            for m in regex.finditer(text):
                value = m.group()
                # Mask the middle of the value for safe display
                if len(value) > 12:
                    preview = value[:6] + "..." + value[-4:]
                else:
                    preview = value[:4] + "..."

                severity = "HIGH"
                if pattern_name in ("base64_blob", "internal_url", "crypto_material"):
                    severity = "MEDIUM"

                self.sensitive_findings.append(SensitiveMatch(
                    pattern_name=pattern_name,
                    value_preview=preview,
                    message_index=index,
                    severity=severity,
                ))

    def detect_sensitive(self) -> list[SensitiveMatch]:
        """Re-scan all messages for sensitive data. Returns findings."""
        self.sensitive_findings.clear()
        for i, msg in enumerate(self.messages):
            self._scan_sensitive(msg, i)
        return self.sensitive_findings

    def get_stats(self) -> dict[str, Any]:
        """Get message statistics summary."""
        stats: dict[str, int] = {}
        for msg in self.messages:
            stats[msg.type] = stats.get(msg.type, 0) + 1
        return {
            "total": len(self.messages),
            "by_type": stats,
            "sensitive_count": len(self.sensitive_findings),
            "sensitive_high": sum(1 for s in self.sensitive_findings if s.severity == "HIGH"),
        }


def _payload_to_text(payload: Any) -> str:
    """Convert a message payload to searchable text."""
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        return json.dumps(payload, default=str)
    if isinstance(payload, (list, tuple)):
        return json.dumps(payload, default=str)
    return str(payload)
