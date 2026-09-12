"""Observer - Collect send messages, console output, errors, and crashes.

Pure Frida message handler with structured output.
No LLM dependency.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable


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
    """Collects and structures Frida runtime messages."""

    def __init__(self) -> None:
        self.messages: list[Message] = []
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
        for cb in self._callbacks:
            cb(msg)
