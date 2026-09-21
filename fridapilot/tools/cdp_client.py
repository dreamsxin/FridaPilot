"""Minimal Chrome DevTools Protocol client over a stdlib WebSocket.

The CDP subset this tool needs is small (target enumeration, flatten
sessions, Runtime.evaluate, consoleAPICalled events) and is implemented
directly on a socket so the package gains no new runtime dependency
(H-T2 channel redesign - see DELIVERY decision memo).

Pure Python. No LLM dependency.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import socket
import struct
import threading
import urllib.request
from collections import deque
from typing import Any, Callable


def fetch_json(url: str, timeout: float = 5.0) -> Any:
    """GET a JSON document (e.g. http://127.0.0.1:PORT/json/list)."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class WebSocket:
    """Blocking RFC 6455 client WebSocket (text frames, client-masked).

    Supports what CDP needs: single-frame and fragmented text messages,
    ping/pong answering, close handling. All I/O is synchronous.
    """

    def __init__(self, url: str, timeout: float = 15.0):
        if not url.startswith("ws://"):
            raise ValueError(f"only ws:// endpoints are supported: {url}")
        rest = url[5:]
        hostport, _, path = rest.partition("/")
        host, _, port_s = hostport.partition(":")
        port = int(port_s) if port_s else 80
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)
        try:
            self._handshake(hostport, path)
        except Exception:
            # The socket is already connected at this point; leaking it here is how a
            # retry loop runs out of file descriptors.
            self._sock.close()
            raise
        self._send_lock = threading.Lock()

    def _handshake(self, hostport: str, path: str) -> None:
        """Send the RFC 6455 upgrade request and require a 101 response."""
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET /{path} HTTP/1.1\r\n"
            f"Host: {hostport}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake: connection closed")
            buf += chunk
        head, _, rest_data = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise ConnectionError(f"websocket handshake failed: {status!r}")
        self._buf = bytearray(rest_data)

    def set_read_timeout(self, timeout: float | None) -> None:
        """Change the socket timeout after the handshake.

        A reader thread must block indefinitely: a timeout fires in the middle of a
        frame, and frame-parse state (header consumed, payload not) cannot be resumed
        from ``recv_message``, so the only safe options are "never time out" or "give
        up". Idle CDP connections are normal, so the reader chooses the former.
        """
        self._sock.settimeout(timeout)

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "WebSocket":
        """Wrap an already-connected socket (skips the handshake) - for tests."""
        self = cls.__new__(cls)
        self._sock = sock
        self._buf = bytearray()
        self._send_lock = threading.Lock()
        return self

    def close(self) -> None:
        """Close the socket, ignoring an already-dead connection."""
        try:
            self._sock.close()
        except Exception:
            pass

    # ── frames ──

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes, buffering whatever the socket hands over."""
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket: socket EOF")
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _recv_frame(self) -> tuple[int, bytes]:
        """One frame as (opcode | FIN bit, unmasked payload)."""
        b1, b2 = self._recv_exact(2)
        flags = b1
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return (opcode | (0x80 if flags & 0x80 else 0)), payload

    def _send_frame(self, opcode: int, payload: bytes = b"", fin: bool = True) -> None:
        """Send one client-masked frame (the RFC requires client masking)."""
        mask = os.urandom(4)
        header = bytes([(0x80 if fin else 0) | opcode])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(header + mask + masked)

    def recv_message(self) -> tuple[int, bytes]:
        """Assemble one complete message; answers pings, raises on close."""
        data = b""
        text = False
        while True:
            flags, payload = self._recv_frame()
            opcode = flags & 0x0F
            fin = bool(flags & 0x80)
            if opcode == 0x9:  # ping -> pong
                self._send_frame(0xA, payload)
                continue
            if opcode == 0x8:  # close
                try:
                    self._send_frame(0x8, payload)
                except Exception:
                    pass
                raise ConnectionError("websocket closed by peer")
            if opcode in (0x1, 0x2):
                text = opcode == 0x1
                data = payload
            elif opcode == 0x0 and (data or text):
                data += payload
            else:
                continue  # pong or stray control frame
            if fin:
                return (0x1 if text else 0x2), data

    def send_text(self, text: str) -> None:
        """Send one UTF-8 text message."""
        self._send_frame(0x1, text.encode("utf-8"))


class CDPConnection:
    """One WebSocket against a DevTools endpoint, flatten-protocol aware.

    call() is synchronous (matched by id); events are dispatched to
    on_event() subscribers from a reader thread.
    """

    def __init__(self, ws_url: str, timeout: float = 15.0):
        self._ws = WebSocket(ws_url, timeout)
        # The handshake needed a timeout; the reader must not have one. A DevTools
        # endpoint is legitimately silent for minutes, and a timeout there killed the
        # reader thread while the caller kept printing "Monitoring".
        self._ws.set_read_timeout(None)
        self._timeout = timeout
        self._next_id = 1
        self._id_lock = threading.Lock()
        self._pending: dict[int, queue.Queue] = {}
        self._handlers: list[tuple[str, Callable[[dict], None]]] = []
        self._alive = True
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    @property
    def alive(self) -> bool:
        """False once the reader thread has stopped - check before trusting events."""
        return self._alive

    def _read_loop(self) -> None:
        """Route responses to their waiting call() and events to subscribers."""
        try:
            while self._alive:
                op, raw = self._ws.recv_message()
                if op != 0x1:
                    continue
                msg = json.loads(raw.decode("utf-8"))
                mid = msg.get("id")
                if mid is not None:
                    q = self._pending.get(mid)
                    if q is not None:
                        q.put(msg)
                else:
                    method = msg.get("method", "")
                    for prefix, cb in list(self._handlers):
                        if method == prefix or method.startswith(prefix):
                            try:
                                cb(msg)
                            except Exception:
                                pass
        except Exception:
            self._alive = False
            for q in list(self._pending.values()):
                q.put({"id": -1, "error": "connection closed"})

    def call(self, method: str, params: dict | None = None,
             session_id: str | None = None, timeout: float | None = None) -> dict:
        """Send one command and wait for the response with the matching id.

        Args:
            session_id: target session for the flatten protocol (Target.attachToTarget
                with flatten=True), omitted for browser-level commands.
            timeout: seconds to wait; the connection default when None.

        Returns:
            The ``result`` object.

        Raises:
            TimeoutError: no response within the timeout.
            RuntimeError: the endpoint answered with a CDP ``error``.
        """
        with self._id_lock:
            mid = self._next_id
            self._next_id += 1
        msg: dict[str, Any] = {"id": mid, "method": method}
        if params:
            msg["params"] = params
        if session_id:
            msg["sessionId"] = session_id
        q: queue.Queue = queue.Queue(maxsize=1)
        self._pending[mid] = q
        self._ws.send_text(json.dumps(msg))
        try:
            resp = q.get(timeout=self._timeout if timeout is None else timeout)
        except queue.Empty:
            self._pending.pop(mid, None)
            raise TimeoutError(f"CDP call timed out: {method}") from None
        finally:
            self._pending.pop(mid, None)
        if "error" in resp:
            raise RuntimeError(f"CDP error from {method}: {resp['error']}")
        return resp.get("result", {})

    def on_event(self, prefix: str, cb: Callable[[dict], None]) -> None:
        """Subscribe to events whose method equals or starts with ``prefix``."""
        self._handlers.append((prefix, cb))

    def close(self) -> None:
        """Stop the reader thread and close the socket."""
        self._alive = False
        self._ws.close()


# ── high-level helpers ────────────────────────────────────────

def find_free_port(host: str = "127.0.0.1") -> int:
    """Ask the OS for a free TCP port (for --remote-debugging-port)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def wait_for_endpoint(port: int, host: str = "127.0.0.1",
                      timeout: float = 20.0) -> dict | None:
    """Poll /json/version until the DevTools HTTP endpoint answers.

    Works for Electron AND Chromium launchers that hand off to a child
    process (the stderr line is unreliable in the hand-off case).
    Returns the /json/version payload (contains webSocketDebuggerUrl).

    A payload without ``webSocketDebuggerUrl`` is rejected: the port was picked by
    asking the OS for a free one and then released, so an unrelated local service can
    win the race and answer on it.
    """
    import time as _time
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        try:
            payload = fetch_json(f"http://{host}:{port}/json/version", timeout=2.0)
            if isinstance(payload, dict) and payload.get("webSocketDebuggerUrl"):
                return payload
        except Exception:
            pass
        _time.sleep(0.2)
    return None


def list_targets(port: int, host: str = "127.0.0.1") -> list[dict]:
    """Page-type targets of a DevTools endpoint (main + renderers for Electron)."""
    targets = fetch_json(f"http://{host}:{port}/json/list")
    return [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]


class AttachedTarget:
    """A CDP session bound to one target, with evaluate + console events."""

    def __init__(self, conn: CDPConnection, target_id: str, session_id: str,
                 max_console_events: int = 500):
        self.conn = conn
        self.target_id = target_id
        self.session_id = session_id
        # Bounded: a busy app emits console events forever, and an unbounded list on a
        # long monitoring run is a slow memory leak.
        self.console_events: deque[list[Any]] = deque(maxlen=max_console_events)
        conn.on_event("Runtime.consoleAPICalled", self._on_console)

    def enable_runtime(self) -> None:
        """Enable the Runtime domain (required before evaluate / console events)."""
        self.conn.call("Runtime.enable", {}, session_id=self.session_id)

    def evaluate(self, expression: str, timeout: float | None = None) -> Any:
        """Evaluate an expression in this target and return its value.

        Raises RuntimeError when the script threw: CDP reports that in the response's
        ``exceptionDetails``, so checking only ``result.subtype`` reports a failed
        injection as success - the exact "pretending to monitor" failure this channel
        exists to avoid.
        """
        result = self.conn.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": False},
            session_id=self.session_id, timeout=timeout)
        details = result.get("exceptionDetails")
        if details:
            exc = details.get("exception", {})
            raise RuntimeError(exc.get("description")
                               or details.get("text", "evaluate raised"))
        info = result.get("result", {})
        if info.get("subtype") == "error":
            raise RuntimeError(info.get("description", "evaluate failed"))
        return info.get("value")

    def _on_console(self, msg: dict) -> None:
        """Record console args for THIS session only (handlers are connection-wide)."""
        if msg.get("sessionId") != self.session_id:
            return
        params = msg.get("params", {})
        values = [a.get("value", a.get("description", "")) for a in params.get("args", [])]
        self.console_events.append(values)


def probe_process_type(conn: CDPConnection, session_id: str) -> str | None:
    """'browser' (Electron main) / 'renderer' / None (plain page)."""
    try:
        val = conn.call(
            "Runtime.evaluate",
            {"expression":
             "(typeof process !== 'undefined' && process.type) ? process.type : null",
             "returnByValue": True},
            session_id=session_id, timeout=5.0)
        return val.get("result", {}).get("value")
    except Exception:
        return None
