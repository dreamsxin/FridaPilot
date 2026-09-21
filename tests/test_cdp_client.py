"""Offline unit tests for the stdlib CDP WebSocket transport (test_cdp_client)."""
import socket
import threading

import pytest

from fridapilot.tools.cdp_client import WebSocket, CDPConnection, probe_process_type


def _pair():
    a, b = socket.socketpair()
    return WebSocket.from_socket(a), WebSocket.from_socket(b)


def test_text_roundtrip():
    wa, wb = _pair()
    wa.send_text("hello cdp")
    op, data = wb.recv_message()
    assert op == 0x1 and data == b"hello cdp"


def test_fragmented_message():
    """Non-fin text frame + continuation must assemble into one message."""
    wa, wb = _pair()
    wa._send_frame(0x1, b"hel", fin=False)
    wa._send_frame(0x0, b"lo")
    op, data = wb.recv_message()
    assert op == 0x1 and data == b"hello"


def test_large_payload_16bit_and_64bit_lengths():
    wa, wb = _pair()
    for size in (200, 70_000):
        payload = b"x" * size
        wa.send_text(payload.decode("latin-1"))
        op, data = wb.recv_message()
        assert op == 0x1 and data == payload


def test_ping_answered_with_pong():
    """recv_message answers pings transparently and keeps waiting for data -
    assert the pong went out on the peer side, then unblock with real data."""
    import time
    wa, wb = _pair()
    wa._send_frame(0x9, b"pingme")
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("msg", wb.recv_message()), daemon=True)
    t.start()
    time.sleep(0.2)  # let wb process the ping and emit the pong
    op, payload = wa._recv_frame()
    assert op & 0x0F == 0xA and payload == b"pingme"
    wa.send_text("next")
    deadline = time.time() + 2
    while "msg" not in result and time.time() < deadline:
        time.sleep(0.05)
    assert result.get("msg") == (0x1, b"next")


def test_cdp_call_and_event_routing():
    wa, wb = _pair()
    conn = CDPConnection.__new__(CDPConnection)
    conn._ws = wb
    conn._timeout = 5
    conn._next_id = 1
    conn._id_lock = threading.Lock()
    conn._pending = {}
    conn._handlers = []
    conn._alive = True
    conn._reader = threading.Thread(target=conn._read_loop, daemon=True)
    conn._reader.start()

    events = []
    conn.on_event("Runtime.consoleAPICalled", lambda msg: events.append(msg))

    # simulate the endpoint side: read conn's request from wa, answer it,
    # then push an event.
    def endpoint():
        op, raw = wa.recv_message()
        req = __import__("json").loads(raw.decode())
        assert req["method"] == "Runtime.evaluate"
        wa.send_text(__import__("json").dumps(
            {"id": req["id"], "result": {"result": {"value": 42}}}))
        wa.send_text(__import__("json").dumps(
            {"method": "Runtime.consoleAPICalled",
             "params": {"args": [{"type": "string", "value": "__FP__x"}]}}))

    threading.Thread(target=endpoint, daemon=True).start()
    result = conn.call("Runtime.evaluate", {"expression": "1+1"})
    assert result["result"]["value"] == 42
    import time
    deadline = time.time() + 2
    while not events and time.time() < deadline:
        time.sleep(0.05)
    assert events and events[0]["params"]["args"][0]["value"] == "__FP__x"


def test_probe_process_type_none_on_plain_page():
    wa, wb = _pair()
    conn = CDPConnection.__new__(CDPConnection)
    conn._ws = wb
    conn._timeout = 5
    conn._next_id = 1
    conn._id_lock = threading.Lock()
    conn._pending = {}
    conn._handlers = []
    conn._alive = True
    conn._reader = threading.Thread(target=conn._read_loop, daemon=True)
    conn._reader.start()

    def endpoint():
        op, raw = wa.recv_message()
        req = __import__("json").loads(raw.decode())
        wa.send_text(__import__("json").dumps(
            {"id": req["id"], "result": {"result": {"value": None}}}))

    threading.Thread(target=endpoint, daemon=True).start()
    assert probe_process_type(conn, "sess-1") is None
