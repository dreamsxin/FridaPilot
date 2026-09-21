"""Offline unit tests for the stdlib CDP WebSocket transport (test_cdp_client)."""
import socket
import threading

import pytest

from fridapilot.tools.cdp_client import (
    AttachedTarget,
    CDPConnection,
    WebSocket,
    probe_process_type,
)


def _pair():
    a, b = socket.socketpair()
    return WebSocket.from_socket(a), WebSocket.from_socket(b)


def _fake_conn(ws):
    """A CDPConnection wired to a socketpair, without a real DevTools handshake."""
    conn = CDPConnection.__new__(CDPConnection)
    conn._ws = ws
    conn._timeout = 5
    conn._next_id = 1
    conn._id_lock = threading.Lock()
    conn._pending = {}
    conn._handlers = []
    conn._alive = True
    conn._reader = threading.Thread(target=conn._read_loop, daemon=True)
    conn._reader.start()
    return conn


def test_text_roundtrip():
    """A single-frame text message survives the send/receive path unchanged."""
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
    """200 bytes exercises the 16-bit length field, 70000 the 64-bit one."""
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
    """call() matches the response by id; unsolicited messages reach subscribers."""
    wa, wb = _pair()
    conn = _fake_conn(wb)

    events = []
    conn.on_event("Runtime.consoleAPICalled", lambda msg: events.append(msg))

    # simulate the endpoint side: read conn's request from wa, answer it,
    # then push an event.
    def endpoint():
        """Answer the pending request, then push an unsolicited event."""
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
    """A page without `process` answers null, which must surface as None."""
    wa, wb = _pair()
    conn = _fake_conn(wb)

    def endpoint():
        op, raw = wa.recv_message()
        req = __import__("json").loads(raw.decode())
        wa.send_text(__import__("json").dumps(
            {"id": req["id"], "result": {"result": {"value": None}}}))

    threading.Thread(target=endpoint, daemon=True).start()
    assert probe_process_type(conn, "sess-1") is None


def test_evaluate_raises_when_the_injected_script_threw():
    """CDP reports a thrown script in exceptionDetails, not in result.subtype.

    Checking only result.subtype reported a failed injection as success, and the
    caller then printed "injected" - the "pretending to monitor" failure this
    channel exists to prevent.
    """
    wa, wb = _pair()
    conn = _fake_conn(wb)

    def endpoint():
        op, raw = wa.recv_message()
        req = __import__("json").loads(raw.decode())
        wa.send_text(__import__("json").dumps({
            "id": req["id"],
            "result": {"result": {"type": "object"},
                       "exceptionDetails": {"text": "Uncaught",
                                            "exception": {"description": "boom"}}},
        }))

    threading.Thread(target=endpoint, daemon=True).start()
    target = AttachedTarget(conn, "target-1", "sess-1")
    with pytest.raises(RuntimeError, match="boom"):
        target.evaluate("throw new Error('boom')")


def test_console_events_only_collect_this_session():
    """Handlers are connection-wide, so a target must filter by its own sessionId."""
    wa, wb = _pair()
    conn = _fake_conn(wb)
    target = AttachedTarget(conn, "target-1", "sess-1")

    wa.send_text(__import__("json").dumps(
        {"method": "Runtime.consoleAPICalled", "sessionId": "other",
         "params": {"args": [{"value": "not mine"}]}}))
    wa.send_text(__import__("json").dumps(
        {"method": "Runtime.consoleAPICalled", "sessionId": "sess-1",
         "params": {"args": [{"value": "mine"}]}}))

    import time
    deadline = time.time() + 2
    while not target.console_events and time.time() < deadline:
        time.sleep(0.05)
    assert list(target.console_events) == [["mine"]]
