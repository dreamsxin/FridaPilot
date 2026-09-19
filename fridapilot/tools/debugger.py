"""Debugger Engine - Interactive Frida-based debugging with GDB-like primitives.

Provides breakpoint management, register inspection, memory examination,
single-step emulation, backtrace, and disassembly through Frida Interceptor/Stalker.

Architecture:
- Python side: manages breakpoint state, dispatches commands, formats output
- Frida JS side: Interceptor hooks for breakpoints, memory/register access via RPC

No LLM dependency.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

import frida

from fridapilot.models.schemas import DeviceType
from fridapilot.tools.recon import get_device


# ── Data Models ───────────────────────────────────────────────


class BpType(str, Enum):
    SOFTWARE = "software"
    HARDWARE = "hardware"
    CONDITIONAL = "conditional"


class BpState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    HIT = "hit"


@dataclass
class Breakpoint:
    """A debugger breakpoint."""
    id: int
    address: str  # hex address or module!export
    bp_type: BpType = BpType.SOFTWARE
    condition: str = ""  # JS expression for conditional bp
    hit_count: int = 0
    state: BpState = BpState.ENABLED
    module: str = ""
    symbol: str = ""
    resolved_address: str = ""


@dataclass
class RegisterState:
    """CPU register snapshot."""
    registers: dict[str, str] = field(default_factory=dict)
    flags: str = ""


@dataclass
class BreakpointHit:
    """Information about a breakpoint hit event."""
    bp_id: int
    address: str
    thread_id: int
    registers: RegisterState = field(default_factory=RegisterState)
    backtrace: list[str] = field(default_factory=list)
    disassembly: list[str] = field(default_factory=list)


# ── Frida JS runtime for debugger ─────────────────────────────

_DEBUGGER_SCRIPT = """\
// FridaPilot Debugger Runtime
// Provides RPC exports for breakpoint, register, memory, and disassembly operations

const _breakpoints = {};  // id -> { listener, address, condition, hitCount }
let _nextBpId = 1;
let _hitEvent = null;     // pending hit waiting for continue
let _hitResolve = null;

rpc.exports = {
    // ── Breakpoint Management ──

    addBreakpoint(addrStr, condition) {
        const addr = ptr(addrStr);
        const bpId = _nextBpId++;
        const bp = { id: bpId, address: addr.toString(), condition: condition || '', hitCount: 0 };

        bp.listener = Interceptor.attach(addr, {
            onEnter(args) {
                bp.hitCount++;

                // Conditional breakpoint: evaluate JS expression
                if (bp.condition) {
                    try {
                        const pass = eval(bp.condition);
                        if (!pass) return;
                    } catch(e) { /* condition error, break anyway */ }
                }

                // Capture context
                const ctx = this.context;
                const regs = {};
                const regNames = Process.arch === 'x64'
                    ? ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip']
                    : Process.arch === 'ia32'
                    ? ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip']
                    : ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','fp','lr','sp','pc'];

                regNames.forEach(r => {
                    try { regs[r] = ctx[r].toString(); } catch(e) {}
                });

                const bt = Thread.backtrace(ctx, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress)
                    .map(s => s.toString());

                // Disassemble around PC
                const pc = Process.arch === 'x64' ? ctx.rip
                         : Process.arch === 'ia32' ? ctx.eip
                         : ctx.pc;
                let disasm = [];
                try {
                    disasm = Instruction.parse(pc) ? [pc.toString() + ': ' + Instruction.parse(pc).toString()] : [];
                    let cur = pc;
                    for (let i = 0; i < 5; i++) {
                        const insn = Instruction.parse(cur);
                        if (!insn) break;
                        disasm.push(cur.toString() + ': ' + insn.toString());
                        cur = cur.add(insn.size);
                    }
                } catch(e) {}

                send({
                    type: 'bp_hit',
                    bp_id: bpId,
                    address: addr.toString(),
                    thread_id: Process.getCurrentThreadId(),
                    registers: regs,
                    backtrace: bt,
                    disassembly: disasm,
                    hit_count: bp.hitCount
                });
            }
        });

        _breakpoints[bpId] = bp;
        return { id: bpId, address: addr.toString() };
    },

    removeBreakpoint(bpId) {
        const bp = _breakpoints[bpId];
        if (!bp) return false;
        bp.listener.detach();
        delete _breakpoints[bpId];
        return true;
    },

    listBreakpoints() {
        return Object.values(_breakpoints).map(bp => ({
            id: bp.id,
            address: bp.address,
            condition: bp.condition,
            hit_count: bp.hitCount
        }));
    },

    // ── Register Access ──

    getRegisters(threadId) {
        const regs = {};
        try {
            Process.enumerateThreads().forEach(t => {
                if (threadId && t.id !== threadId) return;
                const ctx = t.context;
                const regNames = Process.arch === 'x64'
                    ? ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15','rip']
                    : Process.arch === 'ia32'
                    ? ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip']
                    : ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','fp','lr','sp','pc'];
                regNames.forEach(r => {
                    try { regs[r] = ctx[r].toString(); } catch(e) {}
                });
            });
        } catch(e) {}
        return regs;
    },

    // ── Memory Access ──

    readMemory(addrStr, size) {
        const buf = Memory.readByteArray(ptr(addrStr), size);
        if (!buf) return '';
        return Array.from(new Uint8Array(buf)).map(b => ('0'+b.toString(16)).slice(-2)).join('');
    },

    writeMemory(addrStr, hexData) {
        const addr = ptr(addrStr);
        const bytes = [];
        for (let i = 0; i < hexData.length; i += 2) {
            bytes.push(parseInt(hexData.substr(i, 2), 16));
        }
        Memory.protect(addr, bytes.length, 'rwx');
        Memory.writeByteArray(addr, bytes);
        return bytes.length;
    },

    readString(addrStr, maxLen) {
        try {
            return Memory.readUtf8String(ptr(addrStr), maxLen || 256);
        } catch(e) {
            try { return Memory.readUtf16String(ptr(addrStr), maxLen || 256); }
            catch(e2) { return '<unreadable>'; }
        }
    },

    // ── Disassembly ──

    disassembleAt(addrStr, count) {
        const results = [];
        let cur = ptr(addrStr);
        for (let i = 0; i < (count || 10); i++) {
            try {
                const insn = Instruction.parse(cur);
                if (!insn) break;
                results.push({
                    address: cur.toString(),
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    size: insn.size
                });
                cur = cur.add(insn.size);
            } catch(e) { break; }
        }
        return results;
    },

    // ── Symbol Resolution ──

    resolveSymbol(moduleStr, exportStr) {
        const addr = Module.findExportByName(moduleStr, exportStr);
        return addr ? addr.toString() : null;
    },

    resolveAddress(addrStr) {
        const sym = DebugSymbol.fromAddress(ptr(addrStr));
        return sym ? sym.toString() : addrStr;
    },

    // ── Module/Thread Info ──

    getModules() {
        return Process.enumerateModules().map(m => ({
            name: m.name, base: m.base.toString(), size: m.size, path: m.path
        }));
    },

    getThreads() {
        return Process.enumerateThreads().map(t => ({
            id: t.id, state: t.state, context_pc: t.context ? t.context.pc.toString() : ''
        }));
    },

    getExports(moduleName) {
        return Module.enumerateExports(moduleName).slice(0, 200).map(e => ({
            name: e.name, address: e.address.toString(), type: e.type
        }));
    },

    // ── Evaluate JS ──

    evaluate(code) {
        try {
            const result = eval(code);
            return { success: true, result: String(result) };
        } catch(e) {
            return { success: false, error: e.message };
        }
    },

    // ── Process Info ──

    getArch() { return Process.arch; },
    getPid() { return Process.id; },
    getPlatform() { return Process.platform; }
};
"""


class DebugSession:
    """Interactive debugger session wrapping a Frida connection.

    Provides GDB-like primitives: breakpoints, registers, memory, disassembly,
    backtrace, symbol resolution, and JS evaluation.
    """

    def __init__(
        self,
        target: str | int,
        device_type: DeviceType = DeviceType.LOCAL,
        host: str = "",
        spawn: bool = False,
    ) -> None:
        self.device = get_device(device_type, host)
        self.spawn = spawn
        self.target = target
        self.pid: int = 0
        self.session: frida.core.Session | None = None
        self.script: frida.core.Script | None = None
        self.breakpoints: dict[int, Breakpoint] = {}
        self.arch: str = ""
        self.platform: str = ""

        # Breakpoint hit queue (thread-safe)
        self._hit_queue: list[BreakpointHit] = []
        self._hit_lock = threading.Lock()
        self._hit_event = threading.Event()

        # Callbacks
        self._on_hit_callbacks: list[Callable[[BreakpointHit], None]] = []

    def connect(self) -> None:
        """Connect to the target process and load the debugger runtime."""
        if self.spawn:
            self.pid = self.device.spawn([str(self.target)])
            self.session = self.device.attach(self.pid)
        else:
            if isinstance(self.target, int):
                self.pid = self.target
            else:
                for p in self.device.enumerate_processes():
                    if p.name == self.target:
                        self.pid = p.pid
                        break
                else:
                    raise ValueError(f"Process not found: {self.target}")
            self.session = self.device.attach(self.pid)

        self.script = self.session.create_script(_DEBUGGER_SCRIPT)
        self.script.on("message", self._on_message)
        self.script.load()

        self.arch = self.script.exports_sync.get_arch()
        self.platform = self.script.exports_sync.get_platform()

        if self.spawn:
            self.device.resume(self.pid)

    def disconnect(self) -> None:
        """Detach and clean up."""
        if self.script:
            try:
                self.script.unload()
            except Exception:
                pass
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass

    def _on_message(self, message: dict, data: Any) -> None:
        """Handle messages from Frida runtime."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "bp_hit":
                hit = BreakpointHit(
                    bp_id=payload.get("bp_id", 0),
                    address=payload.get("address", ""),
                    thread_id=payload.get("thread_id", 0),
                    registers=RegisterState(registers=payload.get("registers", {})),
                    backtrace=payload.get("backtrace", []),
                    disassembly=payload.get("disassembly", []),
                )
                # Update local breakpoint state
                bp_id = hit.bp_id
                if bp_id in self.breakpoints:
                    self.breakpoints[bp_id].hit_count = payload.get("hit_count", 0)
                    self.breakpoints[bp_id].state = BpState.HIT

                with self._hit_lock:
                    self._hit_queue.append(hit)
                self._hit_event.set()

                for cb in self._on_hit_callbacks:
                    cb(hit)

    # ── Breakpoint Commands ───────────────────────────────

    def add_breakpoint(self, address: str, condition: str = "") -> Breakpoint:
        """Add a breakpoint at an address or module!export.

        Args:
            address: Hex address (0x...) or "module!export" format.
            condition: Optional JS expression evaluated at hit time.

        Returns:
            Breakpoint object with assigned ID.
        """
        resolved = self._resolve_address(address)
        result = self.script.exports_sync.add_breakpoint(resolved, condition)

        bp = Breakpoint(
            id=result["id"],
            address=address,
            resolved_address=result["address"],
            condition=condition,
        )
        self.breakpoints[bp.id] = bp
        return bp

    def remove_breakpoint(self, bp_id: int) -> bool:
        """Remove a breakpoint by ID."""
        success = self.script.exports_sync.remove_breakpoint(bp_id)
        if success and bp_id in self.breakpoints:
            del self.breakpoints[bp_id]
        return success

    def list_breakpoints(self) -> list[Breakpoint]:
        """List all active breakpoints."""
        return list(self.breakpoints.values())

    # ── Register Commands ─────────────────────────────────

    def get_registers(self, thread_id: int = 0) -> RegisterState:
        """Read CPU registers."""
        regs = self.script.exports_sync.get_registers(thread_id)
        return RegisterState(registers=regs)

    # ── Memory Commands ───────────────────────────────────

    def read_memory(self, address: str, size: int) -> str:
        """Read memory as hex string."""
        return self.script.exports_sync.read_memory(address, size)

    def write_memory(self, address: str, hex_data: str) -> int:
        """Write hex bytes to memory. Returns bytes written."""
        return self.script.exports_sync.write_memory(address, hex_data)

    def read_string(self, address: str, max_len: int = 256) -> str:
        """Read a string from memory (UTF-8 or UTF-16)."""
        return self.script.exports_sync.read_string(address, max_len)

    def examine(self, address: str, count: int = 64) -> str:
        """Examine memory in hex dump format (GDB 'x' command)."""
        hex_data = self.read_memory(address, count)
        if not hex_data:
            return f"Cannot read memory at {address}"

        lines = []
        addr_int = int(address, 0) if address.startswith("0x") else int(address)
        for i in range(0, len(hex_data), 32):  # 16 bytes per line
            chunk_hex = hex_data[i:i + 32]
            byte_pairs = " ".join(chunk_hex[j:j+2] for j in range(0, len(chunk_hex), 2))
            ascii_chars = ""
            for j in range(0, len(chunk_hex), 2):
                b = int(chunk_hex[j:j+2], 16)
                ascii_chars += chr(b) if 0x20 <= b < 0x7f else "."
            lines.append(f"  0x{addr_int + i // 2:08x}  {byte_pairs:<48s}  {ascii_chars}")
        return "\n".join(lines)

    # ── Disassembly Commands ──────────────────────────────

    def disassemble(self, address: str, count: int = 10) -> list[dict]:
        """Disassemble instructions at address."""
        resolved = self._resolve_address(address)
        return self.script.exports_sync.disassemble_at(resolved, count)

    # ── Symbol Resolution ─────────────────────────────────

    def resolve_symbol(self, module: str, export: str) -> str | None:
        """Resolve module!export to address."""
        return self.script.exports_sync.resolve_symbol(module, export)

    def resolve_address(self, address: str) -> str:
        """Resolve address to symbol name."""
        return self.script.exports_sync.resolve_address(address)

    # ── Info Commands ─────────────────────────────────────

    def get_modules(self) -> list[dict]:
        """List loaded modules."""
        return self.script.exports_sync.get_modules()

    def get_threads(self) -> list[dict]:
        """List threads."""
        return self.script.exports_sync.get_threads()

    def get_exports(self, module: str) -> list[dict]:
        """List exports of a module."""
        return self.script.exports_sync.get_exports(module)

    # ── Evaluate ──────────────────────────────────────────

    def evaluate(self, code: str) -> dict:
        """Evaluate arbitrary JS in the target process."""
        return self.script.exports_sync.evaluate(code)

    # ── Wait for Hit ──────────────────────────────────────

    def wait_for_hit(self, timeout: float = 0) -> BreakpointHit | None:
        """Block until a breakpoint is hit.

        Args:
            timeout: Seconds to wait (0 = forever).

        Returns:
            BreakpointHit or None if timeout.
        """
        self._hit_event.clear()
        with self._hit_lock:
            if self._hit_queue:
                return self._hit_queue.pop(0)

        waited = self._hit_event.wait(timeout=timeout if timeout > 0 else None)
        if waited:
            with self._hit_lock:
                if self._hit_queue:
                    return self._hit_queue.pop(0)
        return None

    # ── Helpers ───────────────────────────────────────────

    def _resolve_address(self, address: str) -> str:
        """Resolve address: supports '0x...' hex or 'module!export' format."""
        if "!" in address:
            parts = address.split("!", 1)
            resolved = self.resolve_symbol(parts[0], parts[1])
            if resolved:
                return resolved
            raise ValueError(f"Cannot resolve symbol: {address}")
        return address


# ── Multi-Process Session Manager ─────────────────────────────


class DebugSessionManager:
    """Manage multiple concurrent DebugSessions for multi-process targets.

    Use case: Electron + Go IPC + native DLL — each process needs its own
    debug session, but they share breakpoint hit events and cross-process
    IPC message correlation.

    Usage:
        mgr = DebugSessionManager()
        mgr.create("electron", "YourApp.exe")
        mgr.create("ipc-server", "ipc-server.exe")
        mgr.connect_all()
        mgr.session("electron").add_breakpoint("kernel32.dll!CreateFileW")
        mgr.session("ipc-server").add_breakpoint("ws2_32.dll!connect")
        # Wait for hits from any session
        name, hit = mgr.wait_any(timeout=30)
    """

    def __init__(self) -> None:
        self._sessions: dict[str, DebugSession] = {}
        self._hit_callbacks: list[Callable[[str, BreakpointHit], None]] = []

    def create(
        self,
        name: str,
        target: str | int,
        device_type: DeviceType = DeviceType.LOCAL,
        host: str = "",
        spawn: bool = False,
    ) -> DebugSession:
        """Create a named debug session.

        Args:
            name: Human-readable name for this session (e.g., "main", "ipc-server").
            target: Process name or PID.
            device_type: Device type.
            host: Remote host.
            spawn: Whether to spawn the process.

        Returns:
            The created DebugSession.
        """
        if name in self._sessions:
            raise ValueError(f"Session '{name}' already exists. Use remove() first.")
        session = DebugSession(target, device_type, host, spawn=spawn)
        # Wire up cross-session hit notification
        session._on_hit_callbacks.append(
            lambda hit, n=name: self._on_session_hit(n, hit)
        )
        self._sessions[name] = session
        return session

    def session(self, name: str) -> DebugSession:
        """Get a session by name."""
        if name not in self._sessions:
            raise KeyError(f"Session '{name}' not found. Active: {list(self._sessions.keys())}")
        return self._sessions[name]

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all active sessions with their status."""
        result = []
        for name, sess in self._sessions.items():
            result.append({
                "name": name,
                "target": sess.target,
                "pid": sess.pid,
                "arch": sess.arch,
                "connected": sess.session is not None,
                "breakpoints": len(sess.breakpoints),
            })
        return result

    def connect_all(self) -> dict[str, bool]:
        """Connect all sessions. Returns {name: success} map."""
        results = {}
        for name, sess in self._sessions.items():
            try:
                sess.connect()
                results[name] = True
            except Exception as e:
                results[name] = False
        return results

    def disconnect_all(self) -> None:
        """Disconnect all sessions."""
        for sess in self._sessions.values():
            try:
                sess.disconnect()
            except Exception:
                pass

    def remove(self, name: str) -> None:
        """Remove and disconnect a session."""
        if name in self._sessions:
            try:
                self._sessions[name].disconnect()
            except Exception:
                pass
            del self._sessions[name]

    def wait_any(self, timeout: float = 0) -> tuple[str, BreakpointHit] | None:
        """Wait for a breakpoint hit from ANY session.

        Args:
            timeout: Seconds to wait (0 = forever).

        Returns:
            Tuple of (session_name, BreakpointHit) or None on timeout.
        """
        import time as _time

        deadline = _time.time() + timeout if timeout > 0 else float("inf")
        while _time.time() < deadline:
            for name, sess in self._sessions.items():
                with sess._hit_lock:
                    if sess._hit_queue:
                        hit = sess._hit_queue.pop(0)
                        return (name, hit)
            _time.sleep(0.1)
        return None

    def _on_session_hit(self, session_name: str, hit: BreakpointHit) -> None:
        """Called when any session gets a breakpoint hit."""
        for cb in self._hit_callbacks:
            cb(session_name, hit)
