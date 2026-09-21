"""fp electron-agent - Electron 监控（H-T2 通道重设计：CDP 为主、preload 兜底）。

用法:
    python -m fridapilot.scripts.electron_agent --app "C:\\path\\app.exe" [--args "..."]
    python -m fridapilot.scripts.electron_agent --cdp-url ws://127.0.0.1:9222/... （目标已自行开启调试端口）
    python -m fridapilot.scripts.electron_agent --app ... --channel preload

通道:
    cdp      默认。spawn 时追加 --remote-debugging-port=0，经 CDP 在主进程/
             渲染进程真实 JS 上下文安装钩子（主进程 require 可用）。
    preload  回退：NODE_OPTIONS=--require 注入 preload_monitor.cjs（受目标
             Fuses 制约，NodeOptions=DISABLE 时被静默忽略——因此必须等待
             health 消息确认，未收到即明确告警，绝不假装在监控）。

健康检查（H-T2 教训的直接对策）：钩子安装后模板回传 health 消息，
agent 校验钩子计数后才打印 Monitoring；失败时打印明确原因。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

TEMPLATES = Path(__file__).parent.parent / "templates" / "electron"
STDOUT_PREFIX = "__FPLINE__"
CONSOLE_PREFIX = "__FP__"

# 模板回传的 payload type → 显示标签（与旧版输出格式兼容）
LABELS = {
    "ipc_main_on": "IPC ← on",
    "ipc_main_handle": "IPC ← handle registered",
    "ipc_main_call": "IPC ← call",
    "ipc_renderer": "IPC →",
    "ipc_renderer_listen": "IPC → listening",
    "context_bridge": "Bridge",
    "browser_window": "Window",
    "electron_fuses": "Fuses",
    "electron_package": "Package",
    "electron_app_path": "AppPath",
    "asar_contents": "ASAR",
    "node_fs": "fs",
    "node_child_process": "exec",
    "node_http": "http",
    "renderer_ready": "Renderer ready",
    "renderer_skip": "Renderer skipped",
    "emit_dropped": "rate-limited",
    "hook_error": "HOOK ERROR",
    "health": "HEALTH",
}

# 决定"能不能监控"的钩子。其余（fuses/asar/app/http/contextBridge/BrowserWindow）
# 是信息性探针：它们 miss 只说明这次拿不到那条信息，不代表 IPC/文件监控失效，
# 因此不该把整次运行判为失败。
REQUIRED_HOOKS = ("require:electron", "ipcMain", "node:fs", "node:child_process")


def _print_payload(payload: dict) -> None:
    """按 type 把模板回传的 payload 打成一行人类可读输出。"""
    t = payload.get("type", "?")
    label = LABELS.get(t, f"[{t}]")
    if t in ("ipc_main_on", "ipc_main_handle"):
        print(f"  [{label}] {payload.get('channel', '')}")
    elif t == "ipc_main_call":
        print(f"  [{label}] {payload.get('channel', '')} args={payload.get('args', '')}")
    elif t == "ipc_renderer":
        print(f"  [{label}] {payload.get('method', '')}({payload.get('channel', '')}) args={payload.get('args', '')}")
    elif t == "context_bridge":
        print(f"  [{label}] {payload.get('apiKey', '')}: {payload.get('methods', [])}")
    elif t == "browser_window":
        print(f"  [{label}] {payload.get('action', '')}: {payload.get('url', payload.get('path', ''))}")
    elif t == "electron_fuses":
        print(f"  [{label}] at {payload.get('offset', '')}: {payload.get('details', payload.get('fuses', ''))}")
    elif t == "health":
        print(f"  [{label}] hooks={payload.get('hooks', [])}")
    else:
        print(f"  [{label}] {payload}")


def _print_health_verdict(health: dict | None, source: str) -> bool:
    """健康检查（H-T2 教训对策）：钩子计数不达标就明说，绝不打印 Monitoring。

    只有 REQUIRED_HOOKS 里的钩子 miss 才判失败；信息性探针（fuses/asar/...）miss
    降级为告警，否则一台读不到 fuses 哨兵的机器会让本来装好的 IPC 监控也被拒绝。
    """
    if not health:
        print(f"[!] 未收到 {source} 通道的 health 消息 —— 目标可能阻止了该通道，"
              "不要相信本次监控输出。")
        return False
    hooks = health.get("hooks", [])
    missed = [h for h in hooks if h.endswith(":miss")]
    print(f"[*] 健康检查：{len(hooks) - len(missed)}/{len(hooks)} 个钩子安装成功")
    required_missed = [h for h in missed if h[:-len(":miss")] in REQUIRED_HOOKS]
    optional_missed = [h for h in missed if h not in required_missed]
    if required_missed:
        print(f"[!] 关键钩子未安装：{', '.join(required_missed)}")
    if optional_missed:
        print(f"[*] 信息性探针未命中（不影响监控）：{', '.join(optional_missed)}")
    return len(hooks) > 0 and not required_missed


def _spawn_and_find_ws(app: str, app_args: str, timeout: float) -> tuple[subprocess.Popen, str]:
    """Spawn the target with a free debugging port, then poll the HTTP
    endpoint (/json/version). Chromium/Electron launchers sometimes hand
    off to a child process, which makes the stderr line unreliable."""
    from fridapilot.tools import cdp_client

    port = cdp_client.find_free_port()
    cmd = [app] + (app_args.split() if app_args else []) + \
        [f"--remote-debugging-port={port}", "--no-first-run"]
    print(f"[*] Spawning: {' '.join(cmd)}")
    # DEVNULL, not PIPE: nobody reads these pipes, and Electron fills the ~64 KB
    # buffer quickly - the target then blocks forever in write() and looks hung.
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        version = cdp_client.wait_for_endpoint(port, timeout=timeout)
        if version is None:
            raise RuntimeError("DevTools HTTP 端点未就绪 —— 目标可能不是 "
                               "Electron/Chromium，或调试端口被禁用。")
        ws = version.get("webSocketDebuggerUrl")
        if not ws:
            raise RuntimeError("DevTools 端点缺少 webSocketDebuggerUrl。")
    except BaseException:
        # 我们启动的进程，失败时必须回收，否则留下一个持续输出的孤儿进程
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    return proc, ws


def run_cdp(args) -> int:
    """CDP 主通道：spawn（或复用）调试端口 → attach 各 target → 注入模板 → 等 health。

    返回 0 表示监控正常结束，1 表示注入或健康检查失败（此时不会打印 Monitoring）。
    """
    from fridapilot.tools import cdp_client

    proc = None
    ws_url = args.cdp_url
    if not ws_url:
        if not args.app:
            print("[!] 需要 --app（由 agent 启动以开启调试端口）或 --cdp-url（目标已自行开启时）")
            return 1
        try:
            proc, ws_url = _spawn_and_find_ws(args.app, args.app_args, timeout=20.0)
        except RuntimeError as exc:
            print(f"[!] {exc}")
            return 1
        print(f"[*] DevTools endpoint: {ws_url}")

    conn = cdp_client.CDPConnection(ws_url)
    state: dict = {"main_sid": None, "health": None, "seen": set(),
                   "main_src": (TEMPLATES / "cdp_main_hooks.js").read_text(encoding="utf-8"),
                   "renderer_src": (TEMPLATES / "cdp_renderer_hooks.js").read_text(encoding="utf-8")}

    def on_console(msg: dict) -> None:
        """只收主进程会话的 __FP__ 消息，解析后打印并捕获 health。"""
        if msg.get("sessionId") != state["main_sid"]:
            return
        params = msg.get("params", {})
        for a in params.get("args", []):
            v = a.get("value", a.get("description", ""))
            if isinstance(v, str) and v.startswith(CONSOLE_PREFIX):
                try:
                    payload = json.loads(v[len(CONSOLE_PREFIX):])
                except Exception:
                    continue
                _print_payload(payload)
                if payload.get("type") == "health":
                    state["health"] = payload

    conn.on_event("Runtime.consoleAPICalled", on_console)

    def attach_and_inject() -> None:
        """attach 尚未见过的 target，按进程类型注入主进程/渲染进程模板。"""
        m = re.match(r"ws://([^:/]+):(\d+)", ws_url)
        host, port = (m.group(1), int(m.group(2))) if m else ("127.0.0.1", 0)
        for tgt in cdp_client.list_targets(port, host):
            # /json/list 的标识字段是 "id"；写成 "targetId" 会 KeyError，
            # 而外层 except 会把它显示成"注入失败"，看不出真实原因。
            tid = tgt.get("id") or tgt.get("targetId")
            if not tid:
                print(f"[!] 跳过没有 id 的 target：{sorted(tgt)}")
                continue
            if tid in state["seen"]:
                continue
            state["seen"].add(tid)
            result = conn.call("Target.attachToTarget", {"targetId": tid, "flatten": True})
            sid = result["sessionId"]
            at = cdp_client.AttachedTarget(conn, tid, sid)
            at.enable_runtime()
            ptype = cdp_client.probe_process_type(conn, sid)
            if ptype == "browser":
                # 必须先登记 sid：模板在 evaluate 执行期间就同步回传 health，
                # 而 on_console 用 main_sid 过滤——赋值晚一步这条消息就被丢掉，
                # 随后健康检查超时，看起来像"模板没跑"。
                state["main_sid"] = sid
                at.evaluate(state["main_src"])
                print(f"[*] 主进程已注入（target {tid[:12]}…）")
            else:
                at.evaluate(state["renderer_src"])
                print(f"[*] 渲染进程已注入（target {tid[:12]}…，尽力而为）")

    try:
        attach_and_inject()
    except Exception as exc:
        print(f"[!] 注入失败：{exc}")
        return 1
    if not state["main_sid"]:
        print("[!] 未找到 Electron 主进程 target —— 目标可能不是 Electron 应用。")
        return 1

    # 健康检查：主进程模板注入后经 console 回传 health
    deadline = time.time() + 10
    while state["health"] is None and time.time() < deadline:
        time.sleep(0.2)
    if not _print_health_verdict(state["health"], "cdp"):
        conn.close()
        return 1

    print("[*] Monitoring Electron app... Press Ctrl+C to stop.\n")
    try:
        deadline = time.time() + args.timeout if args.timeout > 0 else None
        while True:
            time.sleep(1)
            # 读线程死了就不能再说自己在监控 —— 这正是本通道要避免的失败模式
            if not conn.alive:
                print("[!] CDP 连接已断开（目标退出或端点关闭），监控停止。")
                return 1
            try:
                attach_and_inject()  # 渲染进程可能晚开（轮询补注入）
            except Exception:
                pass
            if deadline is not None and time.time() > deadline:
                break
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        if proc is not None and proc.poll() is None:
            print("[*] 目标进程仍在运行（由你启动，交还控制权）。")
            print("[!] 注意：它的 --remote-debugging-port 仍然开着且无鉴权，"
                  "本机任何进程都能在应用上下文执行 JS/Node —— 用完请结束该进程。")
    return 0


def run_preload(args) -> int:
    """preload 兜底通道：NODE_OPTIONS=--require 注入，必须等到 health 才算成功。

    目标 Fuses 关闭 NodeOptions/RunAsNode 时脚本被静默忽略，此时返回 1 并说明原因。
    """
    preload = TEMPLATES / "preload_monitor.cjs"
    if not preload.exists():
        print(f"[!] preload 模板缺失：{preload}")
        return 1
    if not args.app:
        print("[!] preload 通道必须由 agent 启动目标：需要 --app")
        return 1
    env = os.environ.copy()
    env["NODE_OPTIONS"] = f'--require "{preload}"'
    cmd = [args.app] + (args.app_args.split() if args.app_args else [])
    print(f"[*] Spawning with NODE_OPTIONS preload: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace")
    state: dict = {"health": None}

    def _read_stdout() -> None:
        """把目标 stdout 分成 __FPLINE__ 事件与应用自己的输出两路打印。"""
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line.startswith(STDOUT_PREFIX):
                try:
                    payload = json.loads(line[len(STDOUT_PREFIX):])
                except Exception:
                    continue
                _print_payload(payload)
                if payload.get("type") == "health":
                    state["health"] = payload
            else:
                print(f"  [app] {line}")

    threading.Thread(target=_read_stdout, daemon=True).start()
    deadline = time.time() + 15
    print("[*] Waiting for preload health message...")
    while state["health"] is None and time.time() < deadline and proc.poll() is None:
        time.sleep(0.2)

    if not _print_health_verdict(state["health"], "preload"):
        print("[!] 可能原因：目标 Fuses 已禁用 NodeOptions/RunAsNode（preload 被静默忽略）。"
              "改用 --channel cdp。")
        # 目标由我们启动，判定失败后不要留下无人监管的进程
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        return 1

    print("[*] Monitoring Electron app... Press Ctrl+C to stop.\n")
    try:
        while proc.poll() is None:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        print("[*] Done.")
    return 0


def main() -> int:
    """按 --channel 分派到 cdp（默认）或 preload 通道。"""
    parser = argparse.ArgumentParser(
        description="FridaPilot Electron Reverse Engineering Agent (H-T2 channels: CDP primary / preload fallback)")
    parser.add_argument("--app", help="Electron 可执行文件或应用目录（由 agent 启动目标）")
    parser.add_argument("--app-args", default="", help="透传给目标应用的额外参数")
    parser.add_argument("--channel", choices=["cdp", "preload"], default="cdp",
                        help="cdp=CDP 注入（默认，全功能）；preload=NODE_OPTIONS 兜底（受 Fuses 制约）")
    parser.add_argument("--cdp-url", help="目标已自行开启调试端口时直接给出 ws:// 地址（免 spawn）")
    parser.add_argument("--timeout", type=int, default=0, help="Seconds to observe (0 = until Ctrl+C).")
    args = parser.parse_args()
    return run_cdp(args) if args.channel == "cdp" else run_preload(args)


if __name__ == "__main__":
    sys.exit(main())
